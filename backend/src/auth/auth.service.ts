import { ForbiddenException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { AuditService } from '../audit/audit.service.js';
import { ENV, type Env } from '../config/env.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import type { AccessTokenPayload } from '../common/guards.js';
import { PasswordService } from './password.service.js';

const MAX_FAILED = 5;
const BASE_LOCK_MIN = 15;
const MAX_LOCK_MIN = 24 * 60;

export interface IssuedSession {
  accessToken: string;
  refreshToken: string;
  csrfToken: string;
  user: AuthUser;
}

export const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly passwords: PasswordService,
    private readonly audit: AuditService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  async login(email: string, password: string, ctx: AuditContext): Promise<IssuedSession> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    const now = new Date();

    if (!user) {
      await this.passwords.verifyDummy(password);
      await this.audit.log(ctx, { action: 'AUTH_LOGIN', outcome: 'FAILURE', metadata: { reason: 'unknown_user' } });
      throw invalidCredentials();
    }

    // Compte verrouillé : même message qu'un mauvais mot de passe, mais on vérifie quand même le hash (temps constant).
    if (user.lockedUntil && user.lockedUntil > now) {
      await this.passwords.verifyDummy(password);
      await this.audit.log(ctx, { action: 'AUTH_LOGIN', outcome: 'DENIED', userId: user.id, metadata: { reason: 'locked' } });
      throw invalidCredentials();
    }

    const ok = await this.passwords.verify(user.passwordHash, password);
    if (!ok || !user.active) {
      if (!ok) await this.registerFailure(user.id, user.failedLogins);
      await this.audit.log(ctx, {
        action: 'AUTH_LOGIN',
        outcome: 'FAILURE',
        userId: user.id,
        metadata: { reason: ok ? 'inactive' : 'bad_password' },
      });
      throw invalidCredentials();
    }

    await this.prisma.user.update({ where: { id: user.id }, data: { failedLogins: 0, lockedUntil: null } });
    const session = await this.issueSession(user, randomUUID());
    await this.audit.log(ctx, { action: 'AUTH_LOGIN', outcome: 'SUCCESS', userId: user.id });
    return session;
  }

  /** Rotation du jeton de rafraîchissement, avec détection de réutilisation (révocation de la famille). */
  async refresh(rawToken: string | undefined, ctx: AuditContext): Promise<IssuedSession> {
    if (!rawToken) throw new UnauthorizedException('Session expirée ou invalide.');
    const record = await this.prisma.refreshToken.findUnique({
      where: { tokenHash: sha256(rawToken) },
      include: { user: true },
    });
    if (!record) throw new UnauthorizedException('Session expirée ou invalide.');

    if (record.revokedAt) {
      // Jeton déjà utilisé : vol probable. On révoque toute la famille.
      await this.prisma.refreshToken.updateMany({
        where: { familyId: record.familyId, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await this.audit.log(ctx, {
        action: 'AUTH_REFRESH_REUSE',
        outcome: 'DENIED',
        userId: record.userId,
        metadata: { familyId: record.familyId },
      });
      throw new UnauthorizedException('Session expirée ou invalide.');
    }
    if (record.expiresAt <= new Date() || !record.user.active) {
      throw new UnauthorizedException('Session expirée ou invalide.');
    }

    // Rotation atomique : un seul appel concurrent peut consommer ce jeton.
    const consumed = await this.prisma.refreshToken.updateMany({
      where: { id: record.id, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (consumed.count !== 1) throw new UnauthorizedException('Session expirée ou invalide.');

    const session = await this.issueSession(record.user, record.familyId);
    await this.audit.log(ctx, { action: 'AUTH_REFRESH', outcome: 'SUCCESS', userId: record.userId });
    return session;
  }

  async logout(userId: string | undefined, rawRefresh: string | undefined, ctx: AuditContext): Promise<void> {
    if (rawRefresh) {
      const record = await this.prisma.refreshToken.findUnique({ where: { tokenHash: sha256(rawRefresh) } });
      if (record) {
        await this.prisma.refreshToken.updateMany({
          where: { familyId: record.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
      }
    }
    if (userId) {
      await this.prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
    }
    await this.audit.log(ctx, { action: 'AUTH_LOGOUT', outcome: 'SUCCESS', userId });
  }

  async changePassword(user: AuthUser, current: string, next: string, ctx: AuditContext): Promise<IssuedSession> {
    const record = await this.prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    if (!(await this.passwords.verify(record.passwordHash, current))) {
      await this.audit.log(ctx, { action: 'AUTH_PASSWORD_CHANGE', outcome: 'FAILURE', userId: user.id, metadata: { reason: 'bad_current' } });
      throw new ForbiddenException('Mot de passe actuel incorrect.');
    }
    this.passwords.assertStrong(next, [record.email, record.name]);
    if (current === next) {
      await this.audit.log(ctx, { action: 'AUTH_PASSWORD_CHANGE', outcome: 'FAILURE', userId: user.id, metadata: { reason: 'same_password' } });
      throw new ForbiddenException('Le nouveau mot de passe doit être différent de l\'ancien.');
    }
    const updated = await this.prisma.user.update({
      where: { id: user.id },
      data: {
        passwordHash: await this.passwords.hash(next),
        mustChangePassword: false,
        tokenVersion: { increment: 1 },
        failedLogins: 0,
        lockedUntil: null,
      },
    });
    // Révoque toutes les sessions existantes, puis ouvre une nouvelle session pour l'appareil courant.
    await this.prisma.refreshToken.updateMany({ where: { userId: user.id, revokedAt: null }, data: { revokedAt: new Date() } });
    const session = await this.issueSession(updated, randomUUID());
    await this.audit.log(ctx, { action: 'AUTH_PASSWORD_CHANGE', outcome: 'SUCCESS', userId: user.id });
    return session;
  }

  /** Révoque toutes les sessions d'un utilisateur (désactivation, changement de rôle, réinitialisation). */
  async revokeAll(userId: string): Promise<void> {
    await this.prisma.user.update({ where: { id: userId }, data: { tokenVersion: { increment: 1 } } });
    await this.prisma.refreshToken.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date() } });
  }

  private async registerFailure(userId: string, previous: number): Promise<void> {
    const failed = previous + 1;
    let lockedUntil: Date | null = null;
    if (failed >= MAX_FAILED) {
      // Verrouillage progressif : 15 min au 5e échec, puis 30, 60, ... plafonné à 24 h.
      const minutes = Math.min(BASE_LOCK_MIN * 2 ** Math.min(failed - MAX_FAILED, 10), MAX_LOCK_MIN);
      lockedUntil = new Date(Date.now() + minutes * 60_000);
    }
    await this.prisma.user.update({ where: { id: userId }, data: { failedLogins: failed, lockedUntil } });
  }

  private async issueSession(
    user: { id: string; email: string; name: string; role: AuthUser['role']; mustChangePassword: boolean; tokenVersion: number },
    familyId: string,
  ): Promise<IssuedSession> {
    const payload: AccessTokenPayload = { sub: user.id, tv: user.tokenVersion };
    const accessToken = await this.jwt.signAsync(payload, { expiresIn: `${this.env.JWT_ACCESS_TTL_MIN}m` });
    const refreshToken = randomBytes(32).toString('base64url'); // 256 bits
    await this.prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash: sha256(refreshToken),
        familyId,
        expiresAt: new Date(Date.now() + this.env.REFRESH_TTL_DAYS * 86_400_000),
      },
    });
    return {
      accessToken,
      refreshToken,
      csrfToken: randomBytes(24).toString('base64url'),
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        mustChangePassword: user.mustChangePassword,
      },
    };
  }
}

function invalidCredentials(): UnauthorizedException {
  return new UnauthorizedException('Identifiants incorrects.');
}
