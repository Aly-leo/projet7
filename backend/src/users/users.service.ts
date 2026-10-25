import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import { AuthService } from '../auth/auth.service.js';
import { PasswordService } from '../auth/password.service.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import type { Role } from '../generated/prisma/enums.js';
import { PrismaService } from '../prisma/prisma.service.js';

/** Constante fixe du verrou consultatif qui protège le « dernier administrateur actif ». */
const ADMIN_LOCK_ID = 7_070_002;

const PUBLIC_FIELDS = {
  id: true,
  email: true,
  name: true,
  role: true,
  active: true,
  mustChangePassword: true,
  createdAt: true,
  updatedAt: true,
} as const;

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwords: PasswordService,
    private readonly auth: AuthService,
    private readonly audit: AuditService,
  ) {}

  assignable() {
    return this.prisma.user.findMany({
      where: { active: true, role: { in: ['ADMIN', 'ANALYST'] } },
      select: { id: true, name: true },
      orderBy: { name: 'asc' },
    });
  }

  list() {
    return this.prisma.user.findMany({ select: PUBLIC_FIELDS, orderBy: { createdAt: 'asc' } });
  }

  async create(actor: AuthUser, input: { email: string; name: string; role: Role }, ctx: AuditContext) {
    if (await this.prisma.user.findUnique({ where: { email: input.email } })) {
      throw new ConflictException('Un compte existe déjà avec ce courriel.');
    }
    const temporaryPassword = this.passwords.generateTemporary();
    const user = await this.prisma.user.create({
      data: {
        email: input.email,
        name: input.name,
        role: input.role,
        passwordHash: await this.passwords.hash(temporaryPassword),
        mustChangePassword: true,
      },
      select: PUBLIC_FIELDS,
    });
    await this.audit.log(ctx, {
      action: 'USER_CREATE',
      outcome: 'SUCCESS',
      userId: actor.id,
      resourceType: 'User',
      resourceId: user.id,
      metadata: { role: user.role },
    });
    // Le mot de passe temporaire n'est renvoyé qu'une seule fois et n'est jamais journalisé.
    return { user, temporaryPassword };
  }

  async update(
    actor: AuthUser,
    id: string,
    input: { name?: string; role?: Role; active?: boolean },
    ctx: AuditContext,
  ) {
    const result = await this.prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(${ADMIN_LOCK_ID})`;
      const target = await tx.user.findUnique({ where: { id } });
      if (!target) throw new NotFoundException('Utilisateur introuvable.');

      const losesAdmin =
        target.role === 'ADMIN' &&
        target.active &&
        ((input.role !== undefined && input.role !== 'ADMIN') || input.active === false);
      if (losesAdmin) {
        const otherAdmins = await tx.user.count({ where: { role: 'ADMIN', active: true, id: { not: id } } });
        if (otherAdmins === 0) {
          throw new ConflictException('Impossible : il doit rester au moins un administrateur actif.');
        }
      }
      const sensitiveChange =
        (input.role !== undefined && input.role !== target.role) || (input.active === false && target.active);
      const updated = await tx.user.update({
        where: { id },
        data: {
          ...(input.name !== undefined && { name: input.name }),
          ...(input.role !== undefined && { role: input.role }),
          ...(input.active !== undefined && { active: input.active }),
        },
        select: PUBLIC_FIELDS,
      });
      return { updated, target, sensitiveChange };
    });

    if (result.sensitiveChange) await this.auth.revokeAll(id);
    await this.audit.log(ctx, {
      action: 'USER_UPDATE',
      outcome: 'SUCCESS',
      userId: actor.id,
      resourceType: 'User',
      resourceId: id,
      metadata: {
        roleFrom: result.target.role,
        roleTo: result.updated.role,
        activeFrom: result.target.active,
        activeTo: result.updated.active,
      },
    });
    return result.updated;
  }

  async resetPassword(actor: AuthUser, id: string, ctx: AuditContext) {
    const target = await this.prisma.user.findUnique({ where: { id } });
    if (!target) throw new NotFoundException('Utilisateur introuvable.');
    const temporaryPassword = this.passwords.generateTemporary();
    await this.prisma.user.update({
      where: { id },
      data: {
        passwordHash: await this.passwords.hash(temporaryPassword),
        mustChangePassword: true,
        failedLogins: 0,
        lockedUntil: null,
      },
    });
    await this.auth.revokeAll(id);
    await this.audit.log(ctx, {
      action: 'USER_PASSWORD_RESET',
      outcome: 'SUCCESS',
      userId: actor.id,
      resourceType: 'User',
      resourceId: id,
    });
    return { temporaryPassword };
  }
}
