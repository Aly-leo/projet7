import {
  CanActivate,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  UnauthorizedException,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import { ENV, type Env } from '../config/env.js';
import { PrismaService } from '../prisma/prisma.service.js';
import type { Role } from '../generated/prisma/enums.js';
import {
  ALLOW_PASSWORD_CHANGE,
  AUDIT_AS,
  IS_PUBLIC,
  RATE_LIMIT,
  ROLES,
  buildAuditContext,
  type RateLimitOptions,
} from './decorators.js';
import { RateLimiterService } from './rate-limiter.service.js';
import type { AppRequest } from './types.js';

export const ACCESS_COOKIE = 'access_token';
export const REFRESH_COOKIE = 'refresh_token';
export const CSRF_COOKIE = 'csrf_token';
export const CSRF_HEADER = 'x-csrf-token';
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

export interface AccessTokenPayload {
  sub: string;
  tv: number;
}

/** 1) Limite globale par IP (100 requêtes par minute). */
@Injectable()
export class IpRateLimitGuard implements CanActivate {
  constructor(private readonly limiter: RateLimiterService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<AppRequest>();
    const res = context.switchToHttp().getResponse<Response>();
    const r = this.limiter.hit(`ip:${req.ip}`, 100, 60_000);
    if (!r.allowed) {
      res.setHeader('Retry-After', String(r.retryAfterSec));
      throw new HttpException('Trop de requêtes. Réessayez plus tard.', HttpStatus.TOO_MANY_REQUESTS);
    }
    return true;
  }
}

/**
 * 2) Protection CSRF : vérification de l'en-tête Origin et jeton anti-CSRF (double soumission)
 * sur toute requête qui modifie des données et qui porte des cookies d'authentification.
 */
@Injectable()
export class CsrfGuard implements CanActivate {
  constructor(
    @Inject(ENV) private readonly env: Env,
    private readonly reflector: Reflector,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest<AppRequest>();
    if (SAFE_METHODS.has(req.method)) return true;

    const origin = req.headers.origin;
    if (origin && origin !== this.env.APP_ORIGIN && origin !== `${req.protocol}://${req.get('host')}`) {
      throw new ForbiddenException('Origine non autorisée.');
    }
    // Routes publiques (connexion, rafraîchissement, installation) : contrôle d'Origin + SameSite=Strict.
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, [context.getHandler(), context.getClass()])) {
      return true;
    }

    const cookies = (req as any).cookies as Record<string, string> | undefined;
    const hasSession = Boolean(cookies?.[ACCESS_COOKIE] || cookies?.[REFRESH_COOKIE]);
    if (!hasSession) return true; // pas de cookie d'authentification ambiant : rien à falsifier

    const cookieToken = cookies?.[CSRF_COOKIE];
    const headerToken = req.headers[CSRF_HEADER];
    if (!cookieToken || typeof headerToken !== 'string' || !safeEqual(cookieToken, headerToken)) {
      throw new ForbiddenException('Jeton anti-CSRF invalide.');
    }
    return true;
  }
}

/** 3) Authentification : le rôle et l'état du compte viennent toujours de la base, jamais du client. */
@Injectable()
export class AuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly jwt: JwtService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const req = context.switchToHttp().getRequest<AppRequest>();
    const targets = [context.getHandler(), context.getClass()];
    const auditAs = this.reflector.getAllAndOverride<string | undefined>(AUDIT_AS, targets);
    if (auditAs) req.auditAction = auditAs;
    buildAuditContext(req);

    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, targets)) return true;

    const token = ((req as any).cookies as Record<string, string> | undefined)?.[ACCESS_COOKIE];
    if (!token) throw new UnauthorizedException('Authentification requise.');

    let payload: AccessTokenPayload;
    try {
      payload = await this.jwt.verifyAsync<AccessTokenPayload>(token, { algorithms: ['HS256'] });
    } catch {
      throw new UnauthorizedException('Session expirée ou invalide.');
    }

    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, email: true, name: true, role: true, active: true, tokenVersion: true, mustChangePassword: true },
    });
    if (!user || !user.active || user.tokenVersion !== payload.tv) {
      throw new UnauthorizedException('Session expirée ou invalide.');
    }
    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      mustChangePassword: user.mustChangePassword,
    };
    buildAuditContext(req);

    if (user.mustChangePassword && !this.reflector.getAllAndOverride<boolean>(ALLOW_PASSWORD_CHANGE, targets)) {
      throw new ForbiddenException('Changement de mot de passe obligatoire.');
    }
    return true;
  }
}

/** 4) Rôles : refus par défaut. Toute route non publique doit déclarer ses rôles. */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC, targets)) return true;
    const req = context.switchToHttp().getRequest<AppRequest>();
    const roles = this.reflector.getAllAndOverride<Role[] | undefined>(ROLES, targets);
    if (!roles || roles.length === 0 || !req.user || !roles.includes(req.user.role)) {
      throw new ForbiddenException('Accès refusé.');
    }
    return true;
  }
}

/** 5) Limites propres à une route (connexion, import, export, administration). */
@Injectable()
export class RouteRateLimitGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly limiter: RateLimiterService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  canActivate(context: ExecutionContext): boolean {
    const opts = this.reflector.getAllAndOverride<RateLimitOptions | undefined>(RATE_LIMIT, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!opts) return true;
    const req = context.switchToHttp().getRequest<AppRequest>();
    const res = context.switchToHttp().getResponse<Response>();
    let who: string;
    if (opts.by === 'user') who = req.user?.id ?? `ip:${req.ip}`;
    else if (opts.by === 'ip+email') {
      const email = String((req.body as any)?.courriel ?? '').toLowerCase().slice(0, 254);
      who = `${req.ip}|${email}`;
    } else who = `ip:${req.ip}`;
    const limit = typeof opts.limit === 'function' ? opts.limit(this.env) : opts.limit;
    const r = this.limiter.hit(`${opts.name}:${who}`, limit, opts.windowMs);
    if (!r.allowed) {
      res.setHeader('Retry-After', String(r.retryAfterSec));
      throw new HttpException('Trop de requêtes. Réessayez plus tard.', HttpStatus.TOO_MANY_REQUESTS);
    }
    return true;
  }
}

export function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
