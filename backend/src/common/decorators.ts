import { createParamDecorator, SetMetadata, type ExecutionContext } from '@nestjs/common';
import type { Role } from '../generated/prisma/enums.js';
import { ALL_ROLES, type AppRequest, type AuditContext, type AuthUser } from './types.js';

export const IS_PUBLIC = 'isPublic';
export const ROLES = 'roles';
export const AUDIT_AS = 'auditAs';
export const ALLOW_PASSWORD_CHANGE = 'allowPasswordChange';
export const RATE_LIMIT = 'rateLimit';

/** Route accessible sans authentification (liste blanche explicite). */
export const Public = () => SetMetadata(IS_PUBLIC, true);

/** Rôles autorisés. Sans ce décorateur, l'accès est refusé (refus par défaut). */
export const Roles = (...roles: Role[]) => SetMetadata(ROLES, roles);
export const AllRoles = () => SetMetadata(ROLES, ALL_ROLES);
export const AdminOnly = () => SetMetadata(ROLES, ['ADMIN'] as Role[]);
export const AnalystOrAdmin = () => SetMetadata(ROLES, ['ADMIN', 'ANALYST'] as Role[]);

/** Action d'audit utilisée si la requête est refusée ou échoue avant d'atteindre le service. */
export const AuditAs = (action: string) => SetMetadata(AUDIT_AS, action);

/** Route utilisable même quand le changement de mot de passe est obligatoire. */
export const AllowPasswordChange = () => SetMetadata(ALLOW_PASSWORD_CHANGE, true);

export interface RateLimitOptions {
  name: string;
  limit: number | ((env: Record<string, any>) => number);
  windowMs: number;
  by: 'ip' | 'user' | 'ip+email';
}
export const RateLimit = (options: RateLimitOptions) => SetMetadata(RATE_LIMIT, options);

export const CurrentUser = createParamDecorator((_data: unknown, ctx: ExecutionContext): AuthUser => {
  return ctx.switchToHttp().getRequest<AppRequest>().user as AuthUser;
});

/** Contexte d'audit de la requête (IP, agent utilisateur, identifiant de requête, utilisateur). */
export const Ctx = createParamDecorator((_data: unknown, ctx: ExecutionContext): AuditContext => {
  return buildAuditContext(ctx.switchToHttp().getRequest<AppRequest>());
});

export function buildAuditContext(req: AppRequest): AuditContext {
  if (!req.auditCtx) {
    req.auditCtx = {
      ip: req.ip ?? req.socket?.remoteAddress,
      userAgent: truncate(req.headers['user-agent'], 300),
      requestId: req.id ?? (req.headers['x-request-id'] as string | undefined),
    };
  }
  req.auditCtx.userId = req.user?.id;
  return req.auditCtx;
}

function truncate(value: string | undefined, max: number): string | undefined {
  return value ? value.slice(0, max) : undefined;
}
