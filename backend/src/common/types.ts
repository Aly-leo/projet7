import type { Request } from 'express';
import type { Role } from '../generated/prisma/enums.js';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  mustChangePassword: boolean;
}

/** Contexte de la requête transmis aux services pour le journal d'audit. */
export interface AuditContext {
  ip?: string;
  userAgent?: string;
  requestId?: string;
  userId?: string;
  /** Vrai dès qu'un refus (DENIED) a déjà été journalisé pour cette requête. */
  deniedLogged?: boolean;
  /** Vrai dès qu'une entrée d'audit a déjà été écrite pour cette action. */
  logged?: boolean;
}

export type AppRequest = Request & {
  id?: string;
  user?: AuthUser;
  auditCtx?: AuditContext;
  auditAction?: string;
};

export const ALL_ROLES: Role[] = ['ADMIN', 'ANALYST', 'DECISION_MAKER'];
