import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service.js';
import type { AuditOutcome } from '../generated/prisma/enums.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { AuditContext } from '../common/types.js';

export interface AuditEntry {
  action: string;
  outcome: AuditOutcome;
  userId?: string | null;
  resourceType?: string;
  resourceId?: string;
  metadata?: Record<string, unknown>;
}

const SENSITIVE_KEY = /pass|token|secret|api.?key|authorization|cookie|hash|rawreport|content|description/i;
const MAX_STRING = 300;

/** Retire tout champ sensible et borne la taille des métadonnées (jamais de secret ni de contenu de rapport). */
export function sanitizeMetadata(value: unknown, depth = 0): Prisma.InputJsonValue | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string') return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…` : value;
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (depth > 3) return '[tronqué]';
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => sanitizeMetadata(v, depth + 1));
  if (typeof value === 'object') {
    const out: Record<string, Prisma.InputJsonValue | null> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, 50)) {
      out[k] = SENSITIVE_KEY.test(k) ? '[masqué]' : sanitizeMetadata(v, depth + 1);
    }
    return out as Prisma.InputJsonValue;
  }
  return String(value);
}

@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(private readonly prisma: PrismaService) {}

  /** Écrit une entrée d'audit (ajout seul). Un échec d'écriture est journalisé mais n'interrompt pas la requête. */
  async log(ctx: AuditContext | undefined, entry: AuditEntry): Promise<void> {
    if (ctx) {
      ctx.logged = true;
      if (entry.outcome === 'DENIED') ctx.deniedLogged = true;
    }
    try {
      await this.prisma.auditLog.create({
        data: {
          action: entry.action,
          outcome: entry.outcome,
          userId: entry.userId ?? ctx?.userId ?? null,
          resourceType: entry.resourceType,
          resourceId: entry.resourceId,
          ip: ctx?.ip,
          userAgent: ctx?.userAgent,
          requestId: ctx?.requestId,
          metadata: (sanitizeMetadata(entry.metadata) ?? undefined) as Prisma.InputJsonValue | undefined,
        },
      });
    } catch (err) {
      this.logger.error(`Écriture d'audit impossible (${entry.action}) : ${(err as Error).message}`);
    }
  }
}
