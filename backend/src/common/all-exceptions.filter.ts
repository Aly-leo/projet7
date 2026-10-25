import {
  Catch,
  HttpException,
  HttpStatus,
  Logger,
  type ArgumentsHost,
  type ExceptionFilter,
} from '@nestjs/common';
import type { Response } from 'express';
import { AuditService } from '../audit/audit.service.js';
import { buildAuditContext } from './decorators.js';
import type { AppRequest } from './types.js';

const ERROR_NAMES: Record<number, string> = {
  400: 'Requête invalide',
  401: 'Non authentifié',
  403: 'Accès refusé',
  404: 'Introuvable',
  409: 'Conflit',
  413: 'Fichier ou corps trop volumineux',
  415: 'Type de contenu non pris en charge',
  422: 'Entité non traitable',
  429: 'Trop de requêtes',
};

/**
 * Réponses d'erreur génériques (jamais de trace de pile ni de détail interne) et journalisation
 * des accès refusés (403) et des échecs sur les routes sensibles.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger('Exceptions');

  constructor(private readonly audit: AuditService) {}

  async catch(exception: unknown, host: ArgumentsHost): Promise<void> {
    const http = host.switchToHttp();
    const res = http.getResponse<Response>();
    const req = http.getRequest<AppRequest>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | string[] = 'Erreur interne du serveur.';

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const body = exception.getResponse();
      const m = typeof body === 'string' ? body : (body as any)?.message;
      if (m) message = m;
    } else if (isBodyParserError(exception)) {
      status = (exception as any).status ?? (exception as any).statusCode;
      message = status === 413 ? 'Corps de requête trop volumineux.' : 'Requête invalide.';
    } else {
      this.logger.error(exception instanceof Error ? (exception.stack ?? exception.message) : String(exception));
    }

    if (status >= 500) message = 'Erreur interne du serveur.';

    // Journal d'audit des refus (403) et des échecs sur les routes sensibles.
    try {
      const ctx = buildAuditContext(req);
      const sensitive = req.auditAction !== undefined;
      if (status === 403 && !ctx.deniedLogged) {
        await this.audit.log(ctx, {
          action: req.auditAction ?? 'ACCESS_DENIED',
          outcome: 'DENIED',
          metadata: { method: req.method, path: req.path?.slice(0, 200), status },
        });
      } else if (sensitive && status >= 400 && status !== 401 && status !== 403 && !ctx.logged) {
        await this.audit.log(ctx, {
          action: req.auditAction!,
          outcome: 'FAILURE',
          metadata: { method: req.method, path: req.path?.slice(0, 200), status },
        });
      }
    } catch {
      /* l'audit ne doit jamais masquer la réponse d'erreur */
    }

    res.status(status).json({
      statusCode: status,
      error: ERROR_NAMES[status] ?? 'Erreur',
      message,
      requestId: req.id,
    });
  }
}

function isBodyParserError(e: unknown): boolean {
  const s = (e as any)?.status ?? (e as any)?.statusCode;
  return typeof s === 'number' && s >= 400 && s < 500 && Boolean((e as any)?.expose ?? (e as any)?.type);
}
