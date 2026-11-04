import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  UnprocessableEntityException,
  UnsupportedMediaTypeException,
} from '@nestjs/common';
import { createHash } from 'node:crypto';
import { AuditService } from '../audit/audit.service.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { ENV, type Env } from '../config/env.js';
import type { Prisma } from '../generated/prisma/client.js';
import { PredictionService } from '../predictions/prediction.service.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { fingerprintOf, parseZapReport, ZapImportError } from './zap.parser.js';

export interface UploadedReport {
  originalname: string;
  mimetype: string;
  buffer: Buffer;
  size: number;
}

@Injectable()
export class ScansService {
  private readonly logger = new Logger(ScansService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly predictions: PredictionService,
    private readonly audit: AuditService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  /** Pipeline d'import (section 8.2, étapes 4 à 14). L'authentification et le débit sont déjà traités par les gardes. */
  async importReport(actor: AuthUser, applicationId: string, file: UploadedReport | undefined, ctx: AuditContext) {
    const meta: Record<string, unknown> = { applicationId };
    try {
      if (!file) throw new ZapImportError(400, 'Aucun fichier reçu (champ « fichier »).');
      meta.fileName = file.originalname.slice(0, 200);
      meta.sizeBytes = file.size;
      const sha256 = createHash('sha256').update(file.buffer).digest('hex');
      meta.fileSha256 = sha256;

      const app = await this.prisma.application.findUnique({ where: { id: applicationId } });
      if (!app) throw new NotFoundException('Application introuvable.');

      const { findings, json } = parseZapReport(file, { maxAlerts: this.env.MAX_ALERTS_PER_IMPORT });

      // Étape 9 : même fichier déjà importé pour cette application.
      if (await this.prisma.scan.findUnique({ where: { applicationId_fileSha256: { applicationId, fileSha256: sha256 } } })) {
        throw new ConflictException('Ce rapport a déjà été importé pour cette application.');
      }

      // Étapes 10 et 11 : dédoublonnage et transaction unique.
      const keepRaw = file.size <= this.env.RAW_REPORT_MAX_MB * 1024 * 1024;
      const result = await this.prisma.$transaction(
        async (tx) => {
          const scan = await tx.scan.create({
            data: {
              applicationId,
              fileName: file.originalname.slice(0, 200),
              fileSha256: sha256,
              sizeBytes: file.size,
              rawReport: keepRaw ? (json as Prisma.InputJsonValue) : undefined,
              importedById: actor.id,
              status: 'PROCESSING',
            },
          });
          const withFp = findings.map((f) => ({ f, fingerprint: fingerprintOf(applicationId, f) }));
          const existing = await tx.finding.findMany({
            where: { applicationId, fingerprint: { in: withFp.map((x) => x.fingerprint) } },
            select: { id: true, fingerprint: true },
          });
          const known = new Map(existing.map((e) => [e.fingerprint, e.id]));
          const now = new Date();
          const fresh = withFp.filter((x) => !known.has(x.fingerprint));

          const created = fresh.length
            ? await tx.finding.createManyAndReturn({
                data: fresh.map(({ f, fingerprint }) => ({
                  applicationId,
                  scanId: scan.id,
                  lastSeenScanId: scan.id,
                  fingerprint,
                  title: f.title,
                  severity: f.severity,
                  confidence: f.confidence,
                  cweId: f.cweId,
                  cveId: f.cveId,
                  description: f.description,
                  solution: f.solution,
                  instancesCount: f.instancesCount,
                  sampleUrls: f.sampleUrls,
                })),
                select: { id: true },
              })
            : [];
          if (created.length) {
            await tx.correction.createMany({ data: created.map((c) => ({ findingId: c.id, status: 'IMPORTED' as const })) });
            // Contrôle du schéma réussi : IMPORTED → VALIDATED.
            await tx.correction.updateMany({ where: { findingId: { in: created.map((c) => c.id) } }, data: { status: 'VALIDATED' } });
          }
          let updated = 0;
          for (const { f, fingerprint } of withFp) {
            const id = known.get(fingerprint);
            if (!id) continue;
            await tx.finding.update({
              where: { id },
              data: { lastSeenAt: now, lastSeenScanId: scan.id, instancesCount: f.instancesCount, sampleUrls: f.sampleUrls },
            });
            updated++;
          }
          await tx.scan.update({
            where: { id: scan.id },
            data: { status: 'COMPLETED', findingsTotal: findings.length, findingsNew: created.length, findingsUpdated: updated },
          });
          return { scanId: scan.id, newIds: created.map((c) => c.id), allIds: [...known.values(), ...created.map((c) => c.id)], updated };
        },
        { timeout: 120_000, maxWait: 20_000 },
      );

      // Étape 12 : prédictions simulées (un échec ne doit pas annuler l'import).
      let summary;
      try {
        summary = await this.predictions.predictFindings(result.newIds, ctx);
      } catch (err) {
        this.logger.error(`Prédictions impossibles : ${(err as Error).message}`);
        summary = { total: 0, provider: 'rules' as const, m1Provider: 'rules' as const, fallback: true, m2Fallback: false, byPriority: { P1: 0, P2: 0, P3: 0, P4: 0 } };
      }

      const response = {
        scanId: result.scanId,
        findingsTotal: findings.length,
        findingsNew: result.newIds.length,
        findingsUpdated: result.updated,
        byPriority: summary.byPriority,
        provider: summary.provider,
        m1Provider: summary.m1Provider,
        m2Fallback: summary.m2Fallback,
        simulated: true,
      };
      await this.audit.log(ctx, {
        action: 'SCAN_IMPORT',
        outcome: 'SUCCESS',
        userId: actor.id,
        resourceType: 'Scan',
        resourceId: result.scanId,
        metadata: { ...meta, findingsTotal: response.findingsTotal, findingsNew: response.findingsNew, findingsUpdated: response.findingsUpdated, provider: summary.provider, fallback: summary.fallback },
      });
      return response;
    } catch (err) {
      const status = err instanceof ZapImportError ? err.status : ((err as any)?.getStatus?.() ?? 500);
      await this.audit.log(ctx, { action: 'SCAN_IMPORT', outcome: 'FAILURE', userId: actor.id, metadata: { ...meta, status, reason: (err as Error).message?.slice(0, 150) } });
      if (err instanceof ZapImportError) {
        if (err.status === 415) throw new UnsupportedMediaTypeException(err.message);
        if (err.status === 422) throw new UnprocessableEntityException(err.message);
        throw new BadRequestException(err.message);
      }
      throw err;
    }
  }

  async list(page = 1, pageSize = 20) {
    const [total, items] = await Promise.all([
      this.prisma.scan.count(),
      this.prisma.scan.findMany({
        orderBy: { importedAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
        select: {
          id: true, tool: true, fileName: true, fileSha256: true, sizeBytes: true, findingsTotal: true, findingsNew: true,
          findingsUpdated: true, status: true, importedAt: true,
          application: { select: { id: true, name: true } },
          importedBy: { select: { id: true, name: true } },
        },
      }),
    ]);
    return { total, page, pageSize, items };
  }

  async get(id: string) {
    const scan = await this.prisma.scan.findUnique({
      where: { id },
      select: {
        id: true, tool: true, fileName: true, fileSha256: true, sizeBytes: true, findingsTotal: true, findingsNew: true,
        findingsUpdated: true, status: true, importedAt: true,
        application: { select: { id: true, name: true } },
        importedBy: { select: { id: true, name: true } },
      },
    });
    if (!scan) throw new NotFoundException('Import introuvable.');
    return scan;
  }
}
