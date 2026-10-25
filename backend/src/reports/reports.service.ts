import { Inject, Injectable, NotFoundException, RequestTimeoutException, UnprocessableEntityException } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { AuditService } from '../audit/audit.service.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { ENV, type Env } from '../config/env.js';
import { DashboardService, PRIORITIES, type Aggregate } from '../dashboard/dashboard.service.js';
import type { Priority } from '../generated/prisma/enums.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { PdfLimitError, ReportPdf, clean } from './pdf.builder.js';

export type ReportKind = 'scan' | 'application' | 'summary';
export interface ReportOptions {
  priorities?: Priority[];
  includeDetails?: boolean;
}

const SEVERITY = ['Information', 'Faible', 'Moyenne', 'Élevée'];
const STATUS: Record<string, string> = {
  IMPORTED: 'Importé', VALIDATED: 'Validé', PRIORITIZED: 'Priorisé', ASSIGNED: 'Assigné', IN_REMEDIATION: 'En correction',
  REMEDIATED: 'Corrigé', VERIFIED: 'Vérifié', CLOSED: 'Clos', REJECTED: 'Rejeté',
};
const EXPOSURE: Record<string, string> = { PUBLIC: 'Publique', INTERNAL: 'Interne', RESTRICTED: 'Restreinte' };
const SENSITIVITY: Record<string, string> = { LOW: 'Faible', MEDIUM: 'Moyenne', HIGH: 'Élevée' };
const ROLE: Record<string, string> = { ADMIN: 'Administrateur', ANALYST: 'Analyste', DECISION_MAKER: 'Décideur' };
const FILE_PREFIX: Record<ReportKind, string> = { scan: 'import', application: 'application', summary: 'synthese' };

@Injectable()
export class ReportsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly dashboard: DashboardService,
    private readonly audit: AuditService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  /** Nom de fichier construit par le serveur à partir de valeurs contrôlées. */
  fileName(kind: ReportKind): string {
    return `rapport-${FILE_PREFIX[kind]}-${new Date().toISOString().slice(0, 10)}.pdf`;
  }

  async generate(kind: ReportKind, targetId: string | undefined, user: AuthUser, opts: ReportOptions, ctx: AuditContext): Promise<Buffer> {
    const timeout = new Promise<never>((_, rej) =>
      setTimeout(() => rej(new RequestTimeoutException('Génération du rapport trop longue.')), this.env.REPORT_TIMEOUT_MS).unref(),
    );
    try {
      const { buffer, count } = await Promise.race([this.build(kind, targetId, user, opts), timeout]);
      await this.audit.log(ctx, {
        action: 'REPORT_EXPORT',
        outcome: 'SUCCESS',
        userId: user.id,
        resourceType: kind,
        resourceId: targetId,
        metadata: { type: kind, findings: count, priorities: opts.priorities, details: opts.includeDetails !== false },
      });
      return buffer;
    } catch (err) {
      const e = err instanceof PdfLimitError ? new UnprocessableEntityException('Rapport trop volumineux : filtrez par priorité.') : err;
      await this.audit.log(ctx, {
        action: 'REPORT_EXPORT',
        outcome: 'FAILURE',
        userId: user.id,
        resourceType: kind,
        resourceId: targetId,
        metadata: { type: kind, reason: (e as Error).message?.slice(0, 150) },
      });
      throw e;
    }
  }

  private async build(kind: ReportKind, targetId: string | undefined, user: AuthUser, opts: ReportOptions) {
    const aggregateOnly = user.role === 'DECISION_MAKER' || kind === 'summary';
    const generatedAt = new Date().toLocaleString('fr-FR', { dateStyle: 'long', timeStyle: 'short' });
    const reportId = randomUUID();

    let appFilter: string | undefined;
    let scanInfo: { fileName: string; importedAt: Date; total: number; created: number; updated: number } | undefined;
    let scope = 'Toutes les applications';
    let appInfo: { name: string; exposure: string; sensitivity: string } | undefined;
    let findingWhere: any = {};

    if (kind === 'scan') {
      const scan = await this.prisma.scan.findUnique({ where: { id: targetId }, include: { application: true } });
      if (!scan) throw new NotFoundException('Import introuvable.');
      appFilter = scan.applicationId;
      appInfo = scan.application;
      scope = `Import du ${scan.importedAt.toLocaleDateString('fr-FR')} · ${scan.application.name}`;
      scanInfo = { fileName: scan.fileName, importedAt: scan.importedAt, total: scan.findingsTotal, created: scan.findingsNew, updated: scan.findingsUpdated };
      findingWhere = { OR: [{ scanId: scan.id }, { lastSeenScanId: scan.id }] };
    } else if (kind === 'application') {
      const app = await this.prisma.application.findUnique({ where: { id: targetId } });
      if (!app) throw new NotFoundException('Application introuvable.');
      appFilter = app.id;
      appInfo = app;
      scope = app.name;
    }

    const aggregate = await this.dashboard.aggregate({ applicationId: appFilter, priorities: opts.priorities });
    // Pour un import, les agrégats portent sur l'application ; le détail sur les constats de l'import.
    const pdf = new ReportPdf(`Rapport – ${scope}`, this.env.REPORT_MAX_PAGES);
    const titles: Record<ReportKind, string> = {
      scan: "Rapport d'import",
      application: "Rapport d'application",
      summary: 'Synthèse agrégée',
    };
    pdf.cover({
      title: titles[kind],
      subtitle: scope,
      lines: [
        ['Application', appInfo?.name ?? 'Toutes'],
        ['Généré le', generatedAt],
        ['Auteur', `${user.name} (${ROLE[user.role]})`],
        ['Identifiant', reportId],
      ],
    });

    pdf.heading('1. Synthèse');
    pdf.keyValues([
      ['Constats au total', String(aggregate.totals.findings)],
      ['Constats ouverts', String(aggregate.totals.open)],
      ...(scanInfo ? ([['Fichier importé', scanInfo.fileName], ['Nouveaux / mis à jour', `${scanInfo.created} / ${scanInfo.updated}`]] as [string, string][]) : []),
    ]);
    pdf.heading('Répartition par priorité', 2);
    pdf.barChart([
      { label: 'P1 – critique', value: aggregate.byPriority.P1, color: '#b3261e' },
      { label: 'P2 – élevée', value: aggregate.byPriority.P2, color: '#c2570c' },
      { label: 'P3 – moyenne', value: aggregate.byPriority.P3, color: '#2f6fb3' },
      { label: 'P4 – faible', value: aggregate.byPriority.P4, color: '#7a8aa6' },
    ]);
    pdf.heading('Répartition par statut', 2);
    pdf.barChart(Object.entries(aggregate.byStatus).map(([k, v]) => ({ label: STATUS[k] ?? k, value: v })));
    pdf.heading('Répartition par gravité technique', 2);
    pdf.barChart(['3', '2', '1', '0'].map((s) => ({ label: SEVERITY[Number(s)]!, value: aggregate.bySeverity[s] ?? 0 })));

    if (appInfo) {
      pdf.heading('2. Contexte de l\'application');
      pdf.keyValues([
        ['Application', appInfo.name],
        ['Exposition', EXPOSURE[appInfo.exposure] ?? appInfo.exposure],
        ['Sensibilité des données', SENSITIVITY[appInfo.sensitivity] ?? appInfo.sensitivity],
      ]);
    } else {
      pdf.heading('2. Applications');
      this.appTable(pdf, aggregate);
    }

    pdf.heading('3. Méthode et limites');
    pdf.paragraph(
      'Les modèles M1 (probabilité d\'exploitation) et M2 (priorité contextuelle P1 à P4) ne sont pas entraînés : leurs sorties sont simulées (version sim-0.1, fournisseur à règles ou API de simulation). ' +
        'Ce rapport est un instantané généré à la demande ; il ne constitue pas une évaluation de performance des modèles ni un audit de sécurité.',
    );

    let count = aggregate.totals.findings;
    if (!aggregateOnly) {
      count = await this.detailSections(pdf, appFilter, findingWhere, opts);
    }

    pdf.heading(aggregateOnly ? '4. Glossaire' : '6. Glossaire');
    pdf.keyValues([
      ['P1 à P4', 'Priorité de correction : P1 critique, P2 élevée, P3 moyenne, P4 faible.'],
      ['CWE', 'Common Weakness Enumeration : catégorie de faiblesse logicielle.'],
      ['CVE', 'Common Vulnerabilities and Exposures : identifiant d\'une vulnérabilité connue.'],
      ['SHAP', 'Méthode d\'explication attribuant une contribution à chaque variable (ici simulée).'],
    ]);

    return { buffer: await pdf.finish(generatedAt), count };
  }

  private appTable(pdf: ReportPdf, a: Aggregate): void {
    pdf.table(
      [
        { header: 'Application', width: 3 },
        { header: 'Total', width: 1, align: 'right' },
        { header: 'P1', width: 1, align: 'right' },
        { header: 'P2', width: 1, align: 'right' },
        { header: 'P3', width: 1, align: 'right' },
        { header: 'P4', width: 1, align: 'right' },
      ],
      a.byApplication.map((r) => [r.name, String(r.total), String(r.P1), String(r.P2), String(r.P3), String(r.P4)]),
    );
  }

  /** Tableau des constats et fiches détaillées (analyste / administrateur seulement). */
  private async detailSections(pdf: ReportPdf, applicationId: string | undefined, extraWhere: any, opts: ReportOptions): Promise<number> {
    const where = {
      ...extraWhere,
      ...(applicationId && { applicationId }),
      ...(opts.priorities?.length && { effectivePriority: { in: opts.priorities } }),
    };
    const total = await this.prisma.finding.count({ where });
    if (total > this.env.REPORT_MAX_FINDINGS) {
      throw new UnprocessableEntityException(`Trop de constats (${total} > ${this.env.REPORT_MAX_FINDINGS}) : filtrez par priorité.`);
    }
    const findings = await this.prisma.finding.findMany({
      where,
      orderBy: [{ effectivePriority: { sort: 'asc', nulls: 'last' } }, { modelProbability: { sort: 'desc', nulls: 'last' } }],
      include: {
        correction: { include: { assignee: { select: { name: true } } } },
        annotations: { orderBy: { createdAt: 'desc' }, take: 3, include: { annotator: { select: { name: true } } } },
      },
    });
    const m2 = await this.prisma.prediction.findMany({
      where: { findingId: { in: findings.map((f) => f.id) }, model: 'M2' },
      orderBy: { createdAt: 'desc' },
      distinct: ['findingId'],
    });
    const expl = new Map(m2.map((p) => [p.findingId, p.explanation as { feature: string; contribution: number }[] | null]));

    pdf.heading('4. Constats classés par priorité');
    pdf.paragraph(`${findings.length} constat(s). Les probabilités et priorités sont simulées.`, { color: '#5b6785', size: 9 });
    pdf.table(
      [
        { header: 'Prio.', width: 0.8 },
        { header: 'Titre', width: 5 },
        { header: 'Gravité', width: 1.3 },
        { header: 'CWE / CVE', width: 1.4 },
        { header: 'Proba.', width: 1, align: 'right' },
        { header: 'Statut', width: 1.5 },
      ],
      findings.map((f) => [
        f.effectivePriority ?? '–',
        clean(f.title, 200),
        SEVERITY[f.severity] ?? '',
        f.cveId ?? (f.cweId ? `CWE-${f.cweId}` : '–'),
        f.modelProbability != null ? f.modelProbability.toFixed(2) : '–',
        STATUS[f.correction?.status ?? ''] ?? '–',
      ]),
      { priorityCol: 0 },
    );

    if (opts.includeDetails !== false) {
      const detailed = findings.filter((f) => (opts.priorities?.length ? true : f.effectivePriority === 'P1' || f.effectivePriority === 'P2'));
      pdf.heading(`5. Fiches détaillées (${opts.priorities?.length ? opts.priorities.join(', ') : 'P1 et P2'})`);
      if (!detailed.length) pdf.paragraph('Aucun constat concerné.');
      for (const f of detailed) {
        pdf.card(f.title, f.effectivePriority ?? '–', (p) => {
          p.keyValues([
            ['Gravité / probabilité', `${SEVERITY[f.severity]} · ${f.modelProbability != null ? f.modelProbability.toFixed(2) : '–'} (simulée)`],
            ['CWE / CVE', `${f.cweId ? `CWE-${f.cweId}` : '–'} / ${f.cveId ?? '–'}`],
            ['Instances', String(f.instancesCount)],
          ]);
          p.paragraph(f.description, { size: 9, max: 2000 });
          if (f.solution) p.paragraph(`Solution : ${f.solution}`, { size: 9, max: 2000 });
          const urls = ((f.sampleUrls as string[] | null) ?? []).slice(0, 5);
          if (urls.length) p.paragraph(`URL d'exemple (texte non cliquable) :\n${urls.map((u) => clean(u, 160)).join('\n')}`, { size: 8.5, color: '#5b6785', max: 1000 });
          const ex = expl.get(f.id);
          if (ex?.length) {
            p.paragraph('Explication (contributions simulées)', { size: 9, color: '#2f6fb3' });
            p.contributions(ex.slice(0, 6));
          }
          for (const a of f.annotations) p.paragraph(`Annotation de ${a.annotator.name} : ${a.priority}${a.comment ? ` – ${a.comment}` : ''}`, { size: 9, max: 400 });
          if (f.correction) {
            p.keyValues([
              ['Correction', STATUS[f.correction.status] ?? f.correction.status],
              ['Assigné à', f.correction.assignee?.name ?? '–'],
              ['Échéance', f.correction.dueDate ? f.correction.dueDate.toLocaleDateString('fr-FR') : '–'],
            ]);
          }
        });
      }
    }
    return findings.length;
  }
}

export { PRIORITIES };
