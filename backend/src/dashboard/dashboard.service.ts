import { Injectable } from '@nestjs/common';
import type { Prisma } from '../generated/prisma/client.js';
import type { Priority, Role } from '../generated/prisma/enums.js';
import { PrismaService } from '../prisma/prisma.service.js';

export const PRIORITIES: Priority[] = ['P1', 'P2', 'P3', 'P4'];

export interface AggregateFilters {
  applicationId?: string;
  periodDays?: number;
  priorities?: Priority[];
}

export interface Aggregate {
  totals: { findings: number; open: number };
  byPriority: Record<Priority | 'NONE', number>;
  byStatus: Record<string, number>;
  bySeverity: Record<string, number>;
  byApplication: { applicationId: string; name: string; exposure: string; sensitivity: string; total: number; P1: number; P2: number; P3: number; P4: number }[];
}

const CLOSED = ['CLOSED', 'REJECTED', 'VERIFIED'] as const;

@Injectable()
export class DashboardService {
  constructor(private readonly prisma: PrismaService) {}

  where(f: AggregateFilters): Prisma.FindingWhereInput {
    return {
      ...(f.applicationId && { applicationId: f.applicationId }),
      ...(f.priorities?.length && { effectivePriority: { in: f.priorities } }),
      ...(f.periodDays && { lastSeenAt: { gte: new Date(Date.now() - f.periodDays * 86_400_000) } }),
    };
  }

  /** Agrégats calculés côté serveur : aucun titre, URL ni identifiant de constat n'est chargé. */
  async aggregate(f: AggregateFilters): Promise<Aggregate> {
    const where = this.where(f);
    const [prio, status, severity, perApp, apps, open] = await Promise.all([
      this.prisma.finding.groupBy({ by: ['effectivePriority'], where, _count: { _all: true } }),
      this.prisma.correction.groupBy({ by: ['status'], where: { finding: where }, _count: { _all: true } }),
      this.prisma.finding.groupBy({ by: ['severity'], where, _count: { _all: true } }),
      this.prisma.finding.groupBy({ by: ['applicationId', 'effectivePriority'], where, _count: { _all: true } }),
      this.prisma.application.findMany({ select: { id: true, name: true, exposure: true, sensitivity: true }, orderBy: { name: 'asc' } }),
      this.prisma.finding.count({ where: { ...where, correction: { is: { status: { notIn: [...CLOSED] } } } } }),
    ]);

    const byPriority: Aggregate['byPriority'] = { P1: 0, P2: 0, P3: 0, P4: 0, NONE: 0 };
    for (const r of prio) byPriority[r.effectivePriority ?? 'NONE'] += r._count._all;
    const byStatus: Record<string, number> = {};
    for (const r of status) byStatus[r.status] = r._count._all;
    const bySeverity: Record<string, number> = { '0': 0, '1': 0, '2': 0, '3': 0 };
    for (const r of severity) bySeverity[String(r.severity)] = r._count._all;

    const rows = new Map(apps.map((a) => [a.id, { applicationId: a.id, name: a.name, exposure: a.exposure, sensitivity: a.sensitivity, total: 0, P1: 0, P2: 0, P3: 0, P4: 0 }]));
    for (const r of perApp) {
      const row = rows.get(r.applicationId);
      if (!row) continue;
      row.total += r._count._all;
      if (r.effectivePriority) row[r.effectivePriority] += r._count._all;
    }
    const total = Object.values(byPriority).reduce((a, b) => a + b, 0);
    return {
      totals: { findings: total, open },
      byPriority,
      byStatus,
      bySeverity,
      byApplication: [...rows.values()].filter((r) => !f.applicationId || r.applicationId === f.applicationId),
    };
  }

  async dashboard(role: Role, f: AggregateFilters) {
    const aggregate = await this.aggregate(f);
    const base = { simulated: true, generatedAt: new Date().toISOString(), ...aggregate };
    if (role === 'DECISION_MAKER') return base; // agrégé seulement
    const top = await this.prisma.finding.findMany({
      where: { ...this.where(f), correction: { is: { status: { notIn: [...CLOSED] } } } },
      orderBy: [{ effectivePriority: { sort: 'asc', nulls: 'last' } }, { modelProbability: { sort: 'desc', nulls: 'last' } }],
      take: 8,
      select: {
        id: true, title: true, severity: true, effectivePriority: true, modelProbability: true,
        application: { select: { id: true, name: true } },
        correction: { select: { status: true } },
      },
    });
    return { ...base, topFindings: top.map((t) => ({ ...t, priority: t.effectivePriority })) };
  }
}
