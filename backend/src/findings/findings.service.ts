import { BadRequestException, ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import type { Prisma } from '../generated/prisma/client.js';
import type { CorrectionStatus, Priority } from '../generated/prisma/enums.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { canTransition } from './correction-state.js';

export interface FindingFilters {
  applicationId?: string;
  priority?: Priority;
  status?: CorrectionStatus;
  severity?: number;
  q?: string;
  sort?: 'priority' | 'severity' | 'probability' | 'lastSeen';
  order?: 'asc' | 'desc';
  page?: number;
  pageSize?: number;
}

const LIST_SELECT = {
  id: true,
  title: true,
  severity: true,
  cweId: true,
  cveId: true,
  instancesCount: true,
  lastSeenAt: true,
  effectivePriority: true,
  modelPriority: true,
  expertPriority: true,
  modelProbability: true,
  exploitProbability: true,
  application: { select: { id: true, name: true } },
  correction: { select: { status: true, assigneeId: true, dueDate: true } },
} as const;

@Injectable()
export class FindingsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async list(f: FindingFilters) {
    const page = f.page ?? 1;
    const pageSize = Math.min(f.pageSize ?? 25, 100);
    const where: Prisma.FindingWhereInput = {
      ...(f.applicationId && { applicationId: f.applicationId }),
      ...(f.priority && { effectivePriority: f.priority }),
      ...(f.severity !== undefined && { severity: f.severity }),
      ...(f.status && { correction: { is: { status: f.status } } }),
      ...(f.q && {
        OR: [
          { title: { contains: f.q, mode: 'insensitive' } },
          { cveId: { contains: f.q, mode: 'insensitive' } },
          ...(/^\d+$/.test(f.q) ? [{ cweId: Number(f.q) }] : []),
        ],
      }),
    };
    const dir = f.order ?? (f.sort === 'priority' || !f.sort ? 'asc' : 'desc');
    const orderBy: Prisma.FindingOrderByWithRelationInput[] =
      f.sort === 'severity'
        ? [{ severity: dir }, { modelProbability: 'desc' }]
        : f.sort === 'probability'
          ? [{ modelProbability: { sort: dir, nulls: 'last' } }]
          : f.sort === 'lastSeen'
            ? [{ lastSeenAt: dir }]
            : [{ effectivePriority: { sort: dir, nulls: 'last' } }, { modelProbability: { sort: 'desc', nulls: 'last' } }, { severity: 'desc' }];
    const [total, items] = await Promise.all([
      this.prisma.finding.count({ where }),
      this.prisma.finding.findMany({ where, orderBy, skip: (page - 1) * pageSize, take: pageSize, select: LIST_SELECT }),
    ]);
    return { total, page, pageSize, simulated: true, items: items.map((i) => ({ ...i, priority: i.effectivePriority })) };
  }

  async get(id: string, actor: AuthUser, ctx: AuditContext) {
    const finding = await this.prisma.finding.findUnique({
      where: { id },
      include: {
        application: { select: { id: true, name: true, exposure: true, sensitivity: true } },
        correction: { include: { assignee: { select: { id: true, name: true } } } },
        annotations: { orderBy: { createdAt: 'desc' }, include: { annotator: { select: { id: true, name: true } } } },
      },
    });
    if (!finding) throw new NotFoundException('Constat introuvable.');
    const [m1, m2] = await Promise.all([
      this.prisma.prediction.findFirst({ where: { findingId: id, model: 'M1' }, orderBy: { createdAt: 'desc' } }),
      this.prisma.prediction.findFirst({ where: { findingId: id, model: 'M2' }, orderBy: { createdAt: 'desc' } }),
    ]);
    await this.audit.log(ctx, { action: 'FINDING_VIEW', outcome: 'SUCCESS', userId: actor.id, resourceType: 'Finding', resourceId: id });
    return { ...finding, priority: finding.effectivePriority, predictions: { m1, m2 }, simulated: true };
  }

  async annotate(actor: AuthUser, id: string, priority: Priority, comment: string | undefined, ctx: AuditContext) {
    const finding = await this.prisma.finding.findUnique({ where: { id }, select: { id: true } });
    if (!finding) throw new NotFoundException('Constat introuvable.');
    const annotation = await this.prisma.$transaction(async (tx) => {
      const a = await tx.annotation.create({
        data: { findingId: id, annotatorId: actor.id, priority, comment },
      });
      await tx.finding.update({ where: { id }, data: { expertPriority: priority, effectivePriority: priority } });
      return a;
    });
    await this.audit.log(ctx, {
      action: 'FINDING_ANNOTATE',
      outcome: 'SUCCESS',
      userId: actor.id,
      resourceType: 'Finding',
      resourceId: id,
      metadata: { priority },
    });
    return annotation;
  }

  async updateCorrection(
    actor: AuthUser,
    id: string,
    input: { status?: CorrectionStatus; assigneeId?: string | null; dueDate?: string | null; comment?: string },
    ctx: AuditContext,
  ) {
    const correction = await this.prisma.correction.findUnique({ where: { findingId: id } });
    if (!correction) throw new NotFoundException('Constat introuvable.');

    if (input.status !== undefined && input.status !== correction.status && !canTransition(correction.status, input.status)) {
      await this.audit.log(ctx, {
        action: 'FINDING_STATUS_CHANGE',
        outcome: 'DENIED',
        userId: actor.id,
        resourceType: 'Finding',
        resourceId: id,
        metadata: { from: correction.status, to: input.status },
      });
      throw new ConflictException(`Transition interdite : ${correction.status} → ${input.status}.`);
    }

    if (input.assigneeId) {
      const assignee = await this.prisma.user.findUnique({ where: { id: input.assigneeId } });
      if (!assignee || !assignee.active || assignee.role === 'DECISION_MAKER') {
        throw new BadRequestException("L'assigné doit être un analyste ou un administrateur actif.");
      }
    }
    const nextStatus = input.status ?? correction.status;
    const nextAssignee = input.assigneeId === undefined ? correction.assigneeId : input.assigneeId;
    if (nextStatus === 'ASSIGNED' && !nextAssignee) {
      throw new BadRequestException('Une personne assignée est requise pour ce statut.');
    }

    const updated = await this.prisma.correction.update({
      where: { findingId: id },
      data: {
        ...(input.status !== undefined && { status: input.status }),
        ...(input.assigneeId !== undefined && { assigneeId: input.assigneeId }),
        ...(input.dueDate !== undefined && { dueDate: input.dueDate ? new Date(input.dueDate) : null }),
        ...(input.comment !== undefined && { comment: input.comment }),
      },
    });
    await this.audit.log(ctx, {
      action: input.status !== undefined && input.status !== correction.status ? 'FINDING_STATUS_CHANGE' : 'FINDING_CORRECTION_UPDATE',
      outcome: 'SUCCESS',
      userId: actor.id,
      resourceType: 'Finding',
      resourceId: id,
      metadata: { from: correction.status, to: updated.status },
    });
    return updated;
  }
}
