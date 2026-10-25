import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { AuditService } from '../audit/audit.service.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import type { Exposure, Sensitivity } from '../generated/prisma/enums.js';
import { PrismaService } from '../prisma/prisma.service.js';

export interface ApplicationInput {
  name: string;
  description?: string | null;
  exposure: Exposure;
  sensitivity: Sensitivity;
}

@Injectable()
export class ApplicationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
  ) {}

  async list() {
    const apps = await this.prisma.application.findMany({
      orderBy: { name: 'asc' },
      include: { _count: { select: { findings: true, scans: true } } },
    });
    return apps.map(({ _count, ...a }) => ({ ...a, findingsCount: _count.findings, scansCount: _count.scans }));
  }

  async get(id: string) {
    const app = await this.prisma.application.findUnique({ where: { id } });
    if (!app) throw new NotFoundException('Application introuvable.');
    return app;
  }

  async create(actor: AuthUser, input: ApplicationInput, ctx: AuditContext) {
    try {
      const app = await this.prisma.application.create({ data: input });
      await this.audit.log(ctx, { action: 'APPLICATION_CREATE', outcome: 'SUCCESS', userId: actor.id, resourceType: 'Application', resourceId: app.id });
      return app;
    } catch (err) {
      throw this.mapUnique(err);
    }
  }

  async update(actor: AuthUser, id: string, input: Partial<ApplicationInput>, ctx: AuditContext) {
    await this.get(id);
    try {
      const app = await this.prisma.application.update({ where: { id }, data: input });
      await this.audit.log(ctx, { action: 'APPLICATION_UPDATE', outcome: 'SUCCESS', userId: actor.id, resourceType: 'Application', resourceId: id });
      return app;
    } catch (err) {
      throw this.mapUnique(err);
    }
  }

  async remove(actor: AuthUser, id: string, ctx: AuditContext): Promise<void> {
    await this.get(id);
    const scans = await this.prisma.scan.count({ where: { applicationId: id } });
    if (scans > 0) {
      throw new ConflictException('Suppression impossible : des imports sont rattachés à cette application.');
    }
    await this.prisma.application.delete({ where: { id } });
    await this.audit.log(ctx, { action: 'APPLICATION_DELETE', outcome: 'SUCCESS', userId: actor.id, resourceType: 'Application', resourceId: id });
  }

  private mapUnique(err: unknown): unknown {
    if ((err as any)?.code === 'P2002') return new ConflictException('Une application porte déjà ce nom.');
    return err;
  }
}
