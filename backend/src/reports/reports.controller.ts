import { BadRequestException, Controller, Get, Param, ParseUUIDPipe, Query, Res, StreamableFile } from '@nestjs/common';
import type { Response } from 'express';
import { IsOptional, IsString, MaxLength } from 'class-validator';
import { AllRoles, AnalystOrAdmin, AuditAs, Ctx, CurrentUser, RateLimit } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import type { Priority } from '../generated/prisma/enums.js';
import { ReportsService, type ReportKind } from './reports.service.js';

class ReportQuery {
  @IsOptional() @IsString() @MaxLength(20) priorites?: string;
  @IsOptional() @IsString() @MaxLength(5) inclureDetails?: string;
}

const LIMIT = { name: 'report', limit: (env: Record<string, any>) => env.REPORT_EXPORTS_PER_HOUR as number, windowMs: 3_600_000, by: 'user' } as const;

function parse(q: ReportQuery) {
  const allowed = new Set(['priorites', 'inclureDetails']);
  for (const k of Object.keys(q)) if (!allowed.has(k)) throw new BadRequestException(`Paramètre inconnu : ${k.slice(0, 30)}`);
  let priorities: Priority[] | undefined;
  if (q.priorites !== undefined) {
    const parts = String(q.priorites).split(',').map((s) => s.trim()).filter(Boolean);
    if (!parts.length || parts.length > 4 || parts.some((p) => !['P1', 'P2', 'P3', 'P4'].includes(p))) {
      throw new BadRequestException('Paramètre priorites invalide (ex. P1,P2).');
    }
    priorities = [...new Set(parts)] as Priority[];
  }
  if (q.inclureDetails !== undefined && !['true', 'false'].includes(String(q.inclureDetails))) {
    throw new BadRequestException('Paramètre inclureDetails invalide (true ou false).');
  }
  return { priorities, includeDetails: q.inclureDetails !== 'false' };
}

@Controller('rapports')
export class ReportsController {
  constructor(private readonly reports: ReportsService) {}

  @Get('scans/:id/pdf')
  @AnalystOrAdmin()
  @AuditAs('REPORT_EXPORT')
  @RateLimitReport()
  scan(@Param('id', ParseUUIDPipe) id: string, @Query() q: ReportQuery, @CurrentUser() u: AuthUser, @Ctx() ctx: AuditContext, @Res({ passthrough: true }) res: Response) {
    return this.send('scan', id, q, u, ctx, res);
  }

  @Get('applications/:id/pdf')
  @AnalystOrAdmin()
  @AuditAs('REPORT_EXPORT')
  @RateLimitReport()
  application(@Param('id', ParseUUIDPipe) id: string, @Query() q: ReportQuery, @CurrentUser() u: AuthUser, @Ctx() ctx: AuditContext, @Res({ passthrough: true }) res: Response) {
    return this.send('application', id, q, u, ctx, res);
  }

  @Get('synthese/pdf')
  @AllRoles()
  @AuditAs('REPORT_EXPORT')
  @RateLimitReport()
  summary(@Query() q: ReportQuery, @CurrentUser() u: AuthUser, @Ctx() ctx: AuditContext, @Res({ passthrough: true }) res: Response) {
    return this.send('summary', undefined, q, u, ctx, res);
  }

  private async send(kind: ReportKind, id: string | undefined, q: ReportQuery, u: AuthUser, ctx: AuditContext, res: Response) {
    const opts = parse(q);
    const buffer = await this.reports.generate(kind, id, u, opts, ctx);
    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${this.reports.fileName(kind)}"`,
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      'Content-Length': String(buffer.length),
    });
    return new StreamableFile(buffer);
  }
}

function RateLimitReport() {
  return RateLimit(LIMIT as any);
}
