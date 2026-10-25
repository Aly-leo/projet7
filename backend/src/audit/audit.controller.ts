import { Controller, Get, Query } from '@nestjs/common';
import { IsDateString, IsEnum, IsInt, IsOptional, IsString, IsUUID, Max, MaxLength, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { AdminOnly, Ctx, CurrentUser } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { AuditOutcome } from '../generated/prisma/enums.js';
import type { Prisma } from '../generated/prisma/client.js';

class AuditQueryDto {
  @IsOptional() @IsUUID() userId?: string;
  @IsOptional() @IsString() @MaxLength(60) action?: string;
  @IsOptional() @IsEnum(AuditOutcome) outcome?: AuditOutcome;
  @IsOptional() @IsDateString() from?: string;
  @IsOptional() @IsDateString() to?: string;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) page?: number;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100) pageSize?: number;
}

@Controller('audit')
export class AuditController {
  constructor(private readonly prisma: PrismaService) {}

  /** Journal d'audit en lecture seule (administrateur). */
  @Get()
  @AdminOnly()
  async list(@Query() q: AuditQueryDto, @CurrentUser() _user: AuthUser, @Ctx() _ctx: AuditContext) {
    const page = q.page ?? 1;
    const pageSize = q.pageSize ?? 50;
    const where: Prisma.AuditLogWhereInput = {
      ...(q.userId && { userId: q.userId }),
      ...(q.action && { action: { contains: q.action, mode: 'insensitive' } }),
      ...(q.outcome && { outcome: q.outcome }),
      ...((q.from || q.to) && {
        createdAt: { ...(q.from && { gte: new Date(q.from) }), ...(q.to && { lte: new Date(q.to) }) },
      }),
    };
    const [total, items] = await Promise.all([
      this.prisma.auditLog.count({ where }),
      this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip: (page - 1) * pageSize,
        take: pageSize,
      }),
    ]);
    return { total, page, pageSize, items };
  }
}
