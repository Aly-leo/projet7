import { Body, Controller, Get, Param, ParseUUIDPipe, Put, Query } from '@nestjs/common';
import { IsDateString, IsEnum, IsIn, IsInt, IsOptional, IsString, IsUUID, Max, MaxLength, Min, ValidateIf } from 'class-validator';
import { Type } from 'class-transformer';
import { AnalystOrAdmin, Ctx, CurrentUser } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { CorrectionStatus, Priority } from '../generated/prisma/enums.js';
import { FindingsService } from './findings.service.js';

class ListDto {
  @IsOptional() @IsUUID() applicationId?: string;
  @IsOptional() @IsEnum(Priority) priority?: Priority;
  @IsOptional() @IsEnum(CorrectionStatus) status?: CorrectionStatus;
  @IsOptional() @Type(() => Number) @IsInt() @Min(0) @Max(3) severity?: number;
  @IsOptional() @IsString() @MaxLength(100) q?: string;
  @IsOptional() @IsIn(['priority', 'severity', 'probability', 'lastSeen']) sort?: 'priority' | 'severity' | 'probability' | 'lastSeen';
  @IsOptional() @IsIn(['asc', 'desc']) order?: 'asc' | 'desc';
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) page?: number;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100) pageSize?: number;
}

class AnnotateDto {
  @IsEnum(Priority) priority!: Priority;
  @IsOptional() @IsString() @MaxLength(1000) comment?: string;
}

class CorrectionDto {
  @IsOptional() @IsEnum(CorrectionStatus) status?: CorrectionStatus;
  @IsOptional() @ValidateIf((_o, v) => v !== null) @IsUUID() assigneeId?: string | null;
  @IsOptional() @ValidateIf((_o, v) => v !== null) @IsDateString() dueDate?: string | null;
  @IsOptional() @IsString() @MaxLength(1000) comment?: string;
}

@Controller('constats')
export class FindingsController {
  constructor(private readonly findings: FindingsService) {}

  @Get()
  @AnalystOrAdmin()
  list(@Query() q: ListDto) {
    return this.findings.list(q);
  }

  @Get(':id')
  @AnalystOrAdmin()
  get(@Param('id', ParseUUIDPipe) id: string, @CurrentUser() user: AuthUser, @Ctx() ctx: AuditContext) {
    return this.findings.get(id, user, ctx);
  }

  @Put(':id/priorite')
  @AnalystOrAdmin()
  annotate(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AnnotateDto,
    @CurrentUser() user: AuthUser,
    @Ctx() ctx: AuditContext,
  ) {
    return this.findings.annotate(user, id, dto.priority, dto.comment, ctx);
  }

  @Put(':id/correction')
  @AnalystOrAdmin()
  correction(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: CorrectionDto,
    @CurrentUser() user: AuthUser,
    @Ctx() ctx: AuditContext,
  ) {
    return this.findings.updateCorrection(user, id, dto, ctx);
  }
}
