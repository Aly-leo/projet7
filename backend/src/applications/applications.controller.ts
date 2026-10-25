import { Body, Controller, Delete, Get, HttpCode, Param, ParseUUIDPipe, Post, Put } from '@nestjs/common';
import { IsEnum, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';
import { AdminOnly, AnalystOrAdmin, Ctx, CurrentUser, RateLimit } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { Exposure, Sensitivity } from '../generated/prisma/enums.js';
import { ApplicationsService } from './applications.service.js';

class CreateApplicationDto {
  @IsString() @MinLength(2) @MaxLength(100) name!: string;
  @IsOptional() @IsString() @MaxLength(500) description?: string;
  @IsEnum(Exposure) exposure!: Exposure;
  @IsEnum(Sensitivity) sensitivity!: Sensitivity;
}

class UpdateApplicationDto {
  @IsOptional() @IsString() @MinLength(2) @MaxLength(100) name?: string;
  @IsOptional() @IsString() @MaxLength(500) description?: string;
  @IsOptional() @IsEnum(Exposure) exposure?: Exposure;
  @IsOptional() @IsEnum(Sensitivity) sensitivity?: Sensitivity;
}

const ADMIN_LIMIT = { name: 'admin', limit: 60, windowMs: 60_000, by: 'user' } as const;

@Controller('applications')
export class ApplicationsController {
  constructor(private readonly apps: ApplicationsService) {}

  @Get()
  @AnalystOrAdmin()
  list() {
    return this.apps.list();
  }

  @Post()
  @AdminOnly()
  @RateLimit(ADMIN_LIMIT)
  create(@CurrentUser() actor: AuthUser, @Body() dto: CreateApplicationDto, @Ctx() ctx: AuditContext) {
    return this.apps.create(actor, dto, ctx);
  }

  @Put(':id')
  @AdminOnly()
  @RateLimit(ADMIN_LIMIT)
  update(
    @CurrentUser() actor: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateApplicationDto,
    @Ctx() ctx: AuditContext,
  ) {
    return this.apps.update(actor, id, dto, ctx);
  }

  @Delete(':id')
  @AdminOnly()
  @HttpCode(204)
  @RateLimit(ADMIN_LIMIT)
  remove(@CurrentUser() actor: AuthUser, @Param('id', ParseUUIDPipe) id: string, @Ctx() ctx: AuditContext) {
    return this.apps.remove(actor, id, ctx);
  }
}
