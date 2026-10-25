import { Body, Controller, Get, Param, ParseUUIDPipe, Post, Query, UploadedFile, UseInterceptors } from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { memoryStorage } from 'multer';
import { AnalystOrAdmin, AuditAs, Ctx, CurrentUser, RateLimit } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { loadEnv } from '../config/env.js';
import { ScansService, type UploadedReport } from './scans.service.js';

class ImportDto {
  @IsUUID() applicationId!: string;
}
class PageDto {
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) page?: number;
  @IsOptional() @Type(() => Number) @IsInt() @Min(1) @Max(100) pageSize?: number;
}

const maxBytes = loadEnv().MAX_IMPORT_MB * 1024 * 1024;

@Controller('scans')
export class ScansController {
  constructor(private readonly scans: ScansService) {}

  /** Import d'un rapport ZAP (multipart). Fichier reçu en mémoire uniquement, jamais écrit sur le disque. */
  @Post()
  @AnalystOrAdmin()
  @AuditAs('SCAN_IMPORT')
  @RateLimit({ name: 'import', limit: (env) => env.IMPORTS_PER_HOUR, windowMs: 3_600_000, by: 'user' })
  @UseInterceptors(
    FileInterceptor('fichier', {
      storage: memoryStorage(),
      limits: { fileSize: maxBytes, files: 1, fields: 5, fieldSize: 1024, parts: 8 },
    }),
  )
  import(
    @CurrentUser() user: AuthUser,
    @Body() dto: ImportDto,
    @UploadedFile() file: UploadedReport | undefined,
    @Ctx() ctx: AuditContext,
  ) {
    return this.scans.importReport(user, dto.applicationId, file, ctx);
  }

  @Get()
  @AnalystOrAdmin()
  list(@Query() q: PageDto) {
    return this.scans.list(q.page, q.pageSize);
  }

  @Get(':id')
  @AnalystOrAdmin()
  get(@Param('id', ParseUUIDPipe) id: string) {
    return this.scans.get(id);
  }
}
