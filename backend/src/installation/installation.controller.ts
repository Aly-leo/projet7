import { Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { IsEmail, IsString, MaxLength, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { AuditAs, Ctx, Public, RateLimit } from '../common/decorators.js';
import type { AuditContext } from '../common/types.js';
import { InstallationService } from './installation.service.js';

class InstallationDto {
  @IsString() @MinLength(2) @MaxLength(100) nom!: string;
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsEmail()
  @MaxLength(254)
  courriel!: string;
  @IsString() @MaxLength(128) motDePasse!: string;
}

@Controller('installation')
export class InstallationController {
  constructor(private readonly installation: InstallationService) {}

  @Get('etat')
  @Public()
  @RateLimit({ name: 'setup-state', limit: 60, windowMs: 60_000, by: 'ip' })
  state() {
    return this.installation.state();
  }

  @Post()
  @Public()
  @AuditAs('SETUP_DENIED')
  @HttpCode(201)
  @RateLimit({ name: 'setup', limit: 5, windowMs: 3_600_000, by: 'ip' })
  async install(@Body() dto: InstallationDto, @Ctx() ctx: AuditContext): Promise<{ ok: true }> {
    await this.installation.install(dto, ctx);
    return { ok: true };
  }
}
