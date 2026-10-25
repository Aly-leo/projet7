import { Body, Controller, Get, HttpCode, Param, ParseUUIDPipe, Post, Put } from '@nestjs/common';
import { IsBoolean, IsEmail, IsEnum, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';
import { Transform } from 'class-transformer';
import { AdminOnly, AnalystOrAdmin, Ctx, CurrentUser, RateLimit } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { Role } from '../generated/prisma/enums.js';
import { UsersService } from './users.service.js';

class CreateUserDto {
  @Transform(({ value }) => (typeof value === 'string' ? value.trim().toLowerCase() : value))
  @IsEmail()
  @MaxLength(254)
  email!: string;
  @IsString() @MinLength(2) @MaxLength(100) name!: string;
  @IsEnum(Role) role!: Role;
}

class UpdateUserDto {
  @IsOptional() @IsString() @MinLength(2) @MaxLength(100) name?: string;
  @IsOptional() @IsEnum(Role) role?: Role;
  @IsOptional() @IsBoolean() active?: boolean;
}

const ADMIN_LIMIT = { name: 'admin', limit: 60, windowMs: 60_000, by: 'user' } as const;

@Controller('utilisateurs')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  /** Personnes assignables à une correction (id et nom seulement) : ouvert aux analystes. */
  @Get('assignables')
  @AnalystOrAdmin()
  assignable() {
    return this.users.assignable();
  }

  @Get()
  @AdminOnly()
  list() {
    return this.users.list();
  }

  @Post()
  @AdminOnly()
  @RateLimit(ADMIN_LIMIT)
  create(@CurrentUser() actor: AuthUser, @Body() dto: CreateUserDto, @Ctx() ctx: AuditContext) {
    return this.users.create(actor, dto, ctx);
  }

  @Put(':id')
  @AdminOnly()
  @RateLimit(ADMIN_LIMIT)
  update(
    @CurrentUser() actor: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserDto,
    @Ctx() ctx: AuditContext,
  ) {
    return this.users.update(actor, id, dto, ctx);
  }

  @Post(':id/reinitialiser-mot-de-passe')
  @AdminOnly()
  @HttpCode(200)
  @RateLimit(ADMIN_LIMIT)
  reset(@CurrentUser() actor: AuthUser, @Param('id', ParseUUIDPipe) id: string, @Ctx() ctx: AuditContext) {
    return this.users.resetPassword(actor, id, ctx);
  }
}
