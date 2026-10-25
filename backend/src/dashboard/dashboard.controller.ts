import { Controller, Get, Query } from '@nestjs/common';
import { IsIn, IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { AllRoles, CurrentUser } from '../common/decorators.js';
import type { AuthUser } from '../common/types.js';
import { DashboardService } from './dashboard.service.js';

class DashboardQuery {
  @IsOptional() @IsUUID() applicationId?: string;
  @IsOptional() @Type(() => Number) @IsInt() @IsIn([7, 30, 90, 365]) @Min(1) @Max(365) periodDays?: number;
}

@Controller('tableaux-de-bord')
export class DashboardController {
  constructor(private readonly dashboard: DashboardService) {}

  @Get()
  @AllRoles()
  get(@CurrentUser() user: AuthUser, @Query() q: DashboardQuery) {
    return this.dashboard.dashboard(user.role, q);
  }
}
