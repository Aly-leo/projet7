import { Global, Module } from '@nestjs/common';
import { DashboardController } from './dashboard.controller.js';
import { DashboardService } from './dashboard.service.js';

@Global()
@Module({ controllers: [DashboardController], providers: [DashboardService], exports: [DashboardService] })
export class DashboardModule {}
