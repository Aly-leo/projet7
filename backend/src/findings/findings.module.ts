import { Module } from '@nestjs/common';
import { FindingsController } from './findings.controller.js';
import { FindingsService } from './findings.service.js';

@Module({ controllers: [FindingsController], providers: [FindingsService] })
export class FindingsModule {}
