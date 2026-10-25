import { Global, Module } from '@nestjs/common';
import { ApplicationsController } from './applications.controller.js';
import { ApplicationsService } from './applications.service.js';

@Global()
@Module({ controllers: [ApplicationsController], providers: [ApplicationsService], exports: [ApplicationsService] })
export class ApplicationsModule {}
