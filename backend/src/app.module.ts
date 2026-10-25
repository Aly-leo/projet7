import { Module } from '@nestjs/common';
import { LoggerModule } from 'nestjs-pino';
import { randomUUID } from 'node:crypto';
import { ApplicationsModule } from './applications/applications.module.js';
import { AuditModule } from './audit/audit.module.js';
import { AuthModule } from './auth/auth.module.js';
import { CommonModule } from './common/common.module.js';
import { DashboardModule } from './dashboard/dashboard.module.js';
import { FindingsModule } from './findings/findings.module.js';
import { InstallationModule } from './installation/installation.module.js';
import { ModelsModule } from './models/models.module.js';
import { PredictionsModule } from './predictions/predictions.module.js';
import { PrismaModule } from './prisma/prisma.module.js';
import { ReportsModule } from './reports/reports.module.js';
import { ScansModule } from './scans/scans.module.js';
import { UsersModule } from './users/users.module.js';

@Module({
  imports: [
    LoggerModule.forRoot({
      pinoHttp: {
        level: process.env.NODE_ENV === 'test' ? 'silent' : 'info',
        genReqId: (req, res) => {
          const id = randomUUID();
          (req as any).id = id;
          res.setHeader('X-Request-Id', id);
          return id;
        },
        // Masquage des champs sensibles : aucun secret dans les journaux (exigence 13.6).
        redact: {
          paths: [
            'req.headers.cookie',
            'req.headers.authorization',
            'req.headers["x-csrf-token"]',
            'res.headers["set-cookie"]',
            'req.body.motDePasse',
            'req.body.nouveauMotDePasse',
            'req.body.motDePasseActuel',
          ],
          censor: '[masqué]',
        },
        serializers: {
          req: (req) => ({ id: req.id, method: req.method, url: String(req.url).split('?')[0], remoteAddress: req.remoteAddress }),
          res: (res) => ({ statusCode: res.statusCode }),
        },
      },
    }),
    PrismaModule,
    CommonModule,
    AuditModule,
    AuthModule,
    InstallationModule,
    UsersModule,
    ApplicationsModule,
    ScansModule,
    PredictionsModule,
    FindingsModule,
    DashboardModule,
    ModelsModule,
    ReportsModule,
  ],
})
export class AppModule {}
