import { Controller, Get, HttpCode, Post } from '@nestjs/common';
import { AdminOnly, AuditAs, Ctx, CurrentUser, RateLimit } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { AuditService } from '../audit/audit.service.js';
import { Inject } from '@nestjs/common';
import { ENV, type Env } from '../config/env.js';
import { PredictionService } from '../predictions/prediction.service.js';
import { TrainedM1Provider } from '../predictions/trained-m1.provider.js';
import { SIM_VERSION } from '../predictions/prediction.types.js';
import { PrismaService } from '../prisma/prisma.service.js';

@Controller('modeles')
export class ModelsController {
  constructor(
    private readonly predictions: PredictionService,
    private readonly trained: TrainedM1Provider,
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  @Get()
  @AdminOnly()
  async state() {
    const m1Info = await this.trained.info();
    const m1Trained = this.trained.enabled;
    return {
      mode: 'SIMULATION',
      message: m1Trained
        ? "M1 est un modèle entraîné (service d'inférence) ; M2 n'est pas entraîné : ses sorties sont simulées."
        : 'Les modèles M1 et M2 ne sont pas entraînés : leurs sorties sont simulées.',
      m1: {
        mode: m1Trained ? 'trained' : 'simulated',
        configuredMode: this.env.M1_PROVIDER,
        serviceConfigured: Boolean(this.env.M1_SERVICE_URL && this.env.M1_SERVICE_TOKEN),
        serviceReachable: m1Trained ? m1Info !== null : null,
        info: m1Info,
      },
      m2: { mode: 'simulated' },
      version: SIM_VERSION,
      configuredProvider: this.env.PREDICTION_PROVIDER,
      activeProvider: this.predictions.activeProvider(),
      anthropicConfigured: Boolean(this.env.ANTHROPIC_API_KEY && this.env.ANTHROPIC_MODEL),
      metrics: null, // aucune métrique de performance inventée
      metricsPlanned: ['PR-AUC', 'F1', 'Score de Brier', 'ECE', 'Précision@k'],
    };
  }

  /** Relance les prédictions SIMULÉES pour tous les constats (aucun entraînement réel). */
  @Post('entrainement')
  @AdminOnly()
  @AuditAs('MODEL_RERUN')
  @HttpCode(200)
  @RateLimit({ name: 'rerun', limit: 6, windowMs: 3_600_000, by: 'user' })
  async rerun(@CurrentUser() user: AuthUser, @Ctx() ctx: AuditContext) {
    const ids = (await this.prisma.finding.findMany({ select: { id: true } })).map((f) => f.id);
    const summary = await this.predictions.predictFindings(ids, ctx);
    await this.audit.log(ctx, {
      action: 'MODEL_RERUN',
      outcome: 'SUCCESS',
      userId: user.id,
      metadata: { total: summary.total, provider: summary.provider, fallback: summary.fallback },
    });
    return { ...summary, simulated: true };
  }
}
