import { Controller, Get, HttpCode, Post } from '@nestjs/common';
import { AdminOnly, AuditAs, Ctx, CurrentUser, RateLimit } from '../common/decorators.js';
import type { AuditContext, AuthUser } from '../common/types.js';
import { AuditService } from '../audit/audit.service.js';
import { Inject } from '@nestjs/common';
import { ENV, type Env } from '../config/env.js';
import { PredictionService } from '../predictions/prediction.service.js';
import { SIM_VERSION } from '../predictions/prediction.types.js';
import { PrismaService } from '../prisma/prisma.service.js';

@Controller('modeles')
export class ModelsController {
  constructor(
    private readonly predictions: PredictionService,
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  @Get()
  @AdminOnly()
  state() {
    return {
      mode: 'SIMULATION',
      message: 'Les modèles M1 et M2 ne sont pas entraînés : leurs sorties sont simulées.',
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
