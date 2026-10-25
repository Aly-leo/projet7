import { Inject, Injectable, Logger, Optional } from '@nestjs/common';
import { createHash } from 'node:crypto';
import { AuditService } from '../audit/audit.service.js';
import type { AuditContext } from '../common/types.js';
import { ENV, type Env } from '../config/env.js';
import type { Prisma } from '../generated/prisma/client.js';
import { PrismaService } from '../prisma/prisma.service.js';
import { AnthropicSimulatedProvider, BATCH_SIZE } from './anthropic.provider.js';
import { RuleBasedProvider } from './rules.provider.js';
import {
  SIM_VERSION,
  type M1Input,
  type M1Output,
  type M2Input,
  type M2Output,
  type PredictionProvider,
} from './prediction.types.js';

/** Jeton permettant d'injecter un faux fournisseur LLM dans les tests. */
export const LLM_PROVIDER_FACTORY = Symbol('LLM_PROVIDER_FACTORY');
export type LlmProviderFactory = () => AnthropicSimulatedProvider | null;

export interface PredictionSummary {
  total: number;
  provider: 'anthropic' | 'rules' | 'mixed';
  fallback: boolean;
  byPriority: Record<'P1' | 'P2' | 'P3' | 'P4', number>;
}

@Injectable()
export class PredictionService {
  private readonly logger = new Logger(PredictionService.name);
  private readonly cache = new Map<string, M1Output | M2Output>();
  private llm: AnthropicSimulatedProvider | null | undefined;

  constructor(
    private readonly prisma: PrismaService,
    private readonly rules: RuleBasedProvider,
    private readonly audit: AuditService,
    @Inject(ENV) private readonly env: Env,
    @Optional() @Inject(LLM_PROVIDER_FACTORY) private readonly llmFactory?: LlmProviderFactory,
  ) {}

  /** Fournisseur actif (information affichée dans la page Modèles). */
  activeProvider(): 'anthropic' | 'rules' {
    return this.getLlm() ? 'anthropic' : 'rules';
  }

  private getLlm(): AnthropicSimulatedProvider | null {
    if (this.env.PREDICTION_PROVIDER !== 'anthropic') return null;
    if (this.llm === undefined) {
      if (this.llmFactory) this.llm = this.llmFactory();
      else if (this.env.ANTHROPIC_API_KEY && this.env.ANTHROPIC_MODEL) {
        this.llm = AnthropicSimulatedProvider.create(this.env.ANTHROPIC_API_KEY, this.env.ANTHROPIC_MODEL, this.env.LLM_TIMEOUT_MS);
      } else this.llm = null;
    }
    return this.llm;
  }

  /** Calcule M1 puis M2 (simulés) pour des constats, enregistre les prédictions et la priorité effective. */
  async predictFindings(findingIds: string[], ctx?: AuditContext): Promise<PredictionSummary> {
    const findings = await this.prisma.finding.findMany({
      where: { id: { in: findingIds } },
      include: { application: { select: { exposure: true, sensitivity: true } } },
    });
    const m1Inputs: M1Input[] = findings.map((f) => ({
      findingId: f.id,
      title: f.title,
      cweId: f.cweId,
      cveId: f.cveId,
      severity: f.severity,
      confidence: f.confidence,
    }));

    // Plafond d'appels par import : au-delà, le fournisseur à règles prend le relais.
    const llm = this.getLlm();
    const llmCapacity = llm ? Math.floor(this.env.LLM_MAX_CALLS_PER_IMPORT / 2) * BATCH_SIZE : 0;
    const llmIds = new Set(m1Inputs.slice(0, llmCapacity).map((i) => i.findingId));
    let fallback = findings.length > llmCapacity && this.env.PREDICTION_PROVIDER === 'anthropic';

    const m1Results = new Map<string, { out: M1Output; provider: PredictionProvider['name'] }>();
    const m2Results = new Map<string, { out: M2Output; provider: PredictionProvider['name'] }>();

    // --- M1 ---
    const m1Llm = m1Inputs.filter((i) => llmIds.has(i.findingId));
    const m1Rules = m1Inputs.filter((i) => !llmIds.has(i.findingId));
    const llmOk1 = await this.runBatches(llm, m1Llm, (p, b) => p.predictM1(b), (i) => this.key('M1', i), 'M1');
    for (const [id, out] of llmOk1.done) m1Results.set(id, { out, provider: 'anthropic' });
    if (llmOk1.failed.length) fallback = true;
    for (const out of await this.rules.predictM1([...m1Rules, ...llmOk1.failed])) m1Results.set(out.findingId, { out, provider: 'rules' });

    // --- M2 ---
    const ctxById = new Map(findings.map((f) => [f.id, f]));
    const m2Inputs: M2Input[] = m1Inputs.map((i) => {
      const f = ctxById.get(i.findingId)!;
      return {
        ...i,
        exposure: f.application.exposure,
        sensitivity: f.application.sensitivity,
        m1Probability: m1Results.get(i.findingId)!.out.exploitationProbability,
        instancesCount: f.instancesCount,
      };
    });
    const m2Llm = m2Inputs.filter((i) => llmIds.has(i.findingId) && m1Results.get(i.findingId)!.provider === 'anthropic');
    const m2LlmIds = new Set(m2Llm.map((i) => i.findingId));
    const m2Rules = m2Inputs.filter((i) => !m2LlmIds.has(i.findingId));
    const llmOk2 = await this.runBatches(llm, m2Llm, (p, b) => p.predictM2(b), (i) => this.key('M2', i), 'M2');
    for (const [id, out] of llmOk2.done) m2Results.set(id, { out, provider: 'anthropic' });
    if (llmOk2.failed.length) fallback = true;
    for (const out of await this.rules.predictM2([...m2Rules, ...llmOk2.failed])) m2Results.set(out.findingId, { out, provider: 'rules' });

    // --- Enregistrement ---
    const byPriority = { P1: 0, P2: 0, P3: 0, P4: 0 };
    const predictions: Prisma.PredictionCreateManyInput[] = [];
    for (const f of findings) {
      const m1 = m1Results.get(f.id)!;
      const m2 = m2Results.get(f.id)!;
      predictions.push(
        { findingId: f.id, model: 'M1', version: SIM_VERSION, simulated: true, provider: m1.provider, probability: m1.out.exploitationProbability },
        {
          findingId: f.id,
          model: 'M2',
          version: SIM_VERSION,
          simulated: true,
          provider: m2.provider,
          probability: m2.out.calibratedProbability,
          priority: m2.out.priority,
          explanation: m2.out.explanation as unknown as Prisma.InputJsonValue,
        },
      );
      byPriority[m2.out.priority]++;
    }
    await this.prisma.$transaction(
      async (tx) => {
        await tx.prediction.createMany({ data: predictions });
        for (const f of findings) {
          const m1 = m1Results.get(f.id)!.out;
          const m2 = m2Results.get(f.id)!.out;
          const updated = await tx.finding.update({
            where: { id: f.id },
            data: { exploitProbability: m1.exploitationProbability, modelProbability: m2.calibratedProbability, modelPriority: m2.priority },
            select: { expertPriority: true },
          });
          await tx.finding.update({ where: { id: f.id }, data: { effectivePriority: updated.expertPriority ?? m2.priority } });
        }
        await tx.correction.updateMany({
          where: { findingId: { in: findings.map((f) => f.id) }, status: { in: ['IMPORTED', 'VALIDATED'] } },
          data: { status: 'PRIORITIZED' },
        });
      },
      { timeout: 120_000, maxWait: 20_000 },
    );

    const providers = new Set([...m1Results.values(), ...m2Results.values()].map((r) => r.provider));
    const provider = providers.size > 1 ? 'mixed' : providers.has('anthropic') ? 'anthropic' : 'rules';
    if (llm && this.llm) {
      await this.audit.log(ctx, {
        action: 'PREDICTION_LLM_USAGE',
        outcome: fallback ? 'FAILURE' : 'SUCCESS',
        metadata: { ...llm.usage, fallback },
      });
    }
    return { total: findings.length, provider, fallback, byPriority };
  }

  private async runBatches<I extends { findingId: string }, O extends { findingId: string }>(
    llm: AnthropicSimulatedProvider | null,
    inputs: I[],
    call: (p: AnthropicSimulatedProvider, batch: I[]) => Promise<O[]>,
    keyOf: (i: I) => string,
    label: string,
  ): Promise<{ done: Map<string, O>; failed: I[] }> {
    const done = new Map<string, O>();
    const failed: I[] = [];
    if (!llm || inputs.length === 0) return { done, failed };
    const pending: I[] = [];
    for (const i of inputs) {
      const hit = this.cache.get(keyOf(i)) as O | undefined;
      if (hit) done.set(i.findingId, { ...hit, findingId: i.findingId });
      else pending.push(i);
    }
    for (let s = 0; s < pending.length; s += BATCH_SIZE) {
      const batch = pending.slice(s, s + BATCH_SIZE);
      try {
        for (const out of await call(llm, batch)) {
          done.set(out.findingId, out);
          const input = batch.find((b) => b.findingId === out.findingId);
          if (input && this.cache.size < 20_000) this.cache.set(keyOf(input), out as unknown as M1Output);
        }
      } catch (err) {
        this.logger.warn(`${label} : repli sur le fournisseur à règles (${(err as Error).message.slice(0, 100)})`);
        failed.push(...batch);
      }
    }
    return { done, failed };
  }

  /** Clé de cache : empreinte du constat et de son contexte (sans l'identifiant). */
  private key(kind: string, input: { findingId: string }): string {
    const { findingId: _id, ...rest } = input as Record<string, unknown>;
    return `${kind}:${createHash('sha256').update(JSON.stringify(rest)).digest('hex')}`;
  }
}
