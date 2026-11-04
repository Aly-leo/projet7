import { Inject, Injectable, Logger } from '@nestjs/common';
import { z } from 'zod';
import { ENV, type Env } from '../config/env.js';

const CVE_RE = /^CVE-\d{4}-\d{4,}$/;
const MAX_BATCH = 500;

const responseSchema = z.object({
  predictions: z
    .array(
      z.object({
        probability: z.number().min(0).max(1),
        source: z.enum(['m1', 'cwe_rate', 'prior']),
        modelVersion: z.string().min(1).max(64),
        calibrated: z.boolean(),
        alreadyInKev: z.boolean().nullable().optional(),
        relativeRisk: z.number().min(0).max(1e6).nullable().optional(),
      }),
    )
    .max(MAX_BATCH),
});

export interface TrainedM1Input {
  findingId: string;
  cveId: string | null;
  cweId: number | null;
}

export interface TrainedM1Output {
  probability: number;
  source: 'm1' | 'cwe_rate' | 'prior';
  modelVersion: string;
  calibrated: boolean;
  /** Probabilité ÷ prévalence d'entraînement (1 = risque moyen). */
  relativeRisk: number | null;
  alreadyInKev: boolean | null;
}

/**
 * M1 ENTRAÎNÉ : appelle le service d'inférence (ml/m1). Seuls cveId et cweId sont envoyés (jamais titre, description ni URL).
 * Toute erreur est propagée : l'appelant bascule alors sur le fournisseur à règles et marque la prédiction comme SIMULÉE.
 */
@Injectable()
export class TrainedM1Provider {
  private readonly logger = new Logger(TrainedM1Provider.name);

  constructor(@Inject(ENV) private readonly env: Env) {}

  get enabled(): boolean {
    return this.env.M1_PROVIDER === 'trained' && Boolean(this.env.M1_SERVICE_URL && this.env.M1_SERVICE_TOKEN);
  }

  private headers(): Record<string, string> {
    return { 'Content-Type': 'application/json', 'X-M1-Token': this.env.M1_SERVICE_TOKEN! };
  }

  async predict(inputs: TrainedM1Input[]): Promise<Map<string, TrainedM1Output>> {
    const out = new Map<string, TrainedM1Output>();
    for (let s = 0; s < inputs.length; s += MAX_BATCH) {
      const batch = inputs.slice(s, s + MAX_BATCH);
      const items = batch.map((i) => ({
        ...(i.cveId && CVE_RE.test(i.cveId) ? { cveId: i.cveId } : {}),
        ...(i.cweId && i.cweId > 0 && i.cweId < 100_000 ? { cweId: `CWE-${i.cweId}` } : {}),
      }));
      const res = await fetch(`${this.env.M1_SERVICE_URL!.replace(/\/$/, '')}/m1/predict`, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify({ items }),
        signal: AbortSignal.timeout(this.env.M1_TIMEOUT_MS),
        redirect: 'error', // jamais de redirection : le service est une destination fixe de configuration
      });
      if (!res.ok) throw new Error(`service M1 : HTTP ${res.status}`);
      const parsed = responseSchema.parse(await res.json());
      if (parsed.predictions.length !== batch.length) throw new Error('service M1 : nombre de prédictions inattendu');
      batch.forEach((b, k) => {
        const p = parsed.predictions[k]!;
        out.set(b.findingId, {
          probability: p.probability,
          source: p.source,
          modelVersion: p.modelVersion,
          calibrated: p.calibrated,
          relativeRisk: p.relativeRisk ?? null,
          alreadyInKev: p.alreadyInKev ?? null,
        });
      });
    }
    return out;
  }

  /** Informations sur le modèle déployé (meilleur effort : null si le service est indisponible). */
  async info(): Promise<Record<string, unknown> | null> {
    if (!this.enabled) return null;
    try {
      const res = await fetch(`${this.env.M1_SERVICE_URL!.replace(/\/$/, '')}/model-info`, {
        headers: this.headers(),
        signal: AbortSignal.timeout(this.env.M1_TIMEOUT_MS),
        redirect: 'error',
      });
      return res.ok ? ((await res.json()) as Record<string, unknown>) : null;
    } catch (err) {
      this.logger.warn(`Service M1 indisponible : ${(err as Error).name}`);
      return null;
    }
  }
}
