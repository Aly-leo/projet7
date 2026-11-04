import { z } from 'zod';
import type { Exposure, Priority, Sensitivity } from '../generated/prisma/enums.js';

export const SIM_VERSION = 'sim-0.1';

export const FEATURES = [
  'technicalSeverity',
  'exposure',
  'sensitivity',
  'controlsInPlace',
  'remediationHistory',
  'm1Probability',
] as const;
export type Feature = (typeof FEATURES)[number];

export interface M1Input {
  findingId: string;
  title: string;
  cweId: number | null;
  cveId: string | null;
  severity: number;
  confidence: string | null;
}
export interface M1Output {
  findingId: string;
  exploitationProbability: number;
}
export interface M2Input extends M1Input {
  exposure: Exposure;
  sensitivity: Sensitivity;
  m1Probability: number;
  instancesCount: number;
}
export interface M2Output {
  findingId: string;
  priority: Priority;
  calibratedProbability: number;
  explanation: { feature: Feature; contribution: number }[];
}

export interface PredictionProvider {
  readonly name: 'anthropic' | 'rules';
  predictM1(input: M1Input[]): Promise<M1Output[]>;
  predictM2(input: M2Input[]): Promise<M2Output[]>;
}

// Schémas de validation des sorties (utilisés pour la sortie du LLM, non fiable).
export const m1OutputSchema = z.object({
  results: z
    .array(
      z.object({
        findingId: z.string().max(64),
        exploitationProbability: z.number().min(0).max(1),
      }),
    )
    .max(200),
});
export const m2OutputSchema = z.object({
  results: z
    .array(
      z.object({
        findingId: z.string().max(64),
        priority: z.enum(['P1', 'P2', 'P3', 'P4']),
        calibratedProbability: z.number().min(0).max(1),
        explanation: z
          .array(z.object({ feature: z.enum(FEATURES), contribution: z.number().min(-1).max(1) }))
          .max(12),
      }),
    )
    .max(200),
});

export const clamp = (v: number, min = 0, max = 1) => Math.min(max, Math.max(min, v));
export const round3 = (v: number) => Math.round(v * 1000) / 1000;

/**
 * Adaptateur M1 entraîné → entrée de M2.
 * M1 entraîné donne une vraie probabilité d'entrée dans KEV (≈ 0,05 % en moyenne), très loin de l'échelle 0,03–0,99 pour laquelle
 * les seuils de M2 ont été écrits. M2 reçoit donc un NIVEAU relatif à la prévalence : échelle logarithmique de 0,1× la moyenne à
 * 100× la moyenne, ramenée à [0, 1] puis élevée au carré pour qu'un risque moyen (1×) pèse ≈ 0,11, comme un M1 simulé « ordinaire »
 * (0,03–0,1) ; 10× = 0,44 ; 100× = 1. Un CVE déjà dans KEV vaut 1. La logique de M2 n'est pas modifiée.
 */
export const NEUTRAL_M1_LEVEL = 1 / 9;
export function m1LevelForM2(relativeRisk: number | null | undefined, alreadyInKev?: boolean | null): number {
  if (alreadyInKev) return 1;
  if (relativeRisk == null || !Number.isFinite(relativeRisk) || relativeRisk <= 0) return round3(NEUTRAL_M1_LEVEL);
  return round3(clamp((Math.log10(relativeRisk) + 1) / 3) ** 2);
}

export function priorityFor(probability: number, severity: number): Priority {
  if (severity === 0) return 'P4'; // un constat purement informatif n'est jamais urgent
  if (probability >= 0.7) return 'P1';
  if (probability >= 0.45) return 'P2';
  if (probability >= 0.25) return 'P3';
  return 'P4';
}
