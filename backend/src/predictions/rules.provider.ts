import { Injectable } from '@nestjs/common';
import {
  clamp,
  priorityFor,
  round3,
  type Feature,
  type M1Input,
  type M1Output,
  type M2Input,
  type M2Output,
  type PredictionProvider,
} from './prediction.types.js';

/** Taux d'exploitation de démonstration par CWE (valeurs fictives, NON issues de données réelles). */
const DEMO_CWE_BONUS: Record<number, number> = {
  89: 0.35, // injection SQL
  79: 0.2, // XSS
  22: 0.2, // traversée de chemin
  78: 0.3, // injection de commande
  352: 0.1, // CSRF
  611: 0.15, // XXE
  918: 0.2, // SSRF
  200: 0.05,
  693: -0.05, // en-têtes de sécurité
  1021: -0.05,
};
const SEVERITY_BASE = [0.03, 0.1, 0.25, 0.45];
const CONFIDENCE_FACTOR: Record<string, number> = { 'False Positive': 0.2, Low: 0.7, Medium: 0.85, High: 1, Confirmed: 1.1 };
const EXPOSURE_W = { PUBLIC: 0.3, INTERNAL: 0.12, RESTRICTED: 0.03 };
const SENSITIVITY_W = { HIGH: 0.25, MEDIUM: 0.12, LOW: 0.04 };

/**
 * Fournisseur déterministe : formule documentée dans docs/ARCHITECTURE.md.
 * Les sorties sont SIMULÉES, elles ne proviennent d'aucun modèle entraîné.
 */
@Injectable()
export class RuleBasedProvider implements PredictionProvider {
  readonly name = 'rules' as const;

  async predictM1(input: M1Input[]): Promise<M1Output[]> {
    return input.map((f) => {
      const base = SEVERITY_BASE[f.severity] ?? 0.03;
      const cwe = f.cweId ? (DEMO_CWE_BONUS[f.cweId] ?? 0) : 0;
      const conf = CONFIDENCE_FACTOR[f.confidence ?? 'Medium'] ?? 0.85;
      const cve = f.cveId ? 0.15 : 0;
      return { findingId: f.findingId, exploitationProbability: round3(clamp((base + cwe) * conf + cve, 0.01, 0.99)) };
    });
  }

  async predictM2(input: M2Input[]): Promise<M2Output[]> {
    return input.map((f) => {
      const parts: Record<Feature, number> = {
        technicalSeverity: (f.severity / 3) * 0.25,
        exposure: EXPOSURE_W[f.exposure],
        sensitivity: SENSITIVITY_W[f.sensitivity],
        m1Probability: f.m1Probability * 0.35,
        controlsInPlace: f.exposure === 'PUBLIC' ? 0 : -0.04,
        remediationHistory: f.instancesCount > 10 ? 0.03 : 0,
      };
      const sum = Object.values(parts).reduce((a, b) => a + b, 0);
      let probability = clamp(sum, 0.01, 0.99);
      if (f.severity === 0) probability = Math.min(probability, 0.2);
      return {
        findingId: f.findingId,
        priority: priorityFor(probability, f.severity),
        calibratedProbability: round3(probability),
        explanation: (Object.entries(parts) as [Feature, number][])
          .map(([feature, contribution]) => ({ feature, contribution: round3(contribution) }))
          .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution)),
      };
    });
  }
}
