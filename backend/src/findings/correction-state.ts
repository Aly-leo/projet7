import type { CorrectionStatus } from '../generated/prisma/enums.js';

/** Machine à états du cycle de vie d'un constat. Toute autre transition est refusée (409). */
export const TRANSITIONS: Record<CorrectionStatus, CorrectionStatus[]> = {
  IMPORTED: ['VALIDATED'],
  VALIDATED: ['PRIORITIZED', 'REJECTED'],
  PRIORITIZED: ['ASSIGNED', 'REJECTED'],
  ASSIGNED: ['IN_REMEDIATION'],
  IN_REMEDIATION: ['REMEDIATED'],
  REMEDIATED: ['VERIFIED'],
  VERIFIED: ['CLOSED', 'IN_REMEDIATION'],
  CLOSED: [],
  REJECTED: [],
};

export function canTransition(from: CorrectionStatus, to: CorrectionStatus): boolean {
  return TRANSITIONS[from].includes(to);
}
