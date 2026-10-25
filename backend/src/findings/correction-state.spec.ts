import { describe, expect, it } from 'vitest';
import { CorrectionStatus } from '../generated/prisma/enums.js';
import { canTransition, TRANSITIONS } from './correction-state.js';

describe('Machine à états des corrections', () => {
  it('autorise le chemin nominal et les deux branches particulières', () => {
    const path: CorrectionStatus[] = ['IMPORTED', 'VALIDATED', 'PRIORITIZED', 'ASSIGNED', 'IN_REMEDIATION', 'REMEDIATED', 'VERIFIED', 'CLOSED'];
    for (let i = 0; i < path.length - 1; i++) expect(canTransition(path[i]!, path[i + 1]!)).toBe(true);
    expect(canTransition('VALIDATED', 'REJECTED')).toBe(true);
    expect(canTransition('VERIFIED', 'IN_REMEDIATION')).toBe(true);
  });

  it('refuse toutes les autres transitions', () => {
    const all = Object.keys(TRANSITIONS) as CorrectionStatus[];
    let allowed = 0;
    for (const a of all) for (const b of all) if (canTransition(a, b)) allowed++;
    expect(allowed).toBe(10); // 7 étapes nominales + REJECTED (x2: VALIDATED, PRIORITIZED) + retour de VERIFIED
    expect(canTransition('CLOSED', 'IMPORTED')).toBe(false);
    expect(canTransition('IMPORTED', 'CLOSED')).toBe(false);
    expect(canTransition('REJECTED', 'VALIDATED')).toBe(false);
    expect(canTransition('ASSIGNED', 'ASSIGNED')).toBe(false);
  });
});
