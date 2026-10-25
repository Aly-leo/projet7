import { BadRequestException, Injectable } from '@nestjs/common';
import * as argon2 from 'argon2';
import { randomInt } from 'node:crypto';
import { ZxcvbnFactory } from '@zxcvbn-ts/core';
import * as zxcvbnCommon from '@zxcvbn-ts/language-common';
import * as zxcvbnEn from '@zxcvbn-ts/language-en';
import * as zxcvbnFr from '@zxcvbn-ts/language-fr';

const estimator = new ZxcvbnFactory({
  translations: zxcvbnFr.translations,
  graphs: zxcvbnCommon.adjacencyGraphs,
  dictionary: {
    ...zxcvbnCommon.dictionary,
    ...zxcvbnEn.dictionary,
    ...zxcvbnFr.dictionary,
  },
});

export const PASSWORD_MIN_LENGTH = 12;
export const PASSWORD_MAX_LENGTH = 128;

// Paramètres Argon2id conformes aux recommandations OWASP (m=19 MiB, t=2, p=1 au minimum) ; renforcés ici.
const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 46_080, // 45 MiB
  timeCost: 3,
  parallelism: 1,
} as const;

@Injectable()
export class PasswordService {
  private dummyHash: Promise<string> | undefined;

  hash(password: string): Promise<string> {
    return argon2.hash(password, ARGON2_OPTIONS);
  }

  verify(hash: string, password: string): Promise<boolean> {
    return argon2.verify(hash, password).catch(() => false);
  }

  /**
   * Calcul factice quand l'utilisateur n'existe pas : le temps de réponse ne révèle pas
   * l'existence d'un compte (exigence 13.2).
   */
  async verifyDummy(password: string): Promise<void> {
    this.dummyHash ??= this.hash('mot-de-passe-factice-0123456789');
    await this.verify(await this.dummyHash, password);
  }

  /** Politique : 12 caractères au moins, refus des mots de passe faibles. */
  assertStrong(password: string, userInputs: string[] = []): void {
    if (typeof password !== 'string' || password.length < PASSWORD_MIN_LENGTH) {
      throw new BadRequestException(`Le mot de passe doit compter au moins ${PASSWORD_MIN_LENGTH} caractères.`);
    }
    if (password.length > PASSWORD_MAX_LENGTH) {
      throw new BadRequestException(`Le mot de passe ne doit pas dépasser ${PASSWORD_MAX_LENGTH} caractères.`);
    }
    const result = estimator.check(password, userInputs.filter(Boolean).map((s) => s.toLowerCase()));
    if (result.score < 3) {
      throw new BadRequestException(
        'Mot de passe trop faible : évitez les mots courants, les suites et les informations personnelles.',
      );
    }
  }

  /** Mot de passe temporaire aléatoire (jamais journalisé, affiché une seule fois à l'administrateur). */
  generateTemporary(): string {
    const lower = 'abcdefghijkmnopqrstuvwxyz';
    const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
    const digits = '23456789';
    const symbols = '!#$%*+-=?@';
    const all = lower + upper + digits + symbols;
    const pick = (set: string) => set[randomInt(set.length)]!;
    const chars = [pick(lower), pick(upper), pick(digits), pick(symbols)];
    while (chars.length < 20) chars.push(pick(all));
    for (let i = chars.length - 1; i > 0; i--) {
      const j = randomInt(i + 1);
      [chars[i], chars[j]] = [chars[j]!, chars[i]!];
    }
    return chars.join('');
  }
}
