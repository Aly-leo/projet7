import { z } from 'zod';

/** Jeton d'injection de la configuration validée. */
export const ENV = Symbol('ENV');

const bool = z
  .enum(['true', 'false', ''])
  .default('false')
  .transform((v) => v === 'true');

const int = (def: number, min = 1, max = 1_000_000) =>
  z.preprocess(
    (v) => (v === '' || v === undefined ? undefined : v),
    z.coerce.number().int().min(min).max(max).default(def),
  );

const optionalString = z
  .string()
  .optional()
  .transform((v) => (v && v.trim() !== '' ? v.trim() : undefined));

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: int(3000, 1, 65535),
  APP_ORIGIN: z.string().url().default('http://localhost:4200'),
  DATABASE_URL: z.string().min(1, 'DATABASE_URL est obligatoire'),
  DIRECT_URL: optionalString,
  JWT_ACCESS_SECRET: z.string().min(32, 'JWT_ACCESS_SECRET doit compter 32 caractères au moins'),
  JWT_ACCESS_TTL_MIN: int(15, 1, 120),
  REFRESH_TTL_DAYS: int(7, 1, 90),
  COOKIE_SECURE: bool,
  SEED_ADMIN_EMAIL: optionalString,
  SEED_ADMIN_PASSWORD: optionalString,
  SEED_DEMO: bool,
  REPORT_MAX_FINDINGS: int(500, 1, 5000),
  REPORT_MAX_PAGES: int(150, 1, 2000),
  REPORT_EXPORTS_PER_HOUR: int(20, 1, 1000),
  REPORT_TIMEOUT_MS: int(30_000, 1000, 300_000),
  MAX_IMPORT_MB: int(10, 1, 100),
  MAX_ALERTS_PER_IMPORT: int(5000, 1, 100_000),
  RAW_REPORT_MAX_MB: int(1, 0, 20),
  IMPORTS_PER_HOUR: int(10, 1, 1000),
  PREDICTION_PROVIDER: z.enum(['rules', 'anthropic']).default('rules'),
  ANTHROPIC_API_KEY: optionalString,
  ANTHROPIC_MODEL: optionalString,
  LLM_MAX_CALLS_PER_IMPORT: int(20, 0, 500),
  LLM_TIMEOUT_MS: int(20_000, 1000, 120_000),
  FRONTEND_DIST: optionalString,
});

export type Env = z.infer<typeof schema>;

/**
 * Valide les variables d'environnement. L'application refuse de démarrer si un secret
 * manque ou est trop faible en production (exigence 13.4).
 */
export function loadEnv(source: NodeJS.ProcessEnv = process.env): Env {
  const parsed = schema.safeParse(source);
  if (!parsed.success) {
    const details = parsed.error.issues.map((i) => `  - ${i.path.join('.')} : ${i.message}`).join('\n');
    throw new Error(`Configuration invalide :\n${details}`);
  }
  const env = parsed.data;
  if (env.NODE_ENV === 'production') {
    const problems: string[] = [];
    if (env.JWT_ACCESS_SECRET.length < 64) problems.push('JWT_ACCESS_SECRET doit compter 64 caractères au moins en production');
    if (!env.COOKIE_SECURE) problems.push('COOKIE_SECURE doit valoir true en production');
    if (!env.APP_ORIGIN.startsWith('https://')) problems.push('APP_ORIGIN doit être en https en production');
    if (env.PREDICTION_PROVIDER === 'anthropic' && (!env.ANTHROPIC_API_KEY || !env.ANTHROPIC_MODEL)) {
      problems.push('ANTHROPIC_API_KEY et ANTHROPIC_MODEL sont requis avec PREDICTION_PROVIDER=anthropic');
    }
    if (problems.length) throw new Error(`Configuration de production invalide :\n  - ${problems.join('\n  - ')}`);
  }
  return env;
}
