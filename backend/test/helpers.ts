import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { Client } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';
import { configureApp } from '../src/app.setup.js';
import { RateLimiterService } from '../src/common/rate-limiter.service.js';
import { loadEnv } from '../src/config/env.js';
import { PrismaService } from '../src/prisma/prisma.service.js';
import { LLM_PROVIDER_FACTORY, type LlmProviderFactory } from '../src/predictions/prediction.service.js';

export const ADMIN_URL = () => process.env.TEST_ADMIN_URL ?? 'postgresql://postgres:postgres@localhost:54330/postgres';
export const STRONG = 'Vélo-Orage-Lune-4829!';
export const ORIGIN = 'http://localhost:4200';

export interface TestContext {
  app: INestApplication;
  prisma: PrismaService;
  limiter: RateLimiterService;
  http: () => ReturnType<typeof request>;
  close: () => Promise<void>;
}

/** Crée une base PostgreSQL dédiée au fichier de test, y applique les migrations SQL, et démarre l'application. */
export async function createTestApp(overrides: { env?: Record<string, string>; llm?: LlmProviderFactory } = {}): Promise<TestContext> {
  const dbName = `t_${randomBytes(6).toString('hex')}`;
  const admin = new Client({ connectionString: ADMIN_URL() });
  await admin.connect();
  await admin.query(`CREATE DATABASE ${dbName}`);
  await admin.end();

  const url = new URL(ADMIN_URL());
  url.pathname = `/${dbName}`;
  const dbUrl = url.toString();

  const db = new Client({ connectionString: dbUrl });
  await db.connect();
  const migrations = resolve(process.cwd(), 'prisma/migrations');
  for (const dir of readdirSync(migrations).filter((d) => /^\d+_/.test(d)).sort()) {
    await db.query(readFileSync(resolve(migrations, dir, 'migration.sql'), 'utf8'));
  }
  await db.end();

  process.env.DATABASE_URL = dbUrl;
  Object.assign(process.env, overrides.env ?? {});
  const env = loadEnv();

  let builder = Test.createTestingModule({ imports: [AppModule] });
  if (overrides.llm) builder = builder.overrideProvider(LLM_PROVIDER_FACTORY).useValue(overrides.llm);
  const moduleRef = await builder.compile();
  const app = moduleRef.createNestApplication();
  configureApp(app, env);
  await app.init();

  const prisma = app.get(PrismaService);
  const limiter = app.get(RateLimiterService);
  return {
    app,
    prisma,
    limiter,
    http: () => request(app.getHttpServer()),
    close: async () => {
      await app.close();
      const a = new Client({ connectionString: ADMIN_URL() });
      await a.connect();
      await a.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
      await a.end();
    },
  };
}

export interface Session {
  cookies: string[];
  csrf: string;
  user: any;
}

/** Ouvre une session : cookies HttpOnly + jeton CSRF. */
export async function login(ctx: TestContext, courriel: string, motDePasse: string): Promise<Session> {
  const res = await ctx.http().post('/api/auth/connexion').set('Origin', ORIGIN).send({ courriel, motDePasse });
  if (res.status !== 200) throw new Error(`Connexion impossible (${res.status}) : ${JSON.stringify(res.body)}`);
  const cookies = (res.headers['set-cookie'] as unknown as string[]).map((c) => c.split(';')[0]!);
  const csrf = cookies.find((c) => c.startsWith('csrf_token='))!.split('=')[1]!;
  return { cookies, csrf, user: res.body.user };
}

/** Requête authentifiée (cookies + en-têtes CSRF et Origin). */
export function as(ctx: TestContext, s: Session) {
  const wrap = (method: 'get' | 'post' | 'put' | 'delete', path: string) =>
    ctx.http()[method](path).set('Cookie', s.cookies).set('X-CSRF-Token', s.csrf).set('Origin', ORIGIN);
  return {
    get: (p: string) => wrap('get', p),
    post: (p: string) => wrap('post', p),
    put: (p: string) => wrap('put', p),
    delete: (p: string) => wrap('delete', p),
  };
}

/** Installe le premier administrateur via la route publique, puis le connecte. */
export async function installAdmin(ctx: TestContext, courriel = 'admin@example.test'): Promise<Session> {
  const res = await ctx
    .http()
    .post('/api/installation')
    .set('Origin', ORIGIN)
    .send({ nom: 'Admin Test', courriel, motDePasse: STRONG });
  if (res.status !== 201) throw new Error(`Installation impossible (${res.status}) : ${JSON.stringify(res.body)}`);
  return login(ctx, courriel, STRONG);
}

/** Crée un utilisateur via l'API admin, change son mot de passe temporaire, et le connecte. */
export async function createUserSession(
  ctx: TestContext,
  admin: Session,
  role: 'ANALYST' | 'DECISION_MAKER' | 'ADMIN',
  email: string,
): Promise<Session> {
  const created = await as(ctx, admin).post('/api/utilisateurs').send({ email, name: `Utilisateur ${role}`, role });
  if (created.status !== 201) throw new Error(`Création impossible (${created.status}) : ${JSON.stringify(created.body)}`);
  const temp = created.body.temporaryPassword as string;
  const first = await login(ctx, email, temp);
  const changed = await as(ctx, first).post('/api/auth/changer-mot-de-passe').send({ motDePasseActuel: temp, nouveauMotDePasse: STRONG });
  if (changed.status !== 200) throw new Error(`Changement impossible (${changed.status}) : ${JSON.stringify(changed.body)}`);
  return login(ctx, email, STRONG);
}

export function fixture(name: string): Buffer {
  return readFileSync(resolve(process.cwd(), '../fixtures/zap', name));
}
