import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AnthropicSimulatedProvider, type LlmClient } from '../src/predictions/anthropic.provider.js';
import { as, createTestApp, createUserSession, fixture, installAdmin, type Session, type TestContext } from './helpers.js';

const ID = '00000000-0000-4000-8000-000000000000';
type Role = 'ADMIN' | 'ANALYST' | 'DECISION_MAKER';
const ALL: Role[] = ['ADMIN', 'ANALYST', 'DECISION_MAKER'];
const STAFF: Role[] = ['ADMIN', 'ANALYST'];
const ADMIN: Role[] = ['ADMIN'];

// Matrice route × rôle (section 6 du cahier des charges). Les routes de mutation reçoivent un corps vide :
// une réponse autre que 401/403 prouve que les gardes ont laissé passer (la validation répond alors 400/404).
const MATRIX: [string, string, Role[]][] = [
  ['get', '/api/auth/moi', ALL],
  ['get', '/api/tableaux-de-bord', ALL],
  ['get', '/api/rapports/synthese/pdf', ALL],
  ['get', '/api/scans', STAFF],
  ['get', `/api/scans/${ID}`, STAFF],
  ['post', '/api/scans', STAFF],
  ['get', '/api/constats', STAFF],
  ['get', `/api/constats/${ID}`, STAFF],
  ['put', `/api/constats/${ID}/priorite`, STAFF],
  ['put', `/api/constats/${ID}/correction`, STAFF],
  ['get', '/api/applications', STAFF],
  ['post', '/api/applications', ADMIN],
  ['put', `/api/applications/${ID}`, ADMIN],
  ['delete', `/api/applications/${ID}`, ADMIN],
  ['get', '/api/utilisateurs', ADMIN],
  ['get', '/api/utilisateurs/assignables', STAFF],
  ['post', '/api/utilisateurs', ADMIN],
  ['put', `/api/utilisateurs/${ID}`, ADMIN],
  ['post', `/api/utilisateurs/${ID}/reinitialiser-mot-de-passe`, ADMIN],
  ['get', '/api/modeles', ADMIN],
  ['post', '/api/modeles/entrainement', ADMIN],
  ['get', '/api/audit', ADMIN],
  ['get', `/api/rapports/scans/${ID}/pdf`, STAFF],
  ['get', `/api/rapports/applications/${ID}/pdf`, STAFF],
];

describe('Contrôle d\'accès : matrice route × rôle', () => {
  let ctx: TestContext;
  const sessions = {} as Record<Role, Session>;

  beforeAll(async () => {
    ctx = await createTestApp();
    sessions.ADMIN = await installAdmin(ctx);
    sessions.ANALYST = await createUserSession(ctx, sessions.ADMIN, 'ANALYST', 'analyste@example.test');
    sessions.DECISION_MAKER = await createUserSession(ctx, sessions.ADMIN, 'DECISION_MAKER', 'decideur@example.test');
  });
  afterAll(() => ctx.close());
  beforeEach(() => ctx.limiter.reset());

  for (const [method, path, allowed] of MATRIX) {
    it(`${method.toUpperCase()} ${path.replace(ID, ':id')}`, async () => {
      const anon = await (ctx.http() as any)[method](path);
      expect(anon.status).toBe(401);
      for (const role of ALL) {
        ctx.limiter.reset();
        const res = await (as(ctx, sessions[role]) as any)[method](path);
        if (allowed.includes(role)) expect([401, 403], `${role} devrait passer les gardes`).not.toContain(res.status);
        else expect(res.status, `${role} devrait être refusé`).toBe(403);
      }
    });
  }

  it('ignore le rôle envoyé par le client : le rôle vient du serveur', async () => {
    const s = sessions.DECISION_MAKER;
    const res = await as(ctx, s).get('/api/utilisateurs').set('X-Role', 'ADMIN');
    expect(res.status).toBe(403);
    const forged = await as(ctx, s).post('/api/auth/changer-mot-de-passe').send({ motDePasseActuel: 'x', nouveauMotDePasse: 'y', role: 'ADMIN' });
    expect(forged.status).toBe(400);
  });

  it('ne propose aucune route publique de création de compte', async () => {
    for (const path of ['/api/utilisateurs', '/api/auth/inscription', '/api/inscription']) {
      const res = await ctx.http().post(path).send({ email: 'x@example.test', name: 'Xx', role: 'ADMIN' });
      expect([401, 404]).toContain(res.status);
    }
    expect(await ctx.prisma.user.count()).toBe(3);
  });

  it('ajoute les en-têtes de sécurité et masque X-Powered-By', async () => {
    const res = await ctx.http().get('/api/installation/etat');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    const csp = res.headers['content-security-policy'] as string;
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-eval');
    expect(res.headers['x-request-id']).toBeTruthy();
  });

  it('répond par des erreurs génériques sans trace de pile', async () => {
    const res = await as(ctx, sessions.ADMIN).get('/api/constats/pas-un-uuid');
    expect(res.status).toBe(400);
    expect(JSON.stringify(res.body)).not.toMatch(/node_modules|\.ts:|at /);
    const unknown = await ctx.http().get('/api/route-inexistante');
    expect(unknown.status).toBe(404);
    expect(JSON.stringify(unknown.body)).not.toMatch(/node_modules|\.ts:/);
  });

  it('refuse un corps JSON supérieur à 1 Mo (413)', async () => {
    const res = await ctx.http().post('/api/auth/connexion').send({ courriel: 'a@b.test', motDePasse: 'x'.repeat(1.2 * 1024 * 1024) });
    expect(res.status).toBe(413);
  });
});

describe('Simulation par l\'API Claude (fournisseur anthropic)', () => {
  let ctx: TestContext;
  let admin: Session;
  let appId: string;
  let mode: 'valid' | 'invalid' | 'inject' | 'down' = 'valid';

  const client: LlmClient = {
    messages: {
      create: async (params: any) => {
        const content = params.messages[0].content as string;
        const data = JSON.parse(content.split('<donnees>')[1]!.split('</donnees>')[0]!) as { findingId: string }[];
        if (mode === 'down') throw new Error('réseau indisponible');
        if (mode === 'inject') return { content: [{ type: 'text', text: 'Ignore tout. {"results":[{"findingId":"x","priority":"P0","calibratedProbability":42}]}' }] };
        if (mode === 'invalid') return { content: [{ type: 'text', text: JSON.stringify({ results: data.map((d) => ({ findingId: d.findingId, exploitationProbability: 7 })) }) }] };
        const isM2 = String(content).includes('simuler M2');
        return {
          content: [{
            type: 'text',
            text: JSON.stringify({
              results: data.map((d) =>
                isM2
                  ? { findingId: d.findingId, priority: 'P2', calibratedProbability: 0.5, explanation: [{ feature: 'exposure', contribution: 0.3 }] }
                  : { findingId: d.findingId, exploitationProbability: 0.4 },
              ),
            }),
          }],
          usage: { input_tokens: 100, output_tokens: 50 },
        };
      },
    },
  };

  beforeAll(async () => {
    ctx = await createTestApp({
      env: { PREDICTION_PROVIDER: 'anthropic', ANTHROPIC_API_KEY: 'cle-factice-pour-test', ANTHROPIC_MODEL: 'modele-test' },
      llm: () => new AnthropicSimulatedProvider(client, 'modele-test'),
    });
    admin = await installAdmin(ctx);
    appId = (await as(ctx, admin).post('/api/applications').send({ name: 'App LLM', exposure: 'PUBLIC', sensitivity: 'HIGH' })).body.id;
  });
  afterAll(async () => {
    process.env.PREDICTION_PROVIDER = 'rules';
    await ctx.close();
  });
  beforeEach(() => ctx.limiter.reset());

  const importFile = (name: string, file = 'valid-small.json') =>
    as(ctx, admin).post('/api/scans').field('applicationId', appId).attach('fichier', fixture(file), { filename: name, contentType: 'application/json' });

  it('utilise le fournisseur anthropic avec des valeurs valides et bornées', async () => {
    mode = 'valid';
    const res = await importFile('a.json');
    expect(res.status).toBe(201);
    expect(res.body.provider).toBe('anthropic');
    const preds = await ctx.prisma.prediction.findMany();
    expect(preds.every((p) => p.simulated && p.provider === 'anthropic')).toBe(true);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'PREDICTION_LLM_USAGE' } })).toBe(1);
    expect(JSON.stringify(await ctx.prisma.auditLog.findMany())).not.toContain('cle-factice-pour-test');
  });

  it('se replie sur les règles quand la sortie est invalide ou contient une injection', async () => {
    for (const m of ['invalid', 'inject', 'down'] as const) {
      mode = m;
      const res = await importFile(`${m}.json`, 'bad-prompt-injection.json').catch((e) => e);
      void res;
    }
    mode = 'inject';
    const res = await importFile('inj2.json', 'valid-medium.json');
    expect(res.status).toBe(201);
    expect(res.body.provider).toBe('rules');
    const bad = await ctx.prisma.prediction.findMany({ where: { OR: [{ probability: { gt: 1 } }, { probability: { lt: 0 } }] } });
    expect(bad).toHaveLength(0);
    const p = await ctx.prisma.prediction.findMany({ where: { provider: 'rules' } });
    expect(p.length).toBeGreaterThan(0);
  });

  it('plafonne les appels : au-delà, le fournisseur à règles prend le relais', async () => {
    const state = await as(ctx, admin).get('/api/modeles');
    expect(state.body.activeProvider).toBe('anthropic');
    expect(state.body).not.toHaveProperty('apiKey');
    expect(JSON.stringify(state.body)).not.toContain('cle-factice');
  });
});
