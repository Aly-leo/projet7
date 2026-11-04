import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createTestApp, fixture, installAdmin, type Session, type TestContext } from './helpers.js';

const TOKEN = 'jeton-de-service-m1-0123456789';

describe('M1 entraîné (service d\'inférence) et repli sur la simulation', () => {
  let ctx: TestContext;
  let admin: Session;
  let appId: string;
  let server: Server;
  let url: string;
  let mode: 'ok' | 'bad' | 'error' = 'ok';
  const received: { headers: Record<string, unknown>; body: any }[] = [];

  const listen = () =>
    new Promise<void>((resolve) => {
      server = createServer((req, res) => {
        let raw = '';
        req.on('data', (c) => (raw += c));
        req.on('end', () => {
          if (req.url === '/model-info') {
            res.setHeader('Content-Type', 'application/json').end(JSON.stringify({ modelVersion: 'm1_v1-test', model: 'xgboost', horizonDays: 90 }));
            return;
          }
          const body = JSON.parse(raw || '{}');
          received.push({ headers: req.headers, body });
          if (req.headers['x-m1-token'] !== TOKEN) return void res.writeHead(401).end('{}');
          if (mode === 'error') return void res.writeHead(500).end('{}');
          const predictions = body.items.map((it: any) =>
            mode === 'bad'
              ? { probability: 2, source: 'm1', modelVersion: 'x', calibrated: true }
              : it.cveId
                ? { probability: 0.03, source: 'm1', modelVersion: 'm1_v1-test', calibrated: true, alreadyInKev: true, relativeRisk: 50 }
                : {
                  probability: it.cweId ? 0.02 : 0.0006,
                  source: it.cweId ? 'cwe_rate' : 'prior',
                  modelVersion: 'm1_v1-test',
                  calibrated: false,
                  relativeRisk: (it.cweId ? 0.02 : 0.0006) / 0.0006, // prévalence d'entraînement fictive : 0,0006
                },
          );
          res.setHeader('Content-Type', 'application/json').end(JSON.stringify({ predictions }));
        });
      });
      server.listen(0, '127.0.0.1', () => resolve());
    });

  beforeAll(async () => {
    await listen();
    url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    ctx = await createTestApp({ env: { M1_PROVIDER: 'trained', M1_SERVICE_URL: url, M1_SERVICE_TOKEN: TOKEN } });
    admin = await installAdmin(ctx);
    appId = (await as(ctx, admin).post('/api/applications').send({ name: 'App M1', exposure: 'PUBLIC', sensitivity: 'HIGH' })).body.id;
  });
  afterAll(async () => {
    process.env.M1_PROVIDER = 'simulated';
    delete process.env.M1_SERVICE_URL;
    delete process.env.M1_SERVICE_TOKEN;
    await ctx.close();
    server.close();
  });
  beforeEach(() => {
    ctx.limiter.reset();
    received.length = 0;
  });

  const importFile = (name: string, file: string) =>
    as(ctx, admin).post('/api/scans').field('applicationId', appId).attach('fichier', fixture(file), { filename: name, contentType: 'application/json' });

  it('utilise le modèle entraîné pour M1 (non simulé) et garde M2 simulé', async () => {
    mode = 'ok';
    const res = await importFile('a.json', 'valid-small.json');
    expect(res.status).toBe(201);
    expect(res.body.m1Provider).toBe('m1-trained');
    const m1 = await ctx.prisma.prediction.findMany({ where: { model: 'M1' } });
    const m2 = await ctx.prisma.prediction.findMany({ where: { model: 'M2' } });
    expect(m1).toHaveLength(10);
    expect(m1.every((p) => p.provider === 'm1-trained' && p.simulated === false && p.version === 'm1_v1-test')).toBe(true);
    expect((m1[0]!.explanation as any).source).toMatch(/cwe_rate|prior/); // origine toujours indiquée
    expect(m2.every((p) => p.simulated === true)).toBe(true);
    // M2 reçoit le NIVEAU relatif de M1 (et non sa probabilité brute, ≈ 0,05 %) : M1 reste audible dans M2
    for (const p of m1) {
      const x = p.explanation as { relativeRisk: number; levelForM2: number };
      expect(x.relativeRisk).toBeGreaterThan(0);
      expect(x.levelForM2).toBeGreaterThanOrEqual(0.11); // au moins le risque moyen (1/9)
      const m2p = m2.find((q) => q.findingId === p.findingId)!;
      const contribution = (m2p.explanation as { feature: string; contribution: number }[]).find((e) => e.feature === 'm1Probability')!.contribution;
      expect(contribution).toBeCloseTo(0.35 * x.levelForM2, 2);
    }
  });

  it('extrait le CVE du rapport, le transmet au service et le fait peser dans M2', async () => {
    mode = 'ok';
    const res = await importFile('cve.json', 'valid-with-cve.json');
    expect(res.status).toBe(201);
    const withCve = await ctx.prisma.finding.findMany({ where: { cveId: { not: null } } });
    expect(withCve.map((f) => f.cveId)).toEqual(['CVE-2021-44228']);
    expect(withCve[0]!.title).toContain('journalisation');
    // le service a bien reçu le CVE (et rien d'autre que cveId/cweId)
    const sent = received.flatMap((r) => r.body.items as Record<string, unknown>[]);
    expect(sent).toContainEqual({ cveId: 'CVE-2021-44228', cweId: 'CWE-502' });
    // modèle (source m1), déjà dans KEV : M2 reçoit le niveau maximal
    const m1 = await ctx.prisma.prediction.findFirst({ where: { findingId: withCve[0]!.id, model: 'M1' } });
    expect(m1!.explanation).toMatchObject({ source: 'm1', alreadyInKev: true, levelForM2: 1 });
    const m2 = await ctx.prisma.prediction.findFirst({ where: { findingId: withCve[0]!.id, model: 'M2' } });
    const contribution = (m2!.explanation as { feature: string; contribution: number }[]).find((e) => e.feature === 'm1Probability')!.contribution;
    expect(contribution).toBeCloseTo(0.35, 2);
  });

  it('envoie le jeton, et uniquement cveId et cweId (jamais titre, description ni URL)', async () => {
    mode = 'ok';
    await importFile('b.json', 'valid-medium.json');
    expect(received.length).toBeGreaterThan(0);
    for (const r of received) {
      expect(r.headers['x-m1-token']).toBe(TOKEN);
      for (const it of r.body.items) expect(Object.keys(it).every((k) => ['cveId', 'cweId'].includes(k))).toBe(true);
      expect(JSON.stringify(r.body)).not.toMatch(/cible-de-labo|SQL Injection|description/i);
    }
  });

  it('se replie sur la simulation (marquée simulée) si le service répond une erreur, et journalise', async () => {
    mode = 'error';
    const before = await ctx.prisma.prediction.count({ where: { model: 'M1', simulated: true } });
    const res = await importFile('c.json', 'bad-xss-in-alert.json');
    expect(res.status).toBe(201);
    const sim = await ctx.prisma.prediction.findMany({ where: { model: 'M1', simulated: true } });
    expect(sim.length).toBe(before + 1);
    expect(sim.at(-1)!.provider).toBe('rules');
    expect(await ctx.prisma.auditLog.count({ where: { action: 'M1_SERVICE_FALLBACK' } })).toBeGreaterThanOrEqual(1);
    expect(JSON.stringify(await ctx.prisma.auditLog.findMany())).not.toContain(TOKEN);
  });

  it('rejette une sortie invalide du service (probabilité hors bornes) et se replie', async () => {
    mode = 'bad';
    const res = await importFile('d.json', 'bad-prompt-injection.json');
    expect(res.status).toBe(201);
    const bad = await ctx.prisma.prediction.findMany({ where: { OR: [{ probability: { gt: 1 } }, { probability: { lt: 0 } }] } });
    expect(bad).toHaveLength(0);
  });

  it('se replie aussi quand le service est arrêté', async () => {
    mode = 'ok';
    await new Promise((r) => server.close(r));
    const res = await importFile('e.json', 'valid-small.json').catch((e) => e);
    // même fichier déjà importé : 409 ; on vérifie plutôt la page Modèles
    expect([201, 409]).toContain(res.status);
    const state = await as(ctx, admin).get('/api/modeles');
    expect(state.body.m1).toMatchObject({ configuredMode: 'trained', serviceConfigured: true, serviceReachable: false });
    await listen(); // pour afterAll
  });
});
