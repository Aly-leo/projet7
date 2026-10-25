import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createTestApp, createUserSession, fixture, installAdmin, type Session, type TestContext } from './helpers.js';

describe('Import des rapports ZAP', () => {
  let ctx: TestContext;
  let admin: Session;
  let analyst: Session;
  let decider: Session;
  let appId: string;

  beforeAll(async () => {
    ctx = await createTestApp();
    admin = await installAdmin(ctx);
    analyst = await createUserSession(ctx, admin, 'ANALYST', 'analyste@example.test');
    decider = await createUserSession(ctx, admin, 'DECISION_MAKER', 'decideur@example.test');
    const app = await as(ctx, admin).post('/api/applications').send({ name: 'Juice Shop (labo)', exposure: 'PUBLIC', sensitivity: 'HIGH' });
    expect(app.status).toBe(201);
    appId = app.body.id;
  });
  afterAll(() => ctx.close());
  beforeEach(() => ctx.limiter.reset());

  const upload = (s: Session, file: Buffer, name = 'rapport.json', mime = 'application/json', application = appId) =>
    as(ctx, s).post('/api/scans').field('applicationId', application).attach('fichier', file, { filename: name, contentType: mime });

  const lastAudit = (outcome?: string) =>
    ctx.prisma.auditLog.findFirst({ where: { action: 'SCAN_IMPORT', ...(outcome && { outcome: outcome as any }) }, orderBy: { createdAt: 'desc' } });

  it('importe valid-small.json : constats, prédictions M1/M2 simulées et audit SUCCESS', async () => {
    const res = await upload(analyst, fixture('valid-small.json'));
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ findingsTotal: 10, findingsNew: 10, findingsUpdated: 0, simulated: true, provider: 'rules' });
    expect(Object.values(res.body.byPriority).reduce((a: number, b: any) => a + b, 0)).toBe(10);

    const preds = await ctx.prisma.prediction.findMany();
    expect(preds).toHaveLength(20);
    expect(preds.every((p) => p.simulated && p.provider === 'rules')).toBe(true);
    const statuses = await ctx.prisma.correction.groupBy({ by: ['status'], _count: true });
    expect(statuses).toEqual([expect.objectContaining({ status: 'PRIORITIZED' })]);

    const log = await lastAudit('SUCCESS');
    expect(log?.metadata).toMatchObject({ findingsNew: 10, fileName: 'rapport.json' });
    expect(JSON.stringify(log?.metadata)).not.toContain('SQL Injection'); // jamais de contenu de rapport
  });

  it('refuse le réimport du même fichier (409)', async () => {
    const res = await upload(analyst, fixture('valid-small.json'));
    expect(res.status).toBe(409);
    expect((await lastAudit('FAILURE'))?.metadata).toMatchObject({ status: 409 });
  });

  it('dédoublonne : un second rapport met à jour les constats connus', async () => {
    const res = await upload(analyst, fixture('valid-medium.json'), 'medium.json');
    expect(res.status).toBe(201);
    expect(res.body.findingsNew + res.body.findingsUpdated).toBe(res.body.findingsTotal);
    expect(res.body.findingsUpdated).toBeGreaterThan(0);
    const distinct = await ctx.prisma.finding.groupBy({ by: ['fingerprint'] });
    expect(distinct.length).toBe(await ctx.prisma.finding.count());
  });

  it('refuse le décideur (403 journalisé) et l\'absence de session (401)', async () => {
    const res = await upload(decider, fixture('valid-small.json'), 'autre.json');
    expect(res.status).toBe(403);
    expect((await lastAudit('DENIED'))?.outcome).toBe('DENIED');
    const anon = await ctx.http().post('/api/scans').field('applicationId', appId).attach('fichier', fixture('valid-small.json'), { filename: 'a.json', contentType: 'application/json' });
    expect(anon.status).toBe(401);
  });

  const bad: [string, string, string, string, number][] = [
    ['JSON invalide', 'bad-not-json.txt', 'rapport.json', 'application/json', 415], // ne commence pas par {
    ['mauvais type MIME', 'valid-small.json', 'rapport.json', 'text/plain', 415],
    ['mauvaise extension', 'valid-small.json', 'rapport.xml', 'application/json', 415],
    ['pollution de prototype', 'bad-proto-pollution.json', 'p.json', 'application/json', 400],
    ['imbrication excessive', 'bad-deep-nesting.json', 'd.json', 'application/json', 422],
    ['schéma invalide', 'bad-schema.json', 's.json', 'application/json', 422],
  ];
  for (const [label, file, name, mime, status] of bad) {
    it(`refuse : ${label} (${status}) avec audit FAILURE et sans erreur 500`, async () => {
      const before = await ctx.prisma.auditLog.count({ where: { action: 'SCAN_IMPORT', outcome: 'FAILURE' } });
      const res = await upload(analyst, fixture(file), name, mime);
      expect(res.status).toBe(status);
      expect(res.body.message).toBeTruthy();
      expect(JSON.stringify(res.body)).not.toMatch(/at .*\.(ts|js):\d+/); // pas de trace de pile
      expect(await ctx.prisma.auditLog.count({ where: { action: 'SCAN_IMPORT', outcome: 'FAILURE' } })).toBe(before + 1);
    });
  }

  it('refuse un JSON mal formé mais commençant par { (400)', async () => {
    const res = await upload(analyst, Buffer.from('{"site": [ {"alerts": ] '));
    expect(res.status).toBe(400);
  });

  it('refuse un fichier trop gros (413, audit FAILURE)', async () => {
    const big = Buffer.from(`{"site":[],"pad":"${'a'.repeat(1.2 * 1024 * 1024)}"}`);
    const res = await upload(analyst, big, 'gros.json');
    expect(res.status).toBe(413);
    expect((await lastAudit('FAILURE'))?.metadata).toMatchObject({ status: 413 });
  });

  it('refuse un rapport dépassant le plafond d\'alertes (422)', async () => {
    const alerts = Array.from({ length: 5001 }, (_, i) => ({ pluginid: String(i), alert: `A${i}`, riskcode: '1' }));
    const res = await upload(analyst, Buffer.from(JSON.stringify({ site: [{ alerts }] })), 'beaucoup.json');
    expect([413, 422]).toContain(res.status);
  });

  it('neutralise le HTML : titres et descriptions stockés en texte brut', async () => {
    const res = await upload(analyst, fixture('bad-xss-in-alert.json'), 'xss.json');
    expect(res.status).toBe(201);
    const f = await ctx.prisma.finding.findFirstOrThrow({ where: { title: { contains: 'Titre piégé' } } });
    expect(f.title).not.toMatch(/<script|<img/i);
    expect(f.description).not.toMatch(/<script|<img|<a /i);
    expect(JSON.stringify(f.sampleUrls)).not.toMatch(/<img/i);
  });

  it('traite le contenu de prompt-injection comme une donnée inerte', async () => {
    const res = await upload(analyst, fixture('bad-prompt-injection.json'), 'inj.json');
    expect(res.status).toBe(201);
    const preds = await ctx.prisma.prediction.findMany({ where: { finding: { title: { contains: 'Ignore les instructions' } } } });
    expect(preds.length).toBeGreaterThan(0);
    for (const p of preds) {
      expect(p.probability).toBeGreaterThanOrEqual(0);
      expect(p.probability).toBeLessThanOrEqual(1);
      if (p.priority) expect(['P1', 'P2', 'P3', 'P4']).toContain(p.priority);
    }
  });

  it('refuse une application inexistante (404) et un identifiant invalide (400)', async () => {
    expect((await upload(analyst, fixture('valid-small.json'), 'x.json', 'application/json', '00000000-0000-4000-8000-000000000000')).status).toBe(404);
    expect((await upload(analyst, fixture('valid-small.json'), 'x.json', 'application/json', 'pas-un-uuid')).status).toBe(400);
  });

  it('limite les imports à 10 par heure et par utilisateur (429)', async () => {
    ctx.limiter.reset();
    let last = 0;
    for (let i = 0; i < 11; i++) last = (await upload(analyst, Buffer.from(`{"site":[],"n":${i}}`), `n${i}.json`)).status;
    expect(last).toBe(429);
  });
});
