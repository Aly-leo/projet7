import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { as, createTestApp, createUserSession, fixture, installAdmin, type Session, type TestContext } from './helpers.js';

describe('Constats, corrections, tableau de bord et modèles', () => {
  let ctx: TestContext;
  let admin: Session;
  let analyst: Session;
  let decider: Session;
  let appId: string;
  let findingId: string;

  beforeAll(async () => {
    ctx = await createTestApp();
    admin = await installAdmin(ctx);
    analyst = await createUserSession(ctx, admin, 'ANALYST', 'analyste@example.test');
    decider = await createUserSession(ctx, admin, 'DECISION_MAKER', 'decideur@example.test');
    appId = (await as(ctx, admin).post('/api/applications').send({ name: 'Juice Shop (labo)', exposure: 'PUBLIC', sensitivity: 'HIGH' })).body.id;
    const imp = await as(ctx, analyst).post('/api/scans').field('applicationId', appId).attach('fichier', fixture('valid-small.json'), { filename: 'r.json', contentType: 'application/json' });
    expect(imp.status).toBe(201);
  });
  afterAll(() => ctx.close());
  beforeEach(() => ctx.limiter.reset());

  it('liste les constats triés par priorité, avec filtres et pagination bornée', async () => {
    const res = await as(ctx, analyst).get('/api/constats?pageSize=100');
    expect(res.status).toBe(200);
    expect(res.body.simulated).toBe(true);
    expect(res.body.total).toBe(10);
    const order = res.body.items.map((i: any) => i.priority);
    expect([...order].sort()).toEqual(order); // P1 avant P4
    findingId = res.body.items[0].id;

    expect((await as(ctx, analyst).get('/api/constats?pageSize=101')).status).toBe(400);
    const sql = await as(ctx, analyst).get(`/api/constats?q=${encodeURIComponent("' OR 1=1 --")}`);
    expect(sql.status).toBe(200);
    expect(sql.body.total).toBe(0);
    const cwe = await as(ctx, analyst).get('/api/constats?q=89');
    expect(cwe.body.items.some((i: any) => i.cweId === 89)).toBe(true);
  });

  it('affiche le détail avec prédictions simulées et journalise la consultation', async () => {
    const res = await as(ctx, analyst).get(`/api/constats/${findingId}`);
    expect(res.status).toBe(200);
    expect(res.body.predictions.m1.simulated).toBe(true);
    expect(res.body.predictions.m2.explanation.length).toBeGreaterThan(0);
    for (const e of res.body.predictions.m2.explanation) expect(Math.abs(e.contribution)).toBeLessThanOrEqual(1);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'FINDING_VIEW', resourceId: findingId } })).toBe(1);
  });

  it('enregistre une annotation d\'expert qui devient la priorité effective', async () => {
    const res = await as(ctx, analyst).put(`/api/constats/${findingId}/priorite`).send({ priority: 'P4', comment: 'Faux risque.' });
    expect(res.status).toBe(200);
    const detail = await as(ctx, analyst).get(`/api/constats/${findingId}`);
    expect(detail.body.priority).toBe('P4');
    expect(detail.body.annotations[0].comment).toBe('Faux risque.');
    expect((await as(ctx, analyst).put(`/api/constats/${findingId}/priorite`).send({ priority: 'P9' })).status).toBe(400);
  });

  it('applique la machine à états : transitions valides, invalides (409)', async () => {
    const put = (body: object) => as(ctx, analyst).put(`/api/constats/${findingId}/correction`).send(body);
    // PRIORITIZED → CLOSED : interdit
    const bad = await put({ status: 'CLOSED' });
    expect(bad.status).toBe(409);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'FINDING_STATUS_CHANGE', outcome: 'DENIED' } })).toBe(1);
    // ASSIGNED sans assigné : refusé
    expect((await put({ status: 'ASSIGNED' })).status).toBe(400);
    // Chemin nominal
    expect((await put({ status: 'ASSIGNED', assigneeId: analyst.user.id, dueDate: '2027-01-31T00:00:00.000Z' })).status).toBe(200);
    expect((await put({ status: 'REMEDIATED' })).status).toBe(409);
    for (const s of ['IN_REMEDIATION', 'REMEDIATED', 'VERIFIED']) expect((await put({ status: s })).status).toBe(200);
    expect((await put({ status: 'IN_REMEDIATION' })).status).toBe(200); // échec de vérification
    for (const s of ['REMEDIATED', 'VERIFIED', 'CLOSED']) expect((await put({ status: s })).status).toBe(200);
    expect((await put({ status: 'IN_REMEDIATION' })).status).toBe(409); // CLOSED est final
  });

  it('refuse d\'assigner un décideur', async () => {
    const other = (await as(ctx, analyst).get('/api/constats?pageSize=5')).body.items[1].id;
    const res = await as(ctx, analyst).put(`/api/constats/${other}/correction`).send({ status: 'ASSIGNED', assigneeId: decider.user.id });
    expect(res.status).toBe(400);
  });

  it('ne donne au décideur que des données agrégées', async () => {
    const res = await as(ctx, decider).get('/api/tableaux-de-bord');
    expect(res.status).toBe(200);
    expect(res.body.totals.findings).toBe(10);
    expect(res.body.topFindings).toBeUndefined();
    const text = JSON.stringify(res.body);
    expect(text).not.toMatch(/SQL Injection|Cross Site|cible-de-labo/);
    expect(res.body.byApplication[0]).toMatchObject({ name: 'Juice Shop (labo)', total: 10 });

    const analystView = await as(ctx, analyst).get('/api/tableaux-de-bord');
    expect(analystView.body.topFindings.length).toBeGreaterThan(0);
  });

  it('refuse au décideur toute route de détail', async () => {
    for (const path of ['/api/constats', `/api/constats/${findingId}`, '/api/scans', '/api/applications']) {
      expect((await as(ctx, decider).get(path)).status).toBe(403);
    }
    expect(await ctx.prisma.auditLog.count({ where: { action: 'ACCESS_DENIED', outcome: 'DENIED' } })).toBeGreaterThanOrEqual(4);
  });

  it('expose l\'état des modèles sans aucune métrique, et relance les prédictions simulées (admin)', async () => {
    const state = await as(ctx, admin).get('/api/modeles');
    expect(state.status).toBe(200);
    expect(state.body).toMatchObject({ mode: 'SIMULATION', metrics: null, activeProvider: 'rules' });
    expect((await as(ctx, analyst).get('/api/modeles')).status).toBe(403);
    const before = await ctx.prisma.prediction.count();
    const rerun = await as(ctx, admin).post('/api/modeles/entrainement');
    expect(rerun.status).toBe(200);
    expect(rerun.body.simulated).toBe(true);
    expect(await ctx.prisma.prediction.count()).toBe(before + 20);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'MODEL_RERUN', outcome: 'SUCCESS' } })).toBeGreaterThanOrEqual(1);
    // L'annotation de l'expert reste prioritaire après une relance.
    const detail = await as(ctx, analyst).get(`/api/constats/${findingId}`);
    expect(detail.body.priority).toBe('P4');
  });

  it('gère les applications (admin) : nom unique, suppression refusée si des imports existent', async () => {
    const dup = await as(ctx, admin).post('/api/applications').send({ name: 'Juice Shop (labo)', exposure: 'PUBLIC', sensitivity: 'LOW' });
    expect(dup.status).toBe(409);
    expect((await as(ctx, analyst).post('/api/applications').send({ name: 'Autre app', exposure: 'PUBLIC', sensitivity: 'LOW' })).status).toBe(403);
    expect((await as(ctx, admin).delete(`/api/applications/${appId}`)).status).toBe(409);
    const created = await as(ctx, admin).post('/api/applications').send({ name: 'Éphémère', exposure: 'INTERNAL', sensitivity: 'LOW' });
    expect((await as(ctx, admin).put(`/api/applications/${created.body.id}`).send({ sensitivity: 'MEDIUM' })).body.sensitivity).toBe('MEDIUM');
    expect((await as(ctx, admin).delete(`/api/applications/${created.body.id}`)).status).toBe(204);
  });

  it('autorise l\'administrateur seul à lire le journal d\'audit', async () => {
    const res = await as(ctx, admin).get('/api/audit?pageSize=10');
    expect(res.status).toBe(200);
    expect(res.body.items.length).toBeGreaterThan(0);
    expect((await as(ctx, analyst).get('/api/audit')).status).toBe(403);
    expect((await as(ctx, decider).get('/api/audit')).status).toBe(403);
  });
});
