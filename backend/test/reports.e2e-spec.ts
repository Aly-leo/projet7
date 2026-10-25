import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { extractText, getDocumentProxy } from 'unpdf';
import { as, createTestApp, createUserSession, fixture, installAdmin, type Session, type TestContext } from './helpers.js';

const binary = (res: any) => res.buffer ?? res.body;

async function pdfText(buf: Buffer): Promise<string> {
  const pdf = await getDocumentProxy(new Uint8Array(buf));
  const { text } = await extractText(pdf, { mergePages: true });
  return text;
}

describe('Rapports PDF', () => {
  let ctx: TestContext;
  let admin: Session;
  let analyst: Session;
  let decider: Session;
  let appId: string;
  let scanId: string;

  const get = (s: Session, path: string) =>
    as(ctx, s).get(path).buffer(true).parse((res, cb) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => cb(null, Buffer.concat(chunks)));
    });

  beforeAll(async () => {
    ctx = await createTestApp();
    admin = await installAdmin(ctx);
    analyst = await createUserSession(ctx, admin, 'ANALYST', 'analyste@example.test');
    decider = await createUserSession(ctx, admin, 'DECISION_MAKER', 'decideur@example.test');
    appId = (await as(ctx, admin).post('/api/applications').send({ name: 'Juice Shop (labo)', exposure: 'PUBLIC', sensitivity: 'HIGH' })).body.id;
    const imp = await as(ctx, analyst).post('/api/scans').field('applicationId', appId).attach('fichier', fixture('valid-small.json'), { filename: 'r.json', contentType: 'application/json' });
    scanId = imp.body.scanId;
    await as(ctx, analyst).post('/api/scans').field('applicationId', appId).attach('fichier', fixture('bad-xss-in-alert.json'), { filename: 'x.json', contentType: 'application/json' });
  });
  afterAll(() => ctx.close());
  beforeEach(() => ctx.limiter.reset());

  it('génère le rapport d\'import avec mention « Prédictions simulées », date et auteur', async () => {
    const res = await get(analyst, `/api/rapports/scans/${scanId}/pdf`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toBe('application/pdf');
    expect(res.headers['content-disposition']).toMatch(/^attachment; filename="rapport-import-\d{4}-\d{2}-\d{2}\.pdf"$/);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['cache-control']).toBe('no-store');
    const buf = binary(res) as Buffer;
    expect(buf.subarray(0, 5).toString()).toBe('%PDF-');
    const text = await pdfText(buf);
    expect(text).toContain('Prédictions simulées');
    expect(text).toContain('Utilisateur ANALYST');
    expect(text).toContain('SQL Injection');
    expect(text).toMatch(/page 1\/\d+/);
  });

  it('génère le rapport d\'application et accepte les filtres', async () => {
    const res = await get(admin, `/api/rapports/applications/${appId}/pdf?priorites=P1,P2&inclureDetails=false`);
    expect(res.status).toBe(200);
    expect(await pdfText(binary(res))).toContain('Juice Shop (labo)');
    expect((await get(admin, `/api/rapports/applications/${appId}/pdf?priorites=P9`)).status).toBe(400);
    expect((await get(admin, `/api/rapports/applications/${appId}/pdf?inconnu=1`)).status).toBe(400);
    expect((await get(admin, '/api/rapports/applications/00000000-0000-4000-8000-000000000000/pdf')).status).toBe(404);
  });

  it('ne contient ni JavaScript, ni pièce jointe, ni formulaire, ni lien actif', async () => {
    const res = await get(analyst, `/api/rapports/applications/${appId}/pdf`);
    const raw = binary(res).toString('latin1');
    for (const marker of ['/JavaScript', '/JS ', '/EmbeddedFile', '/AcroForm', '/URI', '/Launch', '/OpenAction', '/Annots']) {
      expect(raw).not.toContain(marker);
    }
  });

  it('rend le contenu malveillant comme texte inerte', async () => {
    const res = await get(analyst, `/api/rapports/applications/${appId}/pdf`);
    const text = await pdfText(binary(res));
    expect(text).toContain('Titre piégé');
    expect(text).not.toMatch(/<script|onerror|javascript:/i);
  });

  it('limite la synthèse du décideur à des données agrégées (aucun titre, URL ni identifiant)', async () => {
    const res = await get(decider, '/api/rapports/synthese/pdf');
    expect(res.status).toBe(200);
    const text = await pdfText(binary(res));
    expect(text).toContain('Juice Shop (labo)');
    expect(text).toContain('Prédictions simulées');
    expect(text).not.toMatch(/SQL Injection|Cross Site|Content Security|cible-de-labo|http:\/\//);
    const ids = await ctx.prisma.finding.findMany({ select: { id: true } });
    for (const { id } of ids) expect(text).not.toContain(id);
    expect((await get(decider, `/api/rapports/applications/${appId}/pdf`)).status).toBe(403);
    expect((await get(decider, `/api/rapports/scans/${scanId}/pdf`)).status).toBe(403);
  });

  it('refuse sans session (401) et journalise exports et refus', async () => {
    expect((await ctx.http().get('/api/rapports/synthese/pdf')).status).toBe(401);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'REPORT_EXPORT', outcome: 'SUCCESS' } })).toBeGreaterThanOrEqual(4);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'REPORT_EXPORT', outcome: 'DENIED' } })).toBeGreaterThanOrEqual(2);
  });

  it('refuse (422) un rapport au-delà du plafond de constats', async () => {
    const small = await createTestApp({ env: { REPORT_MAX_FINDINGS: String(2) } });
    try {
      const a = await installAdmin(small);
      const app = await as(small, a).post('/api/applications').send({ name: 'Petite app', exposure: 'PUBLIC', sensitivity: 'LOW' });
      await as(small, a).post('/api/scans').field('applicationId', app.body.id).attach('fichier', fixture('valid-small.json'), { filename: 'r.json', contentType: 'application/json' });
      const res = await as(small, a).get(`/api/rapports/applications/${app.body.id}/pdf`);
      expect(res.status).toBe(422);
      expect(res.body.message).toMatch(/filtrez/i);
    } finally {
      process.env.REPORT_MAX_FINDINGS = '500';
      await small.close();
    }
  });

  it('limite à 20 exports par heure (429)', async () => {
    let last = 0;
    for (let i = 0; i < 21; i++) last = (await get(admin, '/api/rapports/synthese/pdf')).status;
    expect(last).toBe(429);
  });
});
