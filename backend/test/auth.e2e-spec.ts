import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Client } from 'pg';
import { ORIGIN, STRONG, as, createTestApp, createUserSession, installAdmin, login, type Session, type TestContext } from './helpers.js';

describe('Authentification et sessions', () => {
  let ctx: TestContext;
  let admin: Session;
  beforeAll(async () => {
    ctx = await createTestApp();
    admin = await installAdmin(ctx);
  });
  afterAll(() => ctx.close());
  beforeEach(() => ctx.limiter.reset());

  const attempt = (courriel: string, motDePasse: string) =>
    ctx.http().post('/api/auth/connexion').set('Origin', ORIGIN).send({ courriel, motDePasse });

  it('pose des cookies HttpOnly SameSite=Strict et ne renvoie aucun jeton dans le corps', async () => {
    const res = await attempt('admin@example.test', STRONG);
    expect(res.status).toBe(200);
    const cookies = res.headers['set-cookie'] as unknown as string[];
    const access = cookies.find((c) => c.startsWith('access_token='))!;
    const refresh = cookies.find((c) => c.startsWith('refresh_token='))!;
    for (const c of [access, refresh]) {
      expect(c).toMatch(/HttpOnly/i);
      expect(c).toMatch(/SameSite=Strict/i);
    }
    expect(JSON.stringify(res.body)).not.toMatch(/token/i);
    expect(res.body.user.role).toBe('ADMIN');
  });

  it('renvoie le même message pour un courriel inconnu et un mauvais mot de passe', async () => {
    const a = await attempt('inconnu@example.test', 'Nimporte-Quoi-123!');
    const b = await attempt('admin@example.test', 'Mauvais-Mot-De-Passe-1!');
    expect(a.status).toBe(401);
    expect(b.status).toBe(401);
    expect(a.body.message).toBe(b.body.message);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'AUTH_LOGIN', outcome: 'FAILURE' } })).toBeGreaterThanOrEqual(2);
  });

  it('verrouille le compte après 5 échecs, même avec le bon mot de passe', async () => {
    const analyst = await createUserSession(ctx, admin, 'ANALYST', 'lock@example.test');
    expect(analyst.user.role).toBe('ANALYST');
    for (let i = 0; i < 5; i++) {
      ctx.limiter.reset(); // isole le verrouillage en base du limiteur de débit
      expect((await attempt('lock@example.test', 'Mauvais-Mot-De-Passe-1!')).status).toBe(401);
    }
    ctx.limiter.reset();
    const locked = await attempt('lock@example.test', STRONG);
    expect(locked.status).toBe(401);
    const user = await ctx.prisma.user.findUniqueOrThrow({ where: { email: 'lock@example.test' } });
    expect(user.lockedUntil!.getTime()).toBeGreaterThan(Date.now());
  });

  it('limite le débit de connexion par couple IP + courriel (429)', async () => {
    let last = 0;
    for (let i = 0; i < 7; i++) last = (await attempt('rate@example.test', 'Mauvais-Mot-De-Passe-1!')).status;
    expect(last).toBe(429);
  });

  it('fait tourner le jeton de rafraîchissement et détecte sa réutilisation', async () => {
    const first = await ctx.http().post('/api/auth/connexion').set('Origin', ORIGIN).send({ courriel: 'admin@example.test', motDePasse: STRONG });
    const cookies1 = (first.headers['set-cookie'] as unknown as string[]).map((c) => c.split(';')[0]!);
    const csrf1 = cookies1.find((c) => c.startsWith('csrf_token='))!.split('=')[1]!;

    const second = await ctx.http().post('/api/auth/rafraichir').set('Origin', ORIGIN).set('Cookie', cookies1).set('X-CSRF-Token', csrf1);
    expect(second.status).toBe(200);
    const cookies2 = (second.headers['set-cookie'] as unknown as string[]).map((c) => c.split(';')[0]!);
    expect(cookies2.find((c) => c.startsWith('refresh_token='))).not.toBe(cookies1.find((c) => c.startsWith('refresh_token=')));

    // Réutilisation de l'ancien jeton : refus, puis révocation de toute la famille.
    const reuse = await ctx.http().post('/api/auth/rafraichir').set('Origin', ORIGIN).set('Cookie', cookies1).set('X-CSRF-Token', csrf1);
    expect(reuse.status).toBe(401);
    const afterReuse = await ctx.http().post('/api/auth/rafraichir').set('Origin', ORIGIN).set('Cookie', cookies2).set('X-CSRF-Token', csrf1);
    expect(afterReuse.status).toBe(401);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'AUTH_REFRESH_REUSE' } })).toBeGreaterThanOrEqual(1);
  });

  it('révoque la session à la déconnexion', async () => {
    const s = await login(ctx, 'admin@example.test', STRONG);
    const out = await as(ctx, s).post('/api/auth/deconnexion');
    expect(out.status).toBe(204);
    const refreshed = await ctx.http().post('/api/auth/rafraichir').set('Origin', ORIGIN).set('Cookie', s.cookies).set('X-CSRF-Token', s.csrf);
    expect(refreshed.status).toBe(401);
  });

  it('refuse une requête qui modifie des données sans jeton CSRF ou depuis une autre origine (403)', async () => {
    const s = await login(ctx, 'admin@example.test', STRONG);
    const noCsrf = await ctx.http().post('/api/utilisateurs').set('Cookie', s.cookies).set('Origin', ORIGIN).send({ email: 'x@example.test', name: 'X Test', role: 'ANALYST' });
    expect(noCsrf.status).toBe(403);
    const badOrigin = await ctx.http().post('/api/utilisateurs').set('Cookie', s.cookies).set('X-CSRF-Token', s.csrf).set('Origin', 'https://evil.example').send({ email: 'x@example.test', name: 'X Test', role: 'ANALYST' });
    expect(badOrigin.status).toBe(403);
  });

  it('impose le changement de mot de passe temporaire, puis applique la politique', async () => {
    const created = await as(ctx, admin).post('/api/utilisateurs').send({ email: 'temp@example.test', name: 'Temp User', role: 'DECISION_MAKER' });
    expect(created.status).toBe(201);
    const temp = created.body.temporaryPassword as string;
    const s = await login(ctx, 'temp@example.test', temp);
    expect((await as(ctx, s).get('/api/tableaux-de-bord')).status).toBe(403); // changement obligatoire
    expect((await as(ctx, s).get('/api/auth/moi')).status).toBe(200);
    const weak = await as(ctx, s).post('/api/auth/changer-mot-de-passe').send({ motDePasseActuel: temp, nouveauMotDePasse: 'azertyuiop12' });
    expect(weak.status).toBe(400);
    const ok = await as(ctx, s).post('/api/auth/changer-mot-de-passe').send({ motDePasseActuel: temp, nouveauMotDePasse: STRONG });
    expect(ok.status).toBe(200);
    // L'ancienne session est invalidée par le changement de mot de passe (tokenVersion).
    expect((await as(ctx, s).get('/api/auth/moi')).status).toBe(401);
  });

  it('invalide immédiatement la session d\'un compte désactivé', async () => {
    const s = await createUserSession(ctx, admin, 'ANALYST', 'off@example.test');
    expect((await as(ctx, s).get('/api/applications')).status).toBe(200);
    const res = await as(ctx, admin).put(`/api/utilisateurs/${s.user.id}`).send({ active: false });
    expect(res.status).toBe(200);
    expect((await as(ctx, s).get('/api/applications')).status).toBe(401);
    expect((await attempt('off@example.test', STRONG)).status).toBe(401);
  });

  it('refuse l\'assignation de masse (champs non prévus) et les courriels en double', async () => {
    const mass = await as(ctx, admin).post('/api/utilisateurs').send({ email: 'm@example.test', name: 'Mass Test', role: 'ANALYST', passwordHash: 'x' });
    expect(mass.status).toBe(400);
    const dup = await as(ctx, admin).post('/api/utilisateurs').send({ email: 'admin@example.test', name: 'Doublon', role: 'ANALYST' });
    expect(dup.status).toBe(409);
  });

  it('rend le journal d\'audit immuable (UPDATE, DELETE et TRUNCATE refusés par la base)', async () => {
    const c = new Client({ connectionString: process.env.DATABASE_URL });
    await c.connect();
    await expect(c.query(`UPDATE "AuditLog" SET action = 'X'`)).rejects.toThrow(/ajout seul/);
    await expect(c.query(`DELETE FROM "AuditLog"`)).rejects.toThrow(/ajout seul/);
    await expect(c.query(`TRUNCATE "AuditLog"`)).rejects.toThrow(/ajout seul/);
    await c.end();
  });

  it('journalise connexions, changements de mot de passe et gestion des utilisateurs, sans secret', async () => {
    const actions = (await ctx.prisma.auditLog.findMany({ select: { action: true } })).map((a) => a.action);
    for (const a of ['AUTH_LOGIN', 'AUTH_LOGOUT', 'AUTH_PASSWORD_CHANGE', 'USER_CREATE', 'USER_UPDATE', 'SETUP_ADMIN_CREATED']) {
      expect(actions).toContain(a);
    }
    const dump = JSON.stringify(await ctx.prisma.auditLog.findMany());
    expect(dump).not.toContain(STRONG);
  });
});
