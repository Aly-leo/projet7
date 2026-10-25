import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { STRONG, as, createTestApp, login, type TestContext } from './helpers.js';

describe('Installation initiale', () => {
  let ctx: TestContext;
  beforeAll(async () => {
    ctx = await createTestApp();
  });
  afterAll(() => ctx.close());

  const body = (over: Record<string, unknown> = {}) => ({
    nom: 'Admin Test',
    courriel: 'admin@example.test',
    motDePasse: STRONG,
    ...over,
  });

  it('indique que l\'installation est requise sur une base vide', async () => {
    const res = await ctx.http().get('/api/installation/etat');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ installationRequise: true });
  });

  it("refuse un champ inconnu (400), dont l'ancien jeton d'installation", async () => {
    const res = await ctx.http().post('/api/installation').send(body({ jetonInstallation: 'x'.repeat(40) }));
    expect(res.status).toBe(400);
    expect(await ctx.prisma.user.count()).toBe(0);
  });

  it('refuse un mot de passe faible (400)', async () => {
    const res = await ctx.http().post('/api/installation').send(body({ motDePasse: 'motdepasse1234' }));
    expect(res.status).toBe(400);
    expect(await ctx.prisma.user.count()).toBe(0);
  });

  it('n\'accepte qu\'une seule création quand deux demandes arrivent en même temps', async () => {
    const [a, b] = await Promise.all([
      ctx.http().post('/api/installation').send(body({ courriel: 'a@example.test' })),
      ctx.http().post('/api/installation').send(body({ courriel: 'b@example.test' })),
    ]);
    expect([a.status, b.status].sort()).toEqual([201, 404]);
    expect(await ctx.prisma.user.count()).toBe(1);
    const user = await ctx.prisma.user.findFirstOrThrow();
    expect(user.role).toBe('ADMIN');
    expect(user.mustChangePassword).toBe(false);
    expect(await ctx.prisma.auditLog.count({ where: { action: 'SETUP_ADMIN_CREATED' } })).toBe(1);
  });

  it('se verrouille ensuite : état false et POST 404', async () => {
    ctx.limiter.reset();
    expect((await ctx.http().get('/api/installation/etat')).body).toEqual({ installationRequise: false });
    const res = await ctx.http().post('/api/installation').send(body({ courriel: 'c@example.test' }));
    expect(res.status).toBe(404);
  });

  it('ne crée pas de session automatique et limite les tentatives (429)', async () => {
    const res = await ctx.http().post('/api/installation').send(body());
    expect(res.headers['set-cookie']).toBeUndefined();
    for (let i = 0; i < 5; i++) await ctx.http().post('/api/installation').send(body());
    expect((await ctx.http().post('/api/installation').send(body())).status).toBe(429);
  });

  it('empêche la désactivation et la rétrogradation du dernier administrateur (409)', async () => {
    ctx.limiter.reset();
    const admin = await ctx.prisma.user.findFirstOrThrow();
    const session = await login(ctx, admin.email, STRONG);
    const r1 = await as(ctx, session).put(`/api/utilisateurs/${admin.id}`).send({ active: false });
    expect(r1.status).toBe(409);
    const r2 = await as(ctx, session).put(`/api/utilisateurs/${admin.id}`).send({ role: 'ANALYST' });
    expect(r2.status).toBe(409);
  });
});
