import { resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { Client } from 'pg';

const DEFAULT_URL = 'postgresql://postgres:postgres@localhost:54330/postgres';

async function reachable(url: string): Promise<boolean> {
  const c = new Client({ connectionString: url, connectionTimeoutMillis: 1500 });
  try {
    await c.connect();
    await c.end();
    return true;
  } catch {
    return false;
  }
}

/**
 * Fournit un serveur PostgreSQL aux tests e2e : TEST_ADMIN_URL (CI, Neon de test) ou, à défaut,
 * un PostgreSQL embarqué éphémère. Chaque fichier de test crée sa propre base.
 */
export default async function setup(): Promise<(() => Promise<void>) | void> {
  const configured = process.env.TEST_ADMIN_URL;
  if (configured) {
    process.env.TEST_ADMIN_URL = configured;
    return;
  }
  if (await reachable(DEFAULT_URL)) {
    process.env.TEST_ADMIN_URL = DEFAULT_URL;
    return;
  }
  const { default: EmbeddedPostgres } = await import('embedded-postgres');
  const databaseDir = resolve(process.cwd(), '.pgdata-test');
  const pg = new EmbeddedPostgres({
    databaseDir,
    user: 'postgres',
    password: 'postgres',
    port: 54330,
    persistent: false,
    initdbFlags: ['--encoding=UTF8', '--locale=C'],
  });
  if (!existsSync(resolve(databaseDir, 'PG_VERSION'))) await pg.initialise();
  await pg.start();
  process.env.TEST_ADMIN_URL = DEFAULT_URL;
  return async () => {
    await pg.stop();
  };
}
