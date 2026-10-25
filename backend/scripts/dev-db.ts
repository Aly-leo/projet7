/**
 * Base PostgreSQL locale de développement (binaires embarqués, aucune installation requise).
 * Alternative à Neon pour travailler hors ligne : `npm run dev:db`, puis utiliser l'URL affichée.
 * Les données sont conservées dans backend/.pgdata (ignoré par Git).
 */
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import EmbeddedPostgres from 'embedded-postgres';

const port = Number(process.env.DEV_DB_PORT ?? 54329);
const databaseDir = resolve(process.cwd(), '.pgdata');
const first = !existsSync(resolve(databaseDir, 'PG_VERSION'));

const pg = new EmbeddedPostgres({
  databaseDir,
  user: 'postgres',
  password: 'postgres',
  port,
  persistent: true,
  initdbFlags: ['--encoding=UTF8', '--locale=C'],
});

if (first) await pg.initialise();
await pg.start();
if (first) await pg.createDatabase('projet7');

const url = `postgresql://postgres:postgres@localhost:${port}/projet7`;
console.log(`\nPostgreSQL local prêt.\n  DATABASE_URL=${url}\n  DIRECT_URL=${url}\nCtrl+C pour arrêter.\n`);

const stop = async () => {
  await pg.stop();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
setInterval(() => undefined, 1 << 30);
