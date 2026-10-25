/**
 * Seed idempotent.
 *  - Aucun administrateur par défaut : la page d'installation crée le premier compte.
 *  - SEED_ADMIN_EMAIL + SEED_ADMIN_PASSWORD (CI et tests uniquement) créent un administrateur s'il n'y en a aucun.
 *  - SEED_DEMO=true crée seulement les deux applications de laboratoire.
 */
import { existsSync } from 'node:fs';
import { PrismaPg } from '@prisma/adapter-pg';
import * as argon2 from 'argon2';
import { PrismaClient } from '../src/generated/prisma/client.js';

for (const file of ['.env', '../.env']) {
  if (existsSync(file)) {
    process.loadEnvFile(file);
    break;
  }
}

const url = process.env.DATABASE_URL;
if (!url) throw new Error('DATABASE_URL est obligatoire');
const prisma = new PrismaClient({ adapter: new PrismaPg({ connectionString: url }) });

async function main(): Promise<void> {
  const email = process.env.SEED_ADMIN_EMAIL?.trim().toLowerCase();
  const password = process.env.SEED_ADMIN_PASSWORD;
  if (email && password) {
    if ((await prisma.user.count()) === 0) {
      await prisma.user.create({
        data: {
          email,
          name: 'Administrateur (seed)',
          role: 'ADMIN',
          passwordHash: await argon2.hash(password, { type: argon2.argon2id, memoryCost: 46_080, timeCost: 3, parallelism: 1 }),
          mustChangePassword: false,
        },
      });
      console.log('Administrateur créé depuis SEED_ADMIN_*.');
    } else console.log('Des utilisateurs existent déjà : administrateur non créé.');
  }

  if (process.env.SEED_DEMO === 'true') {
    const apps = [
      { name: 'Juice Shop (labo)', description: 'Application de laboratoire OWASP Juice Shop (cible autorisée).', exposure: 'PUBLIC', sensitivity: 'HIGH' },
      { name: 'Portail interne (labo)', description: 'Application interne de démonstration.', exposure: 'INTERNAL', sensitivity: 'MEDIUM' },
    ] as const;
    for (const a of apps) {
      await prisma.application.upsert({ where: { name: a.name }, update: {}, create: { ...a } });
    }
    console.log('Applications de laboratoire prêtes.');
  }
}

main()
  .catch((e) => {
    console.error(e);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
