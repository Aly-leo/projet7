import { existsSync } from 'node:fs';
import { defineConfig } from 'prisma/config';

// Prisma 7 ne charge plus automatiquement le fichier .env.
for (const file of ['.env', '../.env']) {
  if (existsSync(file)) {
    process.loadEnvFile(file);
    break;
  }
}

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    seed: 'tsx prisma/seed.ts',
  },
  datasource: {
    // Connexion directe (sans pooler) pour les migrations ; repli sur DATABASE_URL.
    url: process.env.DIRECT_URL || process.env.DATABASE_URL || '',
  },
});
