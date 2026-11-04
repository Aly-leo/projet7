import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';
import { AppModule } from './app.module.js';
import { configureApp } from './app.setup.js';
import { loadEnv } from './config/env.js';

async function bootstrap(): Promise<void> {
  const env = loadEnv(); // refuse de démarrer si la configuration est invalide
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });
  configureApp(app, env);
  await app.listen(env.PORT);
  app.get(Logger).log(`API démarrée sur le port ${env.PORT} (préfixe /api, M1 : ${env.M1_PROVIDER === 'trained' ? 'service entraîné' : 'estimation de repli'}, M2 : simulé)`);
}

bootstrap().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
