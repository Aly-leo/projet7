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
  app.get(Logger).log(`API démarrée sur le port ${env.PORT} (préfixe /api, mode simulation M1/M2)`);
}

bootstrap().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
