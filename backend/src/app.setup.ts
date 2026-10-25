import { ValidationPipe, type INestApplication } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import cookieParser from 'cookie-parser';
import express from 'express';
import helmet from 'helmet';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { Logger } from 'nestjs-pino';
import type { Env } from './config/env.js';

/** Configuration commune à l'application réelle et aux tests e2e (en-têtes, pipes, cookies, limites). */
export function configureApp(app: INestApplication, env: Env): void {
  const server = app as NestExpressApplication;
  const isProd = env.NODE_ENV === 'production';

  server.disable('x-powered-by');
  server.set('trust proxy', isProd ? 1 : false); // derrière le proxy TLS en production
  server.setGlobalPrefix('api');

  server.use(
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          // Angular injecte des styles en ligne (composants) : exception documentée dans docs/SECURITY.md.
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          fontSrc: ["'self'"],
          connectSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'self'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
        },
      },
      hsts: isProd ? { maxAge: 31_536_000, includeSubDomains: true } : false,
      referrerPolicy: { policy: 'no-referrer' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
    }),
  );
  server.use(cookieParser());
  server.useBodyParser('json', { limit: '1mb' });
  server.useBodyParser('urlencoded', { limit: '100kb', extended: false });

  // CORS : liste blanche explicite, jamais de « * » avec des identifiants.
  server.enableCors({
    origin: [env.APP_ORIGIN],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
    exposedHeaders: ['Content-Disposition', 'Retry-After'],
  });

  if (isProd) {
    server.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (req.secure || req.path === '/api/sante') return next();
      res.status(426).json({ statusCode: 426, message: 'HTTPS requis.' });
    });
  }

  server.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: { enableImplicitConversion: false },
      stopAtFirstError: true,
    }),
  );

  // Une seule origine en production : NestJS sert aussi le build Angular.
  if (env.FRONTEND_DIST && existsSync(env.FRONTEND_DIST)) {
    const dist = resolve(env.FRONTEND_DIST);
    server.use(express.static(dist, { index: false, maxAge: '1h' }));
    server.use((req: express.Request, res: express.Response, next: express.NextFunction) => {
      if (req.method !== 'GET' || req.path.startsWith('/api')) return next();
      res.sendFile(resolve(dist, 'index.html'));
    });
  }

  server.useLogger(server.get(Logger));
  server.enableShutdownHooks();
}
