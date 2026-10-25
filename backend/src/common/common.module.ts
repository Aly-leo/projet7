import { Global, Module } from '@nestjs/common';
import { APP_FILTER, APP_GUARD } from '@nestjs/core';
import { JwtModule } from '@nestjs/jwt';
import { ENV, loadEnv, type Env } from '../config/env.js';
import { AllExceptionsFilter } from './all-exceptions.filter.js';
import { AuthGuard, CsrfGuard, IpRateLimitGuard, RolesGuard, RouteRateLimitGuard } from './guards.js';
import { RateLimiterService } from './rate-limiter.service.js';

/**
 * Socle de sécurité : configuration validée, limiteur de débit, JWT et gardes globales.
 * L'ordre des gardes est significatif : débit IP, CSRF, authentification, rôles (refus par défaut),
 * puis limites propres à la route.
 */
@Global()
@Module({
  imports: [
    JwtModule.registerAsync({
      global: true,
      inject: [ENV],
      useFactory: (env: Env) => ({
        secret: env.JWT_ACCESS_SECRET,
        signOptions: { algorithm: 'HS256' as const },
        verifyOptions: { algorithms: ['HS256' as const] },
      }),
      extraProviders: [{ provide: ENV, useFactory: () => loadEnv() }],
    }),
  ],
  providers: [
    { provide: ENV, useFactory: () => loadEnv() },
    RateLimiterService,
    { provide: APP_FILTER, useClass: AllExceptionsFilter },
    { provide: APP_GUARD, useClass: IpRateLimitGuard },
    { provide: APP_GUARD, useClass: CsrfGuard },
    { provide: APP_GUARD, useClass: AuthGuard },
    { provide: APP_GUARD, useClass: RolesGuard },
    { provide: APP_GUARD, useClass: RouteRateLimitGuard },
  ],
  exports: [ENV, RateLimiterService],
})
export class CommonModule {}
