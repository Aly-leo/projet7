import { Body, Controller, Get, HttpCode, Post, Req, Res } from '@nestjs/common';
import type { Response } from 'express';
import {
  AllowPasswordChange,
  AllRoles,
  AuditAs,
  Ctx,
  CurrentUser,
  Public,
  RateLimit,
} from '../common/decorators.js';
import { ACCESS_COOKIE, CSRF_COOKIE, REFRESH_COOKIE } from '../common/guards.js';
import type { AppRequest, AuditContext, AuthUser } from '../common/types.js';
import { ENV, type Env } from '../config/env.js';
import { Inject } from '@nestjs/common';
import { ChangePasswordDto, LoginDto } from './auth.dto.js';
import { AuthService, type IssuedSession } from './auth.service.js';

@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    @Inject(ENV) private readonly env: Env,
  ) {}

  @Post('connexion')
  @Public()
  @HttpCode(200)
  @RateLimit({ name: 'login', limit: 5, windowMs: 15 * 60_000, by: 'ip+email' })
  async login(@Body() dto: LoginDto, @Res({ passthrough: true }) res: Response, @Ctx() ctx: AuditContext) {
    const session = await this.auth.login(dto.courriel, dto.motDePasse, ctx);
    this.setCookies(res, session);
    return { user: session.user };
  }

  @Post('rafraichir')
  @Public()
  @HttpCode(200)
  @RateLimit({ name: 'refresh', limit: 30, windowMs: 15 * 60_000, by: 'ip' })
  async refresh(@Req() req: AppRequest, @Res({ passthrough: true }) res: Response, @Ctx() ctx: AuditContext) {
    const cookies = (req as any).cookies as Record<string, string> | undefined;
    try {
      const session = await this.auth.refresh(cookies?.[REFRESH_COOKIE], ctx);
      this.setCookies(res, session);
      return { user: session.user };
    } catch (err) {
      this.clearCookies(res);
      throw err;
    }
  }

  @Post('deconnexion')
  @AllRoles()
  @AllowPasswordChange()
  @HttpCode(204)
  async logout(
    @CurrentUser() user: AuthUser,
    @Req() req: AppRequest,
    @Res({ passthrough: true }) res: Response,
    @Ctx() ctx: AuditContext,
  ) {
    const cookies = (req as any).cookies as Record<string, string> | undefined;
    await this.auth.logout(user.id, cookies?.[REFRESH_COOKIE], ctx);
    this.clearCookies(res);
  }

  @Get('moi')
  @AllRoles()
  @AllowPasswordChange()
  me(@CurrentUser() user: AuthUser) {
    return { user };
  }

  @Post('changer-mot-de-passe')
  @AllRoles()
  @AllowPasswordChange()
  @AuditAs('AUTH_PASSWORD_CHANGE')
  @HttpCode(200)
  @RateLimit({ name: 'pwd', limit: 10, windowMs: 15 * 60_000, by: 'user' })
  async changePassword(
    @CurrentUser() user: AuthUser,
    @Body() dto: ChangePasswordDto,
    @Res({ passthrough: true }) res: Response,
    @Ctx() ctx: AuditContext,
  ) {
    const session = await this.auth.changePassword(user, dto.motDePasseActuel, dto.nouveauMotDePasse, ctx);
    this.setCookies(res, session);
    return { user: session.user };
  }

  private setCookies(res: Response, s: IssuedSession): void {
    const secure = this.env.COOKIE_SECURE;
    const base = { secure, sameSite: 'strict' as const };
    res.cookie(ACCESS_COOKIE, s.accessToken, {
      ...base,
      httpOnly: true,
      path: '/api',
      maxAge: this.env.JWT_ACCESS_TTL_MIN * 60_000,
    });
    res.cookie(REFRESH_COOKIE, s.refreshToken, {
      ...base,
      httpOnly: true,
      path: '/api/auth',
      maxAge: this.env.REFRESH_TTL_DAYS * 86_400_000,
    });
    // Lisible par le JavaScript de l'application (double soumission) : ne contient aucun secret d'authentification.
    res.cookie(CSRF_COOKIE, s.csrfToken, {
      ...base,
      httpOnly: false,
      path: '/',
      maxAge: this.env.REFRESH_TTL_DAYS * 86_400_000,
    });
  }

  private clearCookies(res: Response): void {
    const base = { secure: this.env.COOKIE_SECURE, sameSite: 'strict' as const };
    res.clearCookie(ACCESS_COOKIE, { ...base, httpOnly: true, path: '/api' });
    res.clearCookie(REFRESH_COOKIE, { ...base, httpOnly: true, path: '/api/auth' });
    res.clearCookie(CSRF_COOKIE, { ...base, path: '/' });
  }
}
