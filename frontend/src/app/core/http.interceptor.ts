import { HttpErrorResponse, HttpInterceptorFn, HttpRequest } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, from, switchMap, throwError } from 'rxjs';
import { AuthService } from './auth.service';
import { ToastService } from './toast.service';

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
let refreshing: Promise<boolean> | null = null;

function csrfToken(): string | null {
  const m = /(?:^|;\s*)csrf_token=([^;]+)/.exec(document.cookie);
  return m ? decodeURIComponent(m[1]!) : null;
}

function withHeaders(req: HttpRequest<unknown>): HttpRequest<unknown> {
  let r = req.clone({ withCredentials: true });
  const token = csrfToken();
  if (UNSAFE.has(req.method) && token) r = r.clone({ setHeaders: { 'X-CSRF-Token': token } });
  return r;
}

/** Cookies, jeton anti-CSRF, et une seule tentative de rafraîchissement sur 401 avant retour à la connexion. */
export const httpInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const auth = inject(AuthService);
  const toast = inject(ToastService);
  const isAuthCall = /\/api\/auth\/(connexion|rafraichir)$/.test(req.url);

  return next(withHeaders(req)).pipe(
    catchError((err: unknown) => {
      if (!(err instanceof HttpErrorResponse) || err.status !== 401 || isAuthCall) return throwError(() => err);

      refreshing ??= fetch('/api/auth/rafraichir', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', ...(csrfToken() ? { 'X-CSRF-Token': csrfToken()! } : {}) },
        body: '{}',
      })
        .then((r) => r.ok)
        .catch(() => false)
        .finally(() => setTimeout(() => (refreshing = null), 0));

      return from(refreshing).pipe(
        switchMap((ok) => {
          if (ok) return next(withHeaders(req));
          const hadSession = auth.user() !== null;
          auth.clear();
          if (hadSession) toast.error('Votre session a expiré. Veuillez vous reconnecter.');
          // La vérification de session initiale (/auth/moi) ne redirige pas : les gardes de routes décident
          // (la page d'accueil publique reste accessible sans connexion).
          const probe = req.url.endsWith('/auth/moi');
          const publicPage = ['/connexion', '/installation'].some((p) => router.url.startsWith(p)) || router.url === '/';
          if (!probe && !publicPage) router.navigateByUrl('/connexion');
          return throwError(() => err);
        }),
      );
    }),
  );
};
