import { inject } from '@angular/core';
import { CanActivateChildFn, CanActivateFn, Router } from '@angular/router';
import { ApiService } from './api.service';
import { AuthService } from './auth.service';
import type { Role } from './models';

let installationRequired: boolean | null = null;

/** Garde d'installation : tant qu'aucun compte n'existe, toutes les routes mènent à /installation. */
export const installationGuard: CanActivateChildFn = async (_route, state) => {
  const router = inject(Router);
  const api = inject(ApiService);
  if (installationRequired !== false) {
    try {
      installationRequired = (await api.get<{ installationRequise: boolean }>('/installation/etat')).installationRequise;
    } catch {
      installationRequired = false; // en cas d'erreur réseau, la page de connexion affichera le problème
    }
  }
  const onInstall = state.url.startsWith('/installation');
  if (installationRequired && !onInstall) return router.createUrlTree(['/installation']);
  if (!installationRequired && onInstall) return router.createUrlTree(['/connexion']);
  return true;
};

export function markInstalled(): void {
  installationRequired = false;
}

/** Aide d'ergonomie : la vraie protection reste côté serveur. */
export const authGuard: CanActivateFn = async (_route, state) => {
  const auth = inject(AuthService);
  const router = inject(Router);
  await auth.load();
  const user = auth.user();
  if (!user) return router.createUrlTree(['/connexion']);
  if (user.mustChangePassword && !state.url.startsWith('/changer-mot-de-passe')) {
    return router.createUrlTree(['/changer-mot-de-passe']);
  }
  return true;
};

export const roleGuard =
  (...roles: Role[]): CanActivateFn =>
  async () => {
    const auth = inject(AuthService);
    const router = inject(Router);
    await auth.load();
    const role = auth.role();
    return role && roles.includes(role) ? true : router.createUrlTree(['/403']);
  };

/** Page d'accueil publique : une personne déjà connectée est envoyée directement au tableau de bord. */
export const landingGuard: CanActivateFn = async () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  await auth.load();
  const user = auth.user();
  if (!user) return true;
  return router.createUrlTree([user.mustChangePassword ? '/changer-mot-de-passe' : '/tableau-de-bord']);
};

export const guestGuard: CanActivateFn = async () => {
  const auth = inject(AuthService);
  const router = inject(Router);
  await auth.load();
  return auth.user() ? router.createUrlTree(['/tableau-de-bord']) : true;
};
