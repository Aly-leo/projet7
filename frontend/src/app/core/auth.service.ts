import { Injectable, computed, inject, signal } from '@angular/core';
import { ApiService } from './api.service';
import type { Role, User } from './models';

@Injectable({ providedIn: 'root' })
export class AuthService {
  private readonly api = inject(ApiService);
  private loading: Promise<void> | null = null;

  readonly user = signal<User | null>(null);
  readonly role = computed<Role | null>(() => this.user()?.role ?? null);
  readonly isStaff = computed(() => this.role() === 'ADMIN' || this.role() === 'ANALYST');
  readonly isAdmin = computed(() => this.role() === 'ADMIN');

  /** Charge le profil une seule fois (le serveur reste l'autorité : cookies HttpOnly, aucun jeton côté JavaScript). */
  load(force = false): Promise<void> {
    if (force) this.loading = null;
    this.loading ??= this.api
      .get<{ user: User }>('/auth/moi')
      .then((r) => this.user.set(r.user))
      .catch(() => this.user.set(null));
    return this.loading;
  }

  async login(courriel: string, motDePasse: string): Promise<User> {
    const r = await this.api.post<{ user: User }>('/auth/connexion', { courriel, motDePasse });
    this.user.set(r.user);
    this.loading = Promise.resolve();
    return r.user;
  }

  async changePassword(motDePasseActuel: string, nouveauMotDePasse: string): Promise<void> {
    const r = await this.api.post<{ user: User }>('/auth/changer-mot-de-passe', { motDePasseActuel, nouveauMotDePasse });
    this.user.set(r.user);
  }

  async logout(): Promise<void> {
    try {
      await this.api.post('/auth/deconnexion');
    } catch {
      /* la session locale est de toute façon abandonnée */
    }
    this.clear();
  }

  clear(): void {
    this.user.set(null);
    this.loading = Promise.resolve();
  }
}
