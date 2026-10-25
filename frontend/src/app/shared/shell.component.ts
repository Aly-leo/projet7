import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { Router, RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { AuthService } from '../core/auth.service';
import { ROLE_LABEL, type Role } from '../core/models';
import { ThemeService } from '../core/theme.service';
import { IconComponent } from './ui';

interface NavItem { path: string; label: string; icon: string; roles: Role[] }

const NAV: NavItem[] = [
  { path: '/tableau-de-bord', label: 'Tableau de bord', icon: 'dashboard', roles: ['ADMIN', 'ANALYST', 'DECISION_MAKER'] },
  { path: '/import', label: 'Importer un scan', icon: 'upload', roles: ['ADMIN', 'ANALYST'] },
  { path: '/constats', label: 'Constats', icon: 'list', roles: ['ADMIN', 'ANALYST'] },
  { path: '/applications', label: 'Applications', icon: 'app', roles: ['ADMIN', 'ANALYST'] },
  { path: '/rapports', label: 'Rapports', icon: 'report', roles: ['ADMIN', 'ANALYST', 'DECISION_MAKER'] },
  { path: '/utilisateurs', label: 'Utilisateurs', icon: 'users', roles: ['ADMIN'] },
  { path: '/modeles', label: 'Modèles', icon: 'model', roles: ['ADMIN'] },
  { path: '/audit', label: "Journal d'audit", icon: 'audit', roles: ['ADMIN'] },
];

@Component({
  selector: 'app-shell',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet, RouterLink, RouterLinkActive, IconComponent],
  styles: `
    :host { display: block; min-height: 100vh; }
    .sim-banner {
      position: sticky; top: 0; z-index: 30; display: flex; align-items: center; justify-content: center; gap: 0.5rem;
      padding: 0.45rem 1rem; text-align: center; font-size: 0.83rem; font-weight: 600; color: var(--warning);
      background: color-mix(in srgb, var(--warning) 10%, var(--glass-strong));
      -webkit-backdrop-filter: var(--blur); backdrop-filter: var(--blur);
      border-bottom: 1px solid color-mix(in srgb, var(--warning) 28%, transparent);
    }
    .layout { display: grid; grid-template-columns: 250px 1fr; gap: 1.1rem; padding: 1.1rem; align-items: start; }
    nav.side { position: sticky; top: 3.4rem; padding: 1rem 0.7rem; display: flex; flex-direction: column; gap: 0.2rem; max-height: calc(100vh - 4.5rem); overflow: auto; }
    .brand { display: flex; align-items: center; gap: 0.65rem; padding: 0.3rem 0.7rem 1rem; font-weight: 700; color: var(--accent-strong); }
    .brand .logo { width: 34px; height: 34px; border-radius: 11px; display: grid; place-items: center; color: #fff;
      background: linear-gradient(135deg, #6aa5e0, #29375f); box-shadow: 0 6px 16px rgba(58, 103, 157, 0.35); }
    .brand small { display: block; font-weight: 500; font-size: 0.72rem; }
    nav.side a.link {
      display: flex; align-items: center; gap: 0.7rem; padding: 0.6rem 0.8rem; border-radius: 12px; color: var(--text-soft);
      font-weight: 600; font-size: 0.92rem; transition: background 0.15s, color 0.15s;
    }
    nav.side a.link:hover { background: var(--accent-soft); color: var(--text); text-decoration: none; }
    nav.side a.link.active { background: var(--accent-soft); color: var(--accent-strong); box-shadow: inset 3px 0 0 var(--accent); }
    .main { min-width: 0; display: flex; flex-direction: column; gap: 1rem; }
    .topbar { display: flex; align-items: center; justify-content: space-between; gap: 0.8rem; padding: 0.6rem 0.8rem 0.6rem 1.1rem; }
    .who { display: flex; flex-direction: column; line-height: 1.2; }
    .who strong { font-size: 0.92rem; }
    .who span { font-size: 0.78rem; color: var(--text-soft); }
    .menu-btn { display: none; }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; padding: 0.7rem; }
      nav.side { position: static; display: none; max-height: none; }
      nav.side.open { display: flex; }
      .menu-btn { display: inline-flex; }
    }
  `,
  template: `
    <div class="sim-banner" role="status">
      <app-icon name="flask" />
      Mode simulation : les prédictions de M1 et M2 sont simulées. Les modèles ne sont pas encore entraînés.
    </div>
    <div class="layout">
      <nav class="side glass" [class.open]="menuOpen()" aria-label="Navigation principale">
        <div class="brand">
          <span class="logo"><app-icon name="shield" /></span>
          <span>Priorisation<small>des vulnérabilités</small></span>
        </div>
        @for (item of items(); track item.path) {
          <a class="link" [routerLink]="item.path" routerLinkActive="active" (click)="menuOpen.set(false)">
            <app-icon [name]="item.icon" />{{ item.label }}
          </a>
        }
      </nav>
      <div class="main">
        <header class="topbar glass">
          <button class="btn ghost small menu-btn" type="button" (click)="menuOpen.set(!menuOpen())" aria-label="Ouvrir le menu">
            <app-icon name="menu" />
          </button>
          <div class="who">
            <strong>{{ auth.user()?.name }}</strong>
            <span>{{ roleLabel() }}</span>
          </div>
          <div class="row">
            <button class="btn ghost small" type="button" (click)="theme.toggle()"
              [attr.aria-label]="theme.theme() === 'dark' ? 'Passer au thème clair' : 'Passer au thème sombre'">
              <app-icon [name]="theme.theme() === 'dark' ? 'sun' : 'moon'" />
              {{ theme.theme() === 'dark' ? 'Clair' : 'Sombre' }}
            </button>
            <button class="btn small" type="button" (click)="logout()"><app-icon name="logout" />Déconnexion</button>
          </div>
        </header>
        <main id="contenu"><router-outlet /></main>
      </div>
    </div>
  `,
})
export class ShellComponent {
  protected readonly auth = inject(AuthService);
  protected readonly theme = inject(ThemeService);
  private readonly router = inject(Router);
  protected readonly menuOpen = signal(false);

  /** Le menu n'affiche que les pages autorisées ; la vraie protection reste côté serveur. */
  protected readonly items = computed(() => NAV.filter((i) => this.auth.role() && i.roles.includes(this.auth.role()!)));
  protected readonly roleLabel = computed(() => (this.auth.role() ? ROLE_LABEL[this.auth.role()!] : ''));

  protected async logout(): Promise<void> {
    await this.auth.logout();
    await this.router.navigateByUrl('/connexion');
  }
}
