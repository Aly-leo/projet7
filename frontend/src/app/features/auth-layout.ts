import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { ThemeService } from '../core/theme.service';
import { IconComponent } from '../shared/ui';

/** Cadre commun des pages publiques (installation, connexion, changement de mot de passe). */
@Component({
  selector: 'app-auth-layout',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  styles: `
    :host { display: grid; place-items: center; min-height: 100vh; padding: 1.2rem; position: relative; }
    .theme { position: absolute; top: 1rem; right: 1rem; }
    .panel { width: min(460px, 100%); padding: 2rem 2rem 1.6rem; }
    .logo { width: 48px; height: 48px; border-radius: 15px; display: grid; place-items: center; color: #fff; margin-bottom: 1rem;
      background: linear-gradient(135deg, #6aa5e0, #29375f); box-shadow: 0 10px 24px rgba(58, 103, 157, 0.35); }
    .logo app-icon { transform: scale(1.3); display: grid; }
  `,
  template: `
    <button class="btn ghost small theme" type="button" (click)="theme.toggle()" [attr.aria-label]="'Changer de thème'">
      <app-icon [name]="theme.theme() === 'dark' ? 'sun' : 'moon'" />
    </button>
    <section class="panel glass">
      <div class="logo"><app-icon name="shield" /></div>
      <ng-content />
    </section>
  `,
})
export class AuthLayoutComponent {
  protected readonly theme = inject(ThemeService);
}
