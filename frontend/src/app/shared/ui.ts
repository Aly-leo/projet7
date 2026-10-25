import { ChangeDetectionStrategy, Component, computed, input } from '@angular/core';
import type { Priority } from '../core/models';
import { PRIORITY_LABEL } from '../core/models';

const ICONS: Record<string, string> = {
  dashboard: 'M3 3h7v9H3zM14 3h7v5h-7zM14 12h7v9h-7zM3 16h7v5H3z',
  upload: 'M12 16V4m0 0-4 4m4-4 4 4M4 16v3a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-3',
  list: 'M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01',
  app: 'M4 5h16v14H4zM4 9h16M8 13h4',
  users: 'M16 19v-1a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v1M9.5 10a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM21 19v-1a4 4 0 0 0-3-3.9M16 4.1a3 3 0 0 1 0 5.8',
  model: 'M12 3 3 8l9 5 9-5zM3 13l9 5 9-5M3 17.5l9 5 9-5',
  audit: 'M9 12l2 2 4-4M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6z',
  report: 'M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6',
  sun: 'M12 16a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4',
  moon: 'M21 12.8A9 9 0 1 1 11.2 3 7 7 0 0 0 21 12.8z',
  logout: 'M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9',
  download: 'M12 4v12m0 0-4-4m4 4 4-4M4 20h16',
  shield: 'M12 3 4 6v6c0 5 3.5 8.5 8 9 4.5-.5 8-4 8-9V6z',
  flask: 'M9 3h6M10 3v6l-5.5 9.5A1.5 1.5 0 0 0 5.8 21h12.4a1.5 1.5 0 0 0 1.3-2.5L14 9V3',
  plus: 'M12 5v14M5 12h14',
  refresh: 'M20 11a8 8 0 1 0-2.3 5.7M20 4v7h-7',
  menu: 'M4 7h16M4 12h16M4 17h16',
  eye: 'M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z',
  'eye-off': 'M3 3l18 18M10.6 5.1A10 10 0 0 1 12 5c6.5 0 10 7 10 7a17 17 0 0 1-3.2 4.1M6.6 6.6A16.5 16.5 0 0 0 2 12s3.5 7 10 7a9.7 9.7 0 0 0 4.4-1M9.9 9.9a3 3 0 0 0 4.2 4.2',
};

@Component({
  selector: 'app-icon',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path [attr.d]="path()" /></svg>`,
})
export class IconComponent {
  readonly name = input.required<string>();
  protected readonly path = computed(() => ICONS[this.name()] ?? '');
}

@Component({
  selector: 'app-priority',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (value(); as p) {
      <span class="badge" [class]="p" [attr.title]="label()">{{ p }}</span>
    } @else {
      <span class="faint">–</span>
    }
  `,
})
export class PriorityComponent {
  readonly value = input<Priority | null | undefined>(null);
  protected readonly label = computed(() => (this.value() ? PRIORITY_LABEL[this.value()!] : ''));
}

@Component({
  selector: 'app-sim-tag',
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `<span class="sim-tag" title="Valeur simulée : les modèles ne sont pas entraînés">Simulé</span>`,
})
export class SimTagComponent {}

@Component({
  selector: 'app-password-strength',
  changeDetection: ChangeDetectionStrategy.OnPush,
  styles: `
    .bar { display: flex; gap: 4px; margin-top: 0.35rem; }
    .seg { flex: 1; height: 5px; border-radius: 99px; background: var(--glass-edge); transition: background 0.25s; }
    .label { font-size: 0.78rem; margin-top: 0.25rem; }
  `,
  template: `
    <div class="bar" aria-hidden="true">
      @for (i of [1, 2, 3, 4]; track i) {
        <span class="seg" [style.background]="i <= score() ? color() : null"></span>
      }
    </div>
    <div class="label" [style.color]="color()" aria-live="polite">{{ text() }}</div>
  `,
})
export class PasswordStrengthComponent {
  readonly value = input.required<string>();

  /** Indicateur indicatif (longueur et variété) ; la politique faisant foi est appliquée par le serveur. */
  readonly score = computed(() => {
    const v = this.value();
    if (!v) return 0;
    let s = 0;
    if (v.length >= 12) s++;
    if (v.length >= 16) s++;
    if (/[a-z]/.test(v) && /[A-Z]/.test(v)) s++;
    if (/\d/.test(v) && /[^A-Za-z0-9]/.test(v)) s++;
    return v.length < 12 ? Math.min(s, 1) : Math.max(s, 1);
  });
  protected readonly color = computed(() => ['var(--text-faint)', 'var(--danger)', 'var(--warning)', 'var(--accent)', 'var(--success)'][this.score()]);
  protected readonly text = computed(() => {
    if (!this.value()) return '12 caractères au moins, sans mot courant.';
    if (this.value().length < 12) return `Trop court (${this.value().length}/12).`;
    return ['', 'Faible', 'Moyen', 'Bon', 'Excellent'][this.score()] + ' — la validation finale est faite par le serveur.';
  });
}
