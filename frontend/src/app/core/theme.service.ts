import { DOCUMENT } from '@angular/common';
import { Injectable, effect, inject, signal } from '@angular/core';

export type Theme = 'light' | 'dark';
const KEY = 'p7-theme';

/** Thème clair / sombre : suit le système par défaut, mémorise le choix (préférence d'affichage uniquement). */
@Injectable({ providedIn: 'root' })
export class ThemeService {
  private readonly doc = inject(DOCUMENT);
  readonly theme = signal<Theme>(this.initial());
  /** Incrémenté à chaque changement effectif : les graphiques se redessinent. */
  readonly version = signal(0);

  constructor() {
    effect(() => {
      const t = this.theme();
      this.doc.documentElement.setAttribute('data-theme', t);
      this.version.update((v) => v + 1);
    });
    const mq = this.doc.defaultView?.matchMedia?.('(prefers-color-scheme: dark)');
    mq?.addEventListener?.('change', (e) => {
      if (!this.stored()) this.theme.set(e.matches ? 'dark' : 'light');
    });
  }

  toggle(): void {
    const next: Theme = this.theme() === 'dark' ? 'light' : 'dark';
    this.theme.set(next);
    try {
      localStorage.setItem(KEY, next);
    } catch {
      /* stockage indisponible : le choix vaut pour la session */
    }
  }

  private stored(): Theme | null {
    try {
      const v = localStorage.getItem(KEY);
      return v === 'light' || v === 'dark' ? v : null;
    } catch {
      return null;
    }
  }

  private initial(): Theme {
    return this.stored() ?? (this.doc.defaultView?.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }
}
