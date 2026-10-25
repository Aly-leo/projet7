import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterOutlet } from '@angular/router';
import { ThemeService } from './core/theme.service';
import { ToastService } from './core/toast.service';

@Component({
  selector: 'app-root',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterOutlet],
  styles: `
    .toasts { position: fixed; right: 1rem; bottom: 1rem; z-index: 100; display: flex; flex-direction: column; gap: 0.5rem; max-width: min(380px, calc(100vw - 2rem)); }
    .toast { padding: 0.75rem 1rem; font-size: 0.9rem; display: flex; gap: 0.7rem; align-items: flex-start; justify-content: space-between; }
    .toast.ok { border-left: 4px solid var(--success); }
    .toast.error { border-left: 4px solid var(--danger); }
    .toast.info { border-left: 4px solid var(--accent); }
    .toast button { background: none; border: 0; color: var(--text-soft); cursor: pointer; font-size: 1.1rem; line-height: 1; padding: 0; width: auto; }
  `,
  template: `
    <router-outlet />
    <div class="toasts" aria-live="polite">
      @for (t of toast.toasts(); track t.id) {
        <div class="toast glass glass-strong" [class]="t.kind" role="status">
          <span>{{ t.text }}</span>
          <button type="button" aria-label="Fermer" (click)="toast.dismiss(t.id)">×</button>
        </div>
      }
    </div>
  `,
})
export class App {
  protected readonly toast = inject(ToastService);
  // Instanciation précoce : applique le thème avant l'affichage des pages.
  private readonly theme = inject(ThemeService);
}
