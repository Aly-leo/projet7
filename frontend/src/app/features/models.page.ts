import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { ApiService, errorMessage } from '../core/api.service';
import { ModelState } from '../core/models';
import { ToastService } from '../core/toast.service';
import { IconComponent } from '../shared/ui';

@Component({
  selector: 'app-models',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  template: `
    <div class="page">
      <div class="page-header"><div><h1>Modèles</h1><p>M1 (exploitabilité) et M2 (priorité contextuelle).</p></div></div>
      @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
      @if (state(); as s) {
        <section class="glass card">
          <div class="alert info" style="margin-bottom:1rem"><strong>Mode simulation.</strong> {{ s.message }}</div>
          <dl class="kv">
            <dt>M1 (exploitabilité)</dt>
            <dd>
              @if (s.m1?.mode === 'trained') {
                <span class="badge ok">Modèle entraîné</span> {{ s.m1?.info?.modelVersion }} · {{ s.m1?.info?.model }} · horizon {{ s.m1?.info?.horizonDays }} j
              } @else {
                <span class="badge warn">Simulation</span>
                @if (s.m1?.configuredMode === 'trained') { <span class="badge bad">Service M1 injoignable : repli sur la simulation</span> }
              }
            </dd>
            <dt>M2 (priorité contextuelle)</dt><dd><span class="badge warn">Simulation</span></dd>
            <dt>Version</dt><dd class="mono">{{ s.version }}</dd>
            <dt>Fournisseur configuré</dt><dd>{{ s.configuredProvider === 'anthropic' ? 'API Claude' : 'Règles déterministes' }}</dd>
            <dt>Fournisseur actif</dt><dd>{{ s.activeProvider === 'anthropic' ? 'API Claude (simulation)' : 'Règles déterministes (simulation)' }}</dd>
            <dt>Clé d'API</dt><dd>{{ s.anthropicConfigured ? 'Configurée côté serveur' : 'Non configurée' }}</dd>
          </dl>
          <div class="row" style="margin-top:1.1rem">
            <button class="btn primary" type="button" (click)="rerun()" [disabled]="busy()">
              @if (busy()) { <span class="spinner"></span> } @else { <app-icon name="refresh" /> } Relancer les prédictions
            </button>
            <span class="field-hint">Aucun entraînement réel : les sorties simulées sont recalculées pour tous les constats.</span>
          </div>
        </section>
        <section class="glass card">
          <h2>Mesures de performance</h2>
          <div class="empty" style="padding:1.2rem 0">Mesures non disponibles : modèles non entraînés.</div>
          <div class="row">
            @for (m of s.metricsPlanned; track m) { <span class="badge neutral" title="Emplacement réservé">{{ m }}</span> }
          </div>
        </section>
      } @else if (!error()) { <div class="empty"><span class="spinner"></span></div> }
    </div>
  `,
})
export class ModelsPage {
  private readonly api = inject(ApiService);
  private readonly toast = inject(ToastService);
  protected readonly state = signal<ModelState | null>(null);
  protected readonly error = signal('');
  protected readonly busy = signal(false);

  constructor() {
    this.api.get<ModelState>('/modeles').then((s) => this.state.set(s)).catch((e) => this.error.set(errorMessage(e)));
  }

  protected async rerun(): Promise<void> {
    if (!confirm('Relancer les prédictions simulées pour tous les constats ?')) return;
    this.busy.set(true);
    try {
      const r = await this.api.post<{ total: number }>('/modeles/entrainement');
      this.toast.ok(`Prédictions simulées relancées pour ${r.total} constat(s).`);
    } catch (err) {
      this.toast.error(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}
