import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { ApiService, errorMessage } from '../core/api.service';
import { ModelState } from '../core/models';
import { ToastService } from '../core/toast.service';
import { IconComponent } from '../shared/ui';

@Component({
  selector: 'app-models',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [DatePipe, IconComponent],
  template: `
    <div class="page">
      <div class="page-header"><div><h1>Modèles</h1><p>M1 (exploitabilité) et M2 (priorité contextuelle).</p></div></div>
      @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
      @if (state(); as s) {
        <section class="glass card">
          <div class="alert info" style="margin-bottom:1rem">{{ s.message }}</div>
          <dl class="kv">
            <dt>M1 (exploitabilité)</dt>
            <dd>
              <span class="badge ok">{{ m1Version() }}</span>
              @if (s.m1?.mode === 'trained') {
                Modèle entraîné · {{ s.m1?.info?.model }} · horizon {{ s.m1?.info?.horizonDays }} j
              } @else if (s.m1?.configuredMode === 'trained') {
                <span class="badge bad">Service M1 injoignable : estimation de repli</span>
              } @else {
                <span class="muted">Service d'inférence non connecté : estimation de repli</span>
              }
            </dd>
            <dt>M2 (priorité contextuelle)</dt><dd><span class="badge warn">Simulation</span><span class="mono" style="margin-left:.6rem">{{ s.version }}</span></dd>
            <dt>Fournisseur M2 configuré</dt><dd>{{ s.configuredProvider === 'anthropic' ? 'API Claude' : 'Règles déterministes' }}</dd>
            <dt>Fournisseur M2 actif</dt><dd>{{ s.activeProvider === 'anthropic' ? 'API Claude' : 'Règles déterministes' }}</dd>
            <dt>Clé d'API</dt><dd>{{ s.anthropicConfigured ? 'Configurée côté serveur' : 'Non configurée' }}</dd>
            @if (s.configuredProvider === 'anthropic') {
              <dt>Dernier appel à l'API Claude</dt>
              <dd>
                @if (s.lastLlmRun; as run) {
                  @if (run.outcome === 'SUCCESS') { <span class="badge ok">Réussi</span> } @else { <span class="badge bad">Échec : repli sur les règles</span> }
                  <span class="muted" style="margin-left:.6rem">{{ run.at | date: 'dd/MM/yyyy HH:mm' }}</span>
                } @else {
                  <span class="muted">Aucun appel enregistré</span>
                }
              </dd>
            }
          </dl>
          <div class="row" style="margin-top:1.1rem">
            <button class="btn primary" type="button" (click)="rerun()" [disabled]="busy()">
              @if (busy()) { <span class="spinner"></span> } @else { <app-icon name="refresh" /> } Relancer les prédictions
            </button>
            <span class="field-hint">Recalcule M1 et M2 pour tous les constats.</span>
          </div>
        </section>
        <section class="glass card">
          <h2>Mesures de performance</h2>
          <h3 style="margin:.2rem 0 .5rem">M1 {{ m1Version() }}</h3>
          @if (s.m1?.info?.evaluation; as ev) {
            <dl class="kv">
              <dt>PR-AUC</dt>
              <dd>{{ num(ev.prAuc, 4) }} @if (ev.prAucCi95) { <span class="muted">(IC 95 % : {{ num(ev.prAucCi95[0], 4) }} à {{ num(ev.prAucCi95[1], 4) }})</span> }</dd>
              <dt>Référence CVSS seul</dt><dd>{{ num(ev.cvssPrAuc, 4) }} <span class="muted">(PR-AUC)</span></dd>
              <dt>ROC-AUC</dt><dd>{{ num(ev.rocAuc, 3) }}</dd>
              <dt>Erreur de calibration (ECE)</dt><dd>{{ num(ev.ece, 4) }}</dd>
              <dt>Jeu de test</dt>
              <dd>{{ ev.n }} CVE dont {{ ev.positives }} exploités <span class="muted">(prévalence {{ pct(ev.prevalence) }})</span></dd>
            </dl>
            <p class="field-hint" style="margin-top:.6rem">Évaluation unique sur le jeu de test. Avec si peu de cas exploités, les résultats sont indicatifs : l'intervalle de confiance est large.</p>
          } @else {
            <div class="empty" style="padding:.8rem 0">Mesures de M1 disponibles quand le service d'inférence est connecté.</div>
          }
          <h3 style="margin:1rem 0 .5rem">M2</h3>
          <div class="row">
            <span class="muted">Mesures non disponibles : modèle non entraîné.</span>
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

  /** « m1_v1 » → « V1 » ; V1 par défaut (première version entraînée). */
  protected readonly m1Version = computed(() => {
    const v = /v(\d+)$/i.exec(this.state()?.m1?.info?.modelVersion ?? '');
    return v ? `V${v[1]}` : 'V1';
  });

  protected num(v: number | null | undefined, digits: number): string {
    return v == null ? '–' : v.toFixed(digits).replace('.', ',');
  }

  protected pct(v: number | null | undefined): string {
    return v == null ? '–' : `${(v * 100).toFixed(2).replace('.', ',')} %`;
  }

  protected async rerun(): Promise<void> {
    if (!confirm('Relancer les prédictions pour tous les constats ?')) return;
    this.busy.set(true);
    try {
      const r = await this.api.post<{ total: number }>('/modeles/entrainement');
      this.toast.ok(`Prédictions relancées pour ${r.total} constat(s).`);
    } catch (err) {
      this.toast.error(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}
