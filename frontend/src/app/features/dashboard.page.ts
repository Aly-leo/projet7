import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';
import { ApiService, errorMessage } from '../core/api.service';
import { AuthService } from '../core/auth.service';
import { Aggregate, Application, PRIORITY_LABEL, STATUS_LABEL, SEVERITY_LABEL, type CorrectionStatus, type Priority } from '../core/models';
import { ToastService } from '../core/toast.service';
import { ChartComponent } from '../shared/chart.component';
import { IconComponent, PriorityComponent, SimTagComponent } from '../shared/ui';

@Component({
  selector: 'app-dashboard',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, ChartComponent, IconComponent, PriorityComponent, SimTagComponent],
  styles: `
    .kpi { padding: 1.1rem 1.25rem; display: flex; flex-direction: column; gap: 0.15rem; position: relative; overflow: hidden; }
    .kpi .n { font-size: 2.2rem; font-weight: 700; letter-spacing: -0.03em; line-height: 1.1; }
    .kpi .l { font-size: 0.82rem; color: var(--text-soft); font-weight: 600; }
    .kpi::after { content: ''; position: absolute; inset: auto -20px -30px auto; width: 90px; height: 90px; border-radius: 50%; background: var(--c, var(--accent)); opacity: 0.12; filter: blur(8px); }
    .filters { display: flex; gap: 0.6rem; flex-wrap: wrap; }
    .filters select { width: auto; min-width: 170px; }
  `,
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Tableau de bord</h1>
          <p>
            @if (auth.role() === 'DECISION_MAKER') { Vue agrégée : aucun détail de constat n'est exposé. } @else { Vue d'ensemble des priorités à traiter. }
            <app-sim-tag />
          </p>
        </div>
        <div class="filters">
          @if (auth.isStaff()) {
            <select aria-label="Filtrer par application" [ngModel]="appId()" (ngModelChange)="appId.set($event); load()">
              <option value="">Toutes les applications</option>
              @for (a of apps(); track a.id) { <option [value]="a.id">{{ a.name }}</option> }
            </select>
          }
          <select aria-label="Filtrer par période" [ngModel]="period()" (ngModelChange)="period.set($event); load()">
            <option value="">Toute la période</option>
            <option value="7">7 derniers jours</option>
            <option value="30">30 derniers jours</option>
            <option value="90">90 derniers jours</option>
            <option value="365">12 derniers mois</option>
          </select>
          <button class="btn" type="button" (click)="downloadSummary()" [disabled]="downloading()">
            @if (downloading()) { <span class="spinner"></span> } @else { <app-icon name="download" /> }
            Télécharger la synthèse PDF
          </button>
        </div>
      </div>

      @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }

      @if (loading() && !data()) {
        <div class="empty"><span class="spinner"></span></div>
      } @else if (data(); as d) {
        <div class="grid cols-4">
          @for (p of priorities; track p) {
            <div class="kpi glass" [style.--c]="'var(--' + p.toLowerCase() + ')'">
              <span class="n" [style.color]="'var(--' + p.toLowerCase() + ')'">{{ d.byPriority[p] }}</span>
              <span class="l">{{ p }} · {{ label(p) }}<app-sim-tag /></span>
            </div>
          }
        </div>

        <div class="grid cols-2">
          <section class="glass card">
            <h2>Répartition par priorité</h2>
            @if (d.totals.findings === 0) {
              <div class="empty">Aucun constat. Importez un rapport ZAP pour commencer.</div>
            } @else {
              <app-chart type="doughnut" label="Répartition des constats par priorité"
                [labels]="prioLabels()" [values]="prioValues()" [colors]="['--p1', '--p2', '--p3', '--p4']" />
            }
          </section>
          <section class="glass card">
            <h2>Constats par application</h2>
            @if (d.byApplication.length === 0) {
              <div class="empty">Aucune application.</div>
            } @else {
              <app-chart type="bar" label="Constats par application" [labels]="appLabels()" [values]="appValues()"
                [colors]="['--accent']" />
            }
          </section>
        </div>

        <div class="grid cols-2">
          <section class="glass card">
            <h2>Par statut de correction</h2>
            <div class="stack">
              @for (s of statusRows(); track s.key) {
                <div class="row between"><span>{{ s.label }}</span><strong>{{ s.value }}</strong></div>
              } @empty { <span class="muted">Aucune donnée.</span> }
            </div>
          </section>
          <section class="glass card">
            <h2>Par gravité technique</h2>
            <div class="stack">
              @for (s of severityRows(); track s.label) {
                <div class="row between"><span>{{ s.label }}</span><strong>{{ s.value }}</strong></div>
              }
            </div>
          </section>
        </div>

        @if (d.topFindings) {
          <section class="glass card">
            <div class="row between"><h2>À traiter en premier</h2><a routerLink="/constats">Tous les constats →</a></div>
            @if (d.topFindings.length === 0) {
              <div class="empty">Aucun constat ouvert.</div>
            } @else {
              <div class="table-wrap">
                <table>
                  <thead><tr><th>Priorité</th><th>Titre</th><th>Application</th><th>Statut</th><th class="num">Probabilité</th></tr></thead>
                  <tbody>
                    @for (f of d.topFindings; track f.id) {
                      <tr class="clickable" tabindex="0" (click)="open(f.id)" (keydown.enter)="open(f.id)">
                        <td class="nowrap"><app-priority [value]="f.priority" /><app-sim-tag /></td>
                        <td class="truncate">{{ f.title }}</td>
                        <td>{{ f.application.name }}</td>
                        <td>@if (f.correction) { <span class="badge neutral">{{ status(f.correction.status) }}</span> }</td>
                        <td class="num">{{ f.modelProbability === null ? '–' : (f.modelProbability * 100).toFixed(0) + ' %' }}</td>
                      </tr>
                    }
                  </tbody>
                </table>
              </div>
            }
          </section>
        }
      }
    </div>
  `,
})
export class DashboardPage {
  private readonly api = inject(ApiService);
  private readonly toast = inject(ToastService);
  private readonly router = inject(Router);
  protected readonly auth = inject(AuthService);

  protected readonly priorities: Priority[] = ['P1', 'P2', 'P3', 'P4'];
  protected readonly data = signal<Aggregate | null>(null);
  protected readonly apps = signal<Application[]>([]);
  protected readonly appId = signal('');
  protected readonly period = signal('');
  protected readonly loading = signal(false);
  protected readonly downloading = signal(false);
  protected readonly error = signal('');

  protected readonly prioLabels = computed(() => this.priorities.map((p) => `${p} · ${PRIORITY_LABEL[p]}`));
  protected readonly prioValues = computed(() => this.priorities.map((p) => this.data()?.byPriority[p] ?? 0));
  protected readonly appLabels = computed(() => (this.data()?.byApplication ?? []).map((a) => a.name));
  protected readonly appValues = computed(() => (this.data()?.byApplication ?? []).map((a) => a.total));
  protected readonly statusRows = computed(() =>
    Object.entries(this.data()?.byStatus ?? {}).map(([key, value]) => ({ key, value, label: this.status(key) })),
  );
  protected readonly severityRows = computed(() =>
    ['3', '2', '1', '0'].map((s) => ({ label: SEVERITY_LABEL[Number(s)]!, value: this.data()?.bySeverity[s] ?? 0 })),
  );

  constructor() {
    void this.init();
  }

  protected label(p: Priority): string { return PRIORITY_LABEL[p]; }
  protected status(s: string): string { return STATUS_LABEL[s as CorrectionStatus] ?? s; }
  protected open(id: string): void { void this.router.navigate(['/constats', id]); }

  private async init(): Promise<void> {
    if (this.auth.isStaff()) {
      try { this.apps.set(await this.api.get<Application[]>('/applications')); } catch { /* filtre indisponible */ }
    }
    await this.load();
  }

  protected async load(): Promise<void> {
    this.loading.set(true);
    this.error.set('');
    try {
      this.data.set(await this.api.get<Aggregate>('/tableaux-de-bord', {
        applicationId: this.appId() || undefined,
        periodDays: this.period() || undefined,
      }));
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.loading.set(false);
    }
  }

  protected async downloadSummary(): Promise<void> {
    this.downloading.set(true);
    try {
      await this.api.downloadPdf('/rapports/synthese/pdf');
      this.toast.ok('Synthèse PDF téléchargée.');
    } catch (err) {
      this.toast.error(errorMessage(err));
    } finally {
      this.downloading.set(false);
    }
  }
}
