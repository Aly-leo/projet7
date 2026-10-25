import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService, errorMessage } from '../core/api.service';
import { Application, FindingRow, Page, SEVERITY_LABEL, STATUS_LABEL, type CorrectionStatus } from '../core/models';
import { PriorityComponent } from '../shared/ui';

const STATUSES = Object.keys(STATUS_LABEL) as CorrectionStatus[];

@Component({
  selector: 'app-findings',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, PriorityComponent],
  styles: `
    .filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 0.6rem; }
    .pager { display: flex; align-items: center; justify-content: space-between; gap: 1rem; flex-wrap: wrap; margin-top: 0.8rem; }
  `,
  template: `
    <div class="page">
      <div class="page-header">
        <div><h1>Constats</h1><p>Classés par priorité.</p></div>
      </div>

      <section class="glass card">
        <div class="filters">
          <input type="search" aria-label="Rechercher" placeholder="Titre, CWE, CVE…" maxlength="100" [ngModel]="q()" (ngModelChange)="q.set($event); reset()" />
          <select aria-label="Application" [ngModel]="appId()" (ngModelChange)="appId.set($event); reset()">
            <option value="">Toutes les applications</option>
            @for (a of apps(); track a.id) { <option [value]="a.id">{{ a.name }}</option> }
          </select>
          <select aria-label="Priorité" [ngModel]="priority()" (ngModelChange)="priority.set($event); reset()">
            <option value="">Toutes les priorités</option>
            @for (p of ['P1', 'P2', 'P3', 'P4']; track p) { <option [value]="p">{{ p }}</option> }
          </select>
          <select aria-label="Statut" [ngModel]="status()" (ngModelChange)="status.set($event); reset()">
            <option value="">Tous les statuts</option>
            @for (s of statuses; track s) { <option [value]="s">{{ statusLabel(s) }}</option> }
          </select>
          <select aria-label="Gravité" [ngModel]="severity()" (ngModelChange)="severity.set($event); reset()">
            <option value="">Toutes les gravités</option>
            @for (g of [3, 2, 1, 0]; track g) { <option [value]="'' + g">{{ sev(g) }}</option> }
          </select>
          <select aria-label="Tri" [ngModel]="sort()" (ngModelChange)="sort.set($event); reset()">
            <option value="priority">Tri : priorité</option>
            <option value="severity">Tri : gravité</option>
            <option value="probability">Tri : probabilité</option>
            <option value="lastSeen">Tri : dernière apparition</option>
          </select>
        </div>
      </section>

      @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }

      <section class="glass card">
        @if (loading() && !data()) {
          <div class="empty"><span class="spinner"></span></div>
        } @else if (data(); as d) {
          @if (d.items.length === 0) {
            <div class="empty">Aucun constat ne correspond aux filtres.</div>
          } @else {
            <div class="table-wrap">
              <table>
                <thead>
                  <tr><th>Priorité</th><th>Titre</th><th>Application</th><th>Gravité</th><th>CWE / CVE</th><th>Statut</th><th class="num">Probabilité</th></tr>
                </thead>
                <tbody>
                  @for (f of d.items; track f.id) {
                    <tr class="clickable" tabindex="0" (click)="open(f.id)" (keydown.enter)="open(f.id)">
                      <td class="nowrap"><app-priority [value]="f.priority" /></td>
                      <td class="truncate" [title]="f.title">{{ f.title }}</td>
                      <td>{{ f.application.name }}</td>
                      <td>{{ sev(f.severity) }}</td>
                      <td class="mono">{{ f.cveId ?? (f.cweId ? 'CWE-' + f.cweId : '–') }}</td>
                      <td>@if (f.correction) { <span class="badge neutral">{{ statusLabel(f.correction.status) }}</span> }</td>
                      <td class="num">{{ f.modelProbability === null ? '–' : (f.modelProbability * 100).toFixed(0) + ' %' }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
            <div class="pager">
              <span class="muted">{{ d.total }} constat(s) · page {{ d.page }} / {{ pages() }}</span>
              <div class="row">
                <button class="btn small" type="button" (click)="go(-1)" [disabled]="page() <= 1">Précédent</button>
                <button class="btn small" type="button" (click)="go(1)" [disabled]="page() >= pages()">Suivant</button>
              </div>
            </div>
          }
        }
      </section>
    </div>
  `,
})
export class FindingsPage {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);

  protected readonly statuses = STATUSES;
  protected readonly apps = signal<Application[]>([]);
  protected readonly data = signal<Page<FindingRow> | null>(null);
  protected readonly loading = signal(false);
  protected readonly error = signal('');
  protected readonly q = signal('');
  protected readonly appId = signal('');
  protected readonly priority = signal('');
  protected readonly status = signal('');
  protected readonly severity = signal('');
  protected readonly sort = signal('priority');
  protected readonly page = signal(1);
  protected readonly pages = computed(() => Math.max(1, Math.ceil((this.data()?.total ?? 0) / 25)));
  private timer?: ReturnType<typeof setTimeout>;

  constructor() {
    this.api.get<Application[]>('/applications').then((a) => this.apps.set(a)).catch(() => undefined);
    void this.load();
  }

  protected sev(n: number): string { return SEVERITY_LABEL[n] ?? String(n); }
  protected statusLabel(s: CorrectionStatus): string { return STATUS_LABEL[s]; }
  protected open(id: string): void { void this.router.navigate(['/constats', id]); }

  /** Réinitialise la pagination et relance la recherche (temporisée pour la saisie). */
  protected reset(): void {
    this.page.set(1);
    clearTimeout(this.timer);
    this.timer = setTimeout(() => void this.load(), 250);
  }

  protected go(delta: number): void {
    this.page.update((p) => p + delta);
    void this.load();
  }

  private async load(): Promise<void> {
    this.loading.set(true);
    this.error.set('');
    try {
      this.data.set(await this.api.get<Page<FindingRow>>('/constats', {
        q: this.q().trim() || undefined,
        applicationId: this.appId() || undefined,
        priority: this.priority() || undefined,
        status: this.status() || undefined,
        severity: this.severity() || undefined,
        sort: this.sort(),
        page: this.page(),
        pageSize: 25,
      }));
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.loading.set(false);
    }
  }
}
