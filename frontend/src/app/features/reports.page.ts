import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, errorMessage } from '../core/api.service';
import { AuthService } from '../core/auth.service';
import { Application, Page, ScanRow, type Priority } from '../core/models';
import { ToastService } from '../core/toast.service';
import { IconComponent } from '../shared/ui';

type Kind = 'summary' | 'application' | 'scan';

@Component({
  selector: 'app-reports',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, DatePipe, IconComponent],
  template: `
    <div class="page">
      <div class="page-header"><div><h1>Rapports PDF</h1><p>Générés à la demande, au moment du téléchargement.</p></div></div>
      <section class="glass card">
        <form class="stack" (ngSubmit)="download()">
          <div class="form-grid">
            <label class="field">Type de rapport
              <select name="kind" [ngModel]="kind()" (ngModelChange)="kind.set($event); target.set('')">
                <option value="summary">Synthèse agrégée</option>
                @if (auth.isStaff()) {
                  <option value="application">Rapport d'application</option>
                  <option value="scan">Rapport d'import</option>
                }
              </select>
            </label>
            @if (kind() === 'application') {
              <label class="field">Application
                <select name="app" required [ngModel]="target()" (ngModelChange)="target.set($event)">
                  <option value="" disabled>Choisir…</option>
                  @for (a of apps(); track a.id) { <option [value]="a.id">{{ a.name }}</option> }
                </select>
              </label>
            }
            @if (kind() === 'scan') {
              <label class="field">Import
                <select name="scan" required [ngModel]="target()" (ngModelChange)="target.set($event)">
                  <option value="" disabled>Choisir…</option>
                  @for (s of scans(); track s.id) { <option [value]="s.id">{{ s.application.name }} · {{ s.fileName }} · {{ s.importedAt | date: 'dd/MM/yyyy HH:mm' }}</option> }
                </select>
              </label>
            }
          </div>

          @if (kind() !== 'summary') {
            <fieldset style="border:0;padding:0;margin:0">
              <legend class="field-hint" style="margin-bottom:.4rem;font-weight:600">Filtre de priorités (toutes si aucune case)</legend>
              <div class="row">
                @for (p of priorities; track p) {
                  <label class="row" style="gap:.35rem"><input type="checkbox" style="width:auto" [checked]="selected().includes(p)" (change)="toggle(p)" />{{ p }}</label>
                }
              </div>
            </fieldset>
            <label class="row" style="gap:.5rem">
              <input type="checkbox" style="width:auto" [checked]="details()" (change)="details.set(!details())" />
              Inclure les fiches détaillées
            </label>
          }

          @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
          <div class="row">
            <button class="btn primary" type="submit" [disabled]="busy() || !ready()">
              @if (busy()) { <span class="spinner"></span> Génération… } @else { <app-icon name="download" /> Télécharger le PDF }
            </button>
          </div>
        </form>
      </section>
      @if (!auth.isStaff()) {
        <div class="alert info">En tant que décideur, vous obtenez uniquement la synthèse agrégée (aucun titre, URL ni identifiant de constat).</div>
      }
    </div>
  `,
})
export class ReportsPage {
  private readonly api = inject(ApiService);
  private readonly toast = inject(ToastService);
  protected readonly auth = inject(AuthService);

  protected readonly priorities: Priority[] = ['P1', 'P2', 'P3', 'P4'];
  protected readonly kind = signal<Kind>('summary');
  protected readonly target = signal('');
  protected readonly selected = signal<Priority[]>([]);
  protected readonly details = signal(true);
  protected readonly apps = signal<Application[]>([]);
  protected readonly scans = signal<ScanRow[]>([]);
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly ready = computed(() => this.kind() === 'summary' || !!this.target());

  constructor() {
    if (this.auth.isStaff()) {
      this.api.get<Application[]>('/applications').then((a) => this.apps.set(a)).catch(() => undefined);
      this.api.get<Page<ScanRow>>('/scans', { pageSize: 100 }).then((p) => this.scans.set(p.items)).catch(() => undefined);
    }
  }

  protected toggle(p: Priority): void {
    this.selected.update((s) => (s.includes(p) ? s.filter((x) => x !== p) : [...s, p]));
  }

  protected async download(): Promise<void> {
    this.busy.set(true);
    this.error.set('');
    const kind = this.kind();
    const path = kind === 'summary' ? '/rapports/synthese/pdf' : kind === 'application' ? `/rapports/applications/${this.target()}/pdf` : `/rapports/scans/${this.target()}/pdf`;
    try {
      await this.api.downloadPdf(path, kind === 'summary' ? {} : {
        priorites: this.selected().length ? this.selected().join(',') : undefined,
        inclureDetails: this.details() ? undefined : 'false',
      });
      this.toast.ok('Rapport PDF téléchargé.');
    } catch (err) {
      // 403, 404, 422 (trop de constats : filtrer) et 429 (limite d'exports) ont des messages explicites.
      this.error.set(await this.blobError(err));
    } finally {
      this.busy.set(false);
    }
  }

  /** Les erreurs d'un téléchargement arrivent sous forme de blob JSON : on en extrait le message. */
  private async blobError(err: unknown): Promise<string> {
    const body = (err as { error?: unknown })?.error;
    if (body instanceof Blob) {
      try {
        const j = JSON.parse(await body.text());
        const m = Array.isArray(j.message) ? j.message.join(' ') : j.message;
        if (m) return String(m);
      } catch { /* corps non JSON */ }
    }
    return errorMessage(err);
  }
}
