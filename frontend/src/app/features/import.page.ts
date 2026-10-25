import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService, errorMessage } from '../core/api.service';
import { Application, ImportSummary, PRIORITY_LABEL, type Priority } from '../core/models';
import { ToastService } from '../core/toast.service';
import { IconComponent } from '../shared/ui';

const MAX_MB = 10;

@Component({
  selector: 'app-import',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, IconComponent],
  styles: `
    .drop { border: 1.5px dashed var(--glass-edge); border-radius: var(--radius); padding: 1.6rem; text-align: center; transition: background 0.2s, border-color 0.2s; }
    .drop.over { background: var(--accent-soft); border-color: var(--accent); }
    .drop input { max-width: 380px; margin: 0.6rem auto 0; }
    .prio { display: flex; gap: 0.6rem; flex-wrap: wrap; }
    .prio .badge { font-size: 0.9rem; padding: 0.3rem 0.8rem; }
  `,
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1>Importer un scan</h1>
          <p>Rapport OWASP ZAP au format JSON, pour une application de laboratoire autorisée.</p>
        </div>
      </div>

      <section class="glass card">
        <form class="stack" (ngSubmit)="submit()">
          <label class="field">Application
            <select name="app" required [ngModel]="appId()" (ngModelChange)="appId.set($event)">
              <option value="" disabled>Choisir une application…</option>
              @for (a of apps(); track a.id) { <option [value]="a.id">{{ a.name }}</option> }
            </select>
            @if (apps().length === 0 && !loadingApps()) {
              <span class="field-hint">Aucune application : un administrateur doit en créer une.</span>
            }
          </label>

          <div class="drop" [class.over]="over()" (dragover)="$event.preventDefault(); over.set(true)" (dragleave)="over.set(false)" (drop)="onDrop($event)">
            <app-icon name="upload" />
            <div><strong>Déposez le rapport .json</strong> ou choisissez un fichier</div>
            <input type="file" name="file" accept=".json,application/json" (change)="onFile($event)" aria-label="Fichier de rapport JSON" />
            @if (file(); as f) { <p class="muted" style="margin-top:.6rem">{{ f.name }} · {{ (f.size / 1024).toFixed(1) }} Ko</p> }
          </div>

          @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
          <div class="row">
            <button class="btn primary" type="submit" [disabled]="!canSubmit() || busy()">
              @if (busy()) { <span class="spinner"></span> Analyse en cours… } @else { <app-icon name="upload" /> Importer }
            </button>
          </div>
        </form>
      </section>

      @if (result(); as r) {
        <section class="glass card" aria-live="polite">
          <h2>Résumé de l'import</h2>
          <div class="grid cols-4" style="margin:.6rem 0 1rem">
            <div><div class="muted">Constats</div><strong style="font-size:1.6rem">{{ r.findingsTotal }}</strong></div>
            <div><div class="muted">Nouveaux</div><strong style="font-size:1.6rem">{{ r.findingsNew }}</strong></div>
            <div><div class="muted">Mis à jour</div><strong style="font-size:1.6rem">{{ r.findingsUpdated }}</strong></div>
            <div><div class="muted">Fournisseur</div><strong style="font-size:1.1rem">{{ r.provider === 'anthropic' ? 'API Claude' : 'Règles' }}</strong></div>
          </div>
          <div class="prio">
            @for (p of priorities; track p) { <span class="badge" [class]="p">{{ p }} · {{ label(p) }} : {{ r.byPriority[p] }}</span> }
          </div>
          <div class="row" style="margin-top:1.1rem">
            <button class="btn" type="button" (click)="downloadReport(r.scanId)" [disabled]="downloading()">
              @if (downloading()) { <span class="spinner"></span> } @else { <app-icon name="download" /> } Télécharger le rapport PDF
            </button>
            <a class="btn ghost" routerLink="/constats">Voir les constats</a>
          </div>
        </section>
      }
    </div>
  `,
})
export class ImportPage {
  private readonly api = inject(ApiService);
  private readonly toast = inject(ToastService);

  protected readonly priorities: Priority[] = ['P1', 'P2', 'P3', 'P4'];
  protected readonly apps = signal<Application[]>([]);
  protected readonly loadingApps = signal(true);
  protected readonly appId = signal('');
  protected readonly file = signal<File | null>(null);
  protected readonly over = signal(false);
  protected readonly busy = signal(false);
  protected readonly downloading = signal(false);
  protected readonly error = signal('');
  protected readonly result = signal<ImportSummary | null>(null);
  protected readonly canSubmit = computed(() => !!this.appId() && !!this.file());

  constructor() {
    this.api.get<Application[]>('/applications').then((a) => this.apps.set(a)).catch((e) => this.error.set(errorMessage(e))).finally(() => this.loadingApps.set(false));
  }

  protected label(p: Priority): string { return PRIORITY_LABEL[p]; }

  protected onFile(e: Event): void {
    this.accept((e.target as HTMLInputElement).files?.[0] ?? null);
  }
  protected onDrop(e: DragEvent): void {
    e.preventDefault();
    this.over.set(false);
    this.accept(e.dataTransfer?.files?.[0] ?? null);
  }

  /** Contrôles côté client (extension, taille) : simple confort, le serveur revérifie tout. */
  private accept(f: File | null): void {
    this.error.set('');
    this.result.set(null);
    if (!f) return this.file.set(null);
    if (!/\.json$/i.test(f.name)) { this.file.set(null); return this.error.set('Seuls les fichiers .json sont acceptés.'); }
    if (f.size > MAX_MB * 1024 * 1024) { this.file.set(null); return this.error.set(`Le fichier dépasse ${MAX_MB} Mo.`); }
    this.file.set(f);
  }

  protected async submit(): Promise<void> {
    const f = this.file();
    if (!f || !this.appId()) return;
    this.busy.set(true);
    this.error.set('');
    this.result.set(null);
    try {
      const form = new FormData();
      form.append('applicationId', this.appId());
      form.append('fichier', f, f.name);
      this.result.set(await this.api.upload<ImportSummary>('/scans', form));
      this.toast.ok('Import terminé.');
      this.file.set(null);
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  protected async downloadReport(scanId: string): Promise<void> {
    this.downloading.set(true);
    try {
      await this.api.downloadPdf(`/rapports/scans/${scanId}/pdf`);
    } catch (err) {
      this.toast.error(errorMessage(err));
    } finally {
      this.downloading.set(false);
    }
  }
}
