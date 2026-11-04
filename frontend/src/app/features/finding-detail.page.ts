import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { RouterLink } from '@angular/router';
import { ApiService, errorMessage } from '../core/api.service';
import {
  EXPOSURE_LABEL, FEATURE_LABEL, FindingDetail, SENSITIVITY_LABEL, SEVERITY_LABEL, STATUS_LABEL, TRANSITIONS,
  type CorrectionStatus, type Priority, type User,
} from '../core/models';
import { ToastService } from '../core/toast.service';
import { PriorityComponent } from '../shared/ui';

@Component({
  selector: 'app-finding-detail',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, RouterLink, DatePipe, PriorityComponent],
  styles: `
    .desc { white-space: pre-line; }
    .urls { margin: 0; padding-left: 1.1rem; font-size: 0.85rem; word-break: break-all; }
    .contrib { display: grid; grid-template-columns: 190px 1fr 56px; align-items: center; gap: 0.6rem; font-size: 0.86rem; padding: 0.25rem 0; }
    .track { position: relative; height: 10px; border-radius: 99px; background: var(--glass-edge); }
    .track::after { content: ''; position: absolute; left: 50%; top: -3px; bottom: -3px; width: 1px; background: var(--text-faint); }
    .fill { position: absolute; top: 0; bottom: 0; border-radius: 99px; }
    .fill.pos { left: 50%; background: linear-gradient(90deg, var(--accent), color-mix(in srgb, var(--accent) 60%, #fff)); }
    .fill.neg { right: 50%; background: var(--warning); }
    @media (max-width: 640px) { .contrib { grid-template-columns: 1fr 70px; } .contrib .track { grid-column: 1 / -1; order: 3; } }
  `,
  template: `
    <div class="page">
      <a routerLink="/constats">← Retour aux constats</a>
      @if (error() && !f()) { <div class="alert error" role="alert">{{ error() }}</div> }

      @if (f(); as d) {
        <div class="page-header">
          <div>
            <h1>{{ d.title }}</h1>
            <p>{{ d.application.name }} · {{ sev(d.severity) }} · {{ d.cveId ?? (d.cweId ? 'CWE-' + d.cweId : 'sans CWE') }}</p>
          </div>
          <div class="row"><app-priority [value]="d.priority" /></div>
        </div>

        <div class="grid cols-2">
          <section class="glass card">
            <h2>Informations</h2>
            <dl class="kv">
              <dt>Description</dt><dd class="desc">{{ d.description || '–' }}</dd>
              <dt>Solution</dt><dd class="desc">{{ d.solution || '–' }}</dd>
              <dt>Confiance ZAP</dt><dd>{{ d.confidence ?? '–' }}</dd>
              <dt>Instances</dt><dd>{{ d.instancesCount }}</dd>
              <dt>Exposition / sensibilité</dt><dd>{{ expo(d.application.exposure) }} · {{ sens(d.application.sensitivity) }}</dd>
              <dt>Vu pour la dernière fois</dt><dd>{{ d.lastSeenAt | date: 'dd/MM/yyyy HH:mm' }}</dd>
              <dt>URL d'exemple</dt>
              <dd>
                @if (d.sampleUrls?.length) {
                  <ul class="urls">@for (u of d.sampleUrls!.slice(0, 10); track u) { <li>{{ u }}</li> }</ul>
                } @else { – }
              </dd>
            </dl>
          </section>

          <section class="glass card">
            <h2>Prédictions</h2>
            <dl class="kv">
              <dt>Probabilité d'exploitation (M1)</dt>
              <dd>{{ m1Display() }}</dd>
              <dt>Priorité (M2)</dt>
              <dd><app-priority [value]="d.modelPriority" /></dd>
              <dt>Probabilité calibrée (M2)</dt>
              <dd>{{ d.predictions.m2 ? (d.predictions.m2.probability * 100).toFixed(0) + ' %' : '–' }}</dd>
              <dt>Origine de M1</dt>
              <dd>{{ m1Origin() }}</dd>
              <dt>Origine de M2</dt>
              <dd>Simulé ({{ d.predictions.m2?.provider === 'anthropic' ? 'API Claude' : 'règles' }}) · {{ d.predictions.m2?.version }}</dd>
            </dl>
            <h3 style="margin:1rem 0 .4rem">Explication</h3>
            @for (c of d.predictions.m2?.explanation ?? []; track c.feature) {
              <div class="contrib">
                <span>{{ feature(c.feature) }}</span>
                <span class="track" role="img" [attr.aria-label]="feature(c.feature) + ' : ' + c.contribution.toFixed(2)">
                  <span class="fill" [class.pos]="c.contribution >= 0" [class.neg]="c.contribution < 0" [style.width.%]="width(c.contribution)"></span>
                </span>
                <span class="mono" style="text-align:right">{{ c.contribution >= 0 ? '+' : '' }}{{ c.contribution.toFixed(2) }}</span>
              </div>
            } @empty { <span class="muted">Aucune explication disponible.</span> }
          </section>
        </div>

        <div class="grid cols-2">
          <section class="glass card">
            <h2>Annotation d'une priorité</h2>
            <form class="stack" (ngSubmit)="annotate()">
              <label class="field">Priorité retenue
                <select name="prio" required [ngModel]="prio()" (ngModelChange)="prio.set($event)">
                  <option value="" disabled>Choisir…</option>
                  @for (p of ['P1', 'P2', 'P3', 'P4']; track p) { <option [value]="p">{{ p }}</option> }
                </select>
              </label>
              <label class="field">Commentaire
                <textarea name="cmt" maxlength="1000" [ngModel]="comment()" (ngModelChange)="comment.set($event)"></textarea>
              </label>
              <div class="row"><button class="btn primary" type="submit" [disabled]="!prio() || busy()">Enregistrer l'annotation</button></div>
            </form>
            @if (d.annotations.length) {
              <h3 style="margin:1rem 0 .4rem">Historique</h3>
              @for (a of d.annotations; track a.id) {
                <div class="row" style="margin-bottom:.4rem">
                  <app-priority [value]="a.priority" />
                  <span class="muted">{{ a.annotator.name }} · {{ a.createdAt | date: 'dd/MM/yyyy HH:mm' }}</span>
                  @if (a.comment) { <span>— {{ a.comment }}</span> }
                </div>
              }
            }
          </section>

          <section class="glass card">
            <h2>Correction</h2>
            @if (d.correction; as c) {
              <form class="stack" (ngSubmit)="saveCorrection()">
                <label class="field">Statut
                  <select name="status" [ngModel]="status()" (ngModelChange)="status.set($event)">
                    <option [value]="c.status">{{ statusLabel(c.status) }} (actuel)</option>
                    @for (s of next(); track s) { <option [value]="s">{{ statusLabel(s) }}</option> }
                  </select>
                  <span class="field-hint">Seules les transitions valides sont proposées.</span>
                </label>
                <label class="field">Assigné à
                  <select name="assignee" [ngModel]="assignee()" (ngModelChange)="assignee.set($event)">
                    <option value="">Personne</option>
                    @for (u of assignees(); track u.id) { <option [value]="u.id">{{ u.name }}</option> }
                  </select>
                </label>
                <label class="field">Échéance
                  <input type="date" name="due" [ngModel]="due()" (ngModelChange)="due.set($event)" />
                </label>
                <label class="field">Commentaire
                  <textarea name="ccmt" maxlength="1000" [ngModel]="corrComment()" (ngModelChange)="corrComment.set($event)"></textarea>
                </label>
                <div class="row"><button class="btn primary" type="submit" [disabled]="busy()">Mettre à jour</button></div>
              </form>
            }
          </section>
        </div>
      } @else if (!error()) {
        <div class="empty"><span class="spinner"></span></div>
      }
    </div>
  `,
})
export class FindingDetailPage {
  readonly id = input.required<string>();

  private readonly api = inject(ApiService);
  private readonly toast = inject(ToastService);

  protected readonly f = signal<FindingDetail | null>(null);
  protected readonly error = signal('');
  protected readonly busy = signal(false);
  protected readonly assignees = signal<Pick<User, 'id' | 'name'>[]>([]);
  protected readonly prio = signal('');
  protected readonly comment = signal('');
  protected readonly status = signal('');
  protected readonly assignee = signal('');
  protected readonly due = signal('');
  protected readonly corrComment = signal('');
  /** M1 entraîné : version et origine de la valeur (modèle, taux historique du CWE ou prévalence globale) ; sinon simulation. */
  protected readonly m1Origin = computed(() => {
    const p = this.f()?.predictions.m1;
    if (!p) return '–';
    if (p.simulated) return `Simulé (${p.provider === 'anthropic' ? 'API Claude' : 'règles'})`;
    const src = (p.explanation as { source?: string } | null)?.source;
    const label = src === 'm1' ? 'prédiction du modèle' : src === 'cwe_rate' ? 'taux historique du CWE' : src === 'prior' ? 'prévalence globale (aucune information)' : 'valeur du modèle';
    return `Modèle entraîné ${p.version} · ${label}`;
  });
  /**
   * Probabilité M1 lisible. Le modèle entraîné donne de vraies probabilités très faibles (≈ 0,05 % en moyenne) : on affiche des décimales
   * adaptées et le risque relatif à la moyenne, plus parlant. Un CVE déjà dans KEV est signalé.
   */
  protected readonly m1Display = computed(() => {
    const p = this.f()?.predictions.m1;
    if (!p) return '–';
    const pct = p.probability * 100;
    const text = (pct >= 10 ? pct.toFixed(0) : pct >= 1 ? pct.toFixed(1) : pct.toFixed(2)) + ' %';
    if (p.simulated) return text;
    const x = p.explanation as { relativeRisk?: number | null; alreadyInKev?: boolean | null } | null;
    const parts = [text];
    if (x?.relativeRisk != null) parts.push(`${x.relativeRisk >= 10 ? x.relativeRisk.toFixed(0) : x.relativeRisk.toFixed(1)}× la moyenne`);
    if (x?.alreadyInKev) parts.push('déjà dans le catalogue KEV');
    return parts.join(' · ');
  });
  protected readonly next = computed(() => {
    const s = this.f()?.correction?.status;
    return s ? TRANSITIONS[s] : [];
  });

  constructor() {
    queueMicrotask(() => void this.load());
  }

  protected sev(n: number): string { return SEVERITY_LABEL[n] ?? String(n); }
  protected expo(e: keyof typeof EXPOSURE_LABEL): string { return EXPOSURE_LABEL[e]; }
  protected sens(e: keyof typeof SENSITIVITY_LABEL): string { return SENSITIVITY_LABEL[e]; }
  protected statusLabel(s: CorrectionStatus): string { return STATUS_LABEL[s]; }
  protected feature(k: string): string { return FEATURE_LABEL[k] ?? k; }
  protected width(v: number): number { return Math.min(100, Math.abs(v) * 100); }

  private async load(): Promise<void> {
    try {
      const d = await this.api.get<FindingDetail>(`/constats/${this.id()}`);
      this.f.set(d);
      this.status.set(d.correction?.status ?? '');
      this.assignee.set(d.correction?.assigneeId ?? '');
      this.due.set(d.correction?.dueDate ? d.correction.dueDate.slice(0, 10) : '');
      this.corrComment.set(d.correction?.comment ?? '');
      if (this.assignees().length === 0) {
        this.api.get<Pick<User, 'id' | 'name'>[]>('/utilisateurs/assignables').then((u) => this.assignees.set(u)).catch(() => undefined);
      }
    } catch (err) {
      this.error.set(errorMessage(err));
    }
  }

  protected async annotate(): Promise<void> {
    this.busy.set(true);
    try {
      await this.api.put(`/constats/${this.id()}/priorite`, { priority: this.prio() as Priority, comment: this.comment().trim() || undefined });
      this.toast.ok('Annotation enregistrée.');
      this.prio.set('');
      this.comment.set('');
      await this.load();
    } catch (err) {
      this.toast.error(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  protected async saveCorrection(): Promise<void> {
    const cur = this.f()?.correction;
    if (!cur) return;
    this.busy.set(true);
    try {
      await this.api.put(`/constats/${this.id()}/correction`, {
        ...(this.status() !== cur.status && { status: this.status() }),
        assigneeId: this.assignee() || null,
        dueDate: this.due() ? new Date(this.due()).toISOString() : null,
        comment: this.corrComment(),
      });
      this.toast.ok('Correction mise à jour.');
      await this.load();
    } catch (err) {
      this.toast.error(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}
