import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, errorMessage } from '../core/api.service';
import { AuthService } from '../core/auth.service';
import { Application, EXPOSURE_LABEL, SENSITIVITY_LABEL, type Exposure, type Sensitivity } from '../core/models';
import { ToastService } from '../core/toast.service';
import { IconComponent } from '../shared/ui';

@Component({
  selector: 'app-applications',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, IconComponent],
  template: `
    <div class="page">
      <div class="page-header">
        <div><h1>Applications</h1><p>Contexte métier utilisé par la priorisation : exposition et sensibilité des données.</p></div>
        @if (auth.isAdmin()) {
          <button class="btn primary" type="button" (click)="startCreate()"><app-icon name="plus" />Nouvelle application</button>
        }
      </div>

      @if (editing(); as e) {
        <section class="glass card">
          <h2>{{ e.id ? "Modifier l'application" : 'Nouvelle application' }}</h2>
          <form class="stack" (ngSubmit)="save()">
            <div class="form-grid">
              <label class="field">Nom
                <input name="name" required minlength="2" maxlength="100" [ngModel]="e.name" (ngModelChange)="patch({ name: $event })" />
              </label>
              <label class="field">Exposition
                <select name="exposure" [ngModel]="e.exposure" (ngModelChange)="patch({ exposure: $event })">
                  @for (x of exposures; track x) { <option [value]="x">{{ exposureLabel(x) }}</option> }
                </select>
              </label>
              <label class="field">Sensibilité des données
                <select name="sens" [ngModel]="e.sensitivity" (ngModelChange)="patch({ sensitivity: $event })">
                  @for (x of sensitivities; track x) { <option [value]="x">{{ sensitivityLabel(x) }}</option> }
                </select>
              </label>
            </div>
            <label class="field">Description
              <textarea name="desc" maxlength="500" [ngModel]="e.description" (ngModelChange)="patch({ description: $event })"></textarea>
            </label>
            @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
            <div class="row">
              <button class="btn primary" type="submit" [disabled]="busy()">Enregistrer</button>
              <button class="btn ghost" type="button" (click)="editing.set(null)">Annuler</button>
            </div>
          </form>
        </section>
      }

      <section class="glass card">
        @if (loading()) { <div class="empty"><span class="spinner"></span></div> }
        @else if (apps().length === 0) { <div class="empty">Aucune application.</div> }
        @else {
          <div class="table-wrap">
            <table>
              <thead><tr><th>Nom</th><th>Exposition</th><th>Sensibilité</th><th class="num">Constats</th><th class="num">Imports</th><th></th></tr></thead>
              <tbody>
                @for (a of apps(); track a.id) {
                  <tr>
                    <td><strong>{{ a.name }}</strong>@if (a.description) { <div class="muted" style="font-size:.82rem">{{ a.description }}</div> }</td>
                    <td><span class="badge neutral">{{ exposureLabel(a.exposure) }}</span></td>
                    <td><span class="badge neutral">{{ sensitivityLabel(a.sensitivity) }}</span></td>
                    <td class="num">{{ a.findingsCount }}</td>
                    <td class="num">{{ a.scansCount }}</td>
                    <td>
                      <div class="row" style="justify-content:flex-end">
                        <button class="btn small" type="button" (click)="report(a)" [disabled]="downloading() === a.id">
                          <app-icon name="download" />Rapport PDF
                        </button>
                        @if (auth.isAdmin()) {
                          <button class="btn small" type="button" (click)="startEdit(a)">Modifier</button>
                          <button class="btn small danger" type="button" (click)="remove(a)">Supprimer</button>
                        }
                      </div>
                    </td>
                  </tr>
                }
              </tbody>
            </table>
          </div>
        }
      </section>
    </div>
  `,
})
export class ApplicationsPage {
  private readonly api = inject(ApiService);
  private readonly toast = inject(ToastService);
  protected readonly auth = inject(AuthService);

  protected readonly exposures: Exposure[] = ['PUBLIC', 'INTERNAL', 'RESTRICTED'];
  protected readonly sensitivities: Sensitivity[] = ['LOW', 'MEDIUM', 'HIGH'];
  protected readonly apps = signal<Application[]>([]);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly downloading = signal('');
  protected readonly editing = signal<Partial<Application> | null>(null);

  constructor() {
    void this.load();
  }

  protected exposureLabel(x: Exposure): string { return EXPOSURE_LABEL[x]; }
  protected sensitivityLabel(x: Sensitivity): string { return SENSITIVITY_LABEL[x]; }

  private async load(): Promise<void> {
    this.loading.set(true);
    try { this.apps.set(await this.api.get<Application[]>('/applications')); }
    catch (err) { this.toast.error(errorMessage(err)); }
    finally { this.loading.set(false); }
  }

  protected startCreate(): void { this.error.set(''); this.editing.set({ name: '', description: '', exposure: 'INTERNAL', sensitivity: 'MEDIUM' }); }
  protected startEdit(a: Application): void { this.error.set(''); this.editing.set({ ...a }); }
  protected patch(p: Partial<Application>): void { this.editing.update((e) => ({ ...e, ...p })); }

  protected async save(): Promise<void> {
    const e = this.editing();
    if (!e) return;
    this.busy.set(true);
    this.error.set('');
    const body = { name: e.name?.trim(), description: e.description?.trim() || undefined, exposure: e.exposure, sensitivity: e.sensitivity };
    try {
      if (e.id) await this.api.put(`/applications/${e.id}`, body);
      else await this.api.post('/applications', body);
      this.toast.ok('Application enregistrée.');
      this.editing.set(null);
      await this.load();
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  protected async remove(a: Application): Promise<void> {
    if (!confirm(`Supprimer « ${a.name} » ?`)) return;
    try {
      await this.api.delete(`/applications/${a.id}`);
      this.toast.ok('Application supprimée.');
      await this.load();
    } catch (err) {
      this.toast.error(errorMessage(err));
    }
  }

  protected async report(a: Application): Promise<void> {
    this.downloading.set(a.id);
    try { await this.api.downloadPdf(`/rapports/applications/${a.id}/pdf`); this.toast.ok('Rapport PDF téléchargé.'); }
    catch (err) { this.toast.error(errorMessage(err)); }
    finally { this.downloading.set(''); }
  }
}
