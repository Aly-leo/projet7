import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, errorMessage } from '../core/api.service';
import { AuditEntry, Page, User } from '../core/models';

@Component({
  selector: 'app-audit',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, DatePipe],
  styles: `
    .filters { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 0.6rem; }
    .meta { max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  `,
  template: `
    <div class="page">
      <div class="page-header"><div><h1>Journal d'audit</h1><p>En ajout seul : consultation uniquement. Aucun secret ni contenu de rapport n'y figure.</p></div></div>
      <section class="glass card">
        <div class="filters">
          <select aria-label="Utilisateur" [ngModel]="userId()" (ngModelChange)="userId.set($event); reset()">
            <option value="">Tous les utilisateurs</option>
            @for (u of users(); track u.id) { <option [value]="u.id">{{ u.name }}</option> }
          </select>
          <input aria-label="Action" placeholder="Action (ex. SCAN_IMPORT)" maxlength="60" [ngModel]="action()" (ngModelChange)="action.set($event); reset()" />
          <select aria-label="Résultat" [ngModel]="outcome()" (ngModelChange)="outcome.set($event); reset()">
            <option value="">Tous les résultats</option>
            <option value="SUCCESS">Réussite</option><option value="DENIED">Refus</option><option value="FAILURE">Échec</option>
          </select>
          <input type="date" aria-label="Depuis le" [ngModel]="from()" (ngModelChange)="from.set($event); reset()" />
          <input type="date" aria-label="Jusqu'au" [ngModel]="to()" (ngModelChange)="to.set($event); reset()" />
        </div>
      </section>
      @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
      <section class="glass card">
        @if (data(); as d) {
          @if (d.items.length === 0) { <div class="empty">Aucune entrée.</div> }
          @else {
            <div class="table-wrap">
              <table>
                <thead><tr><th>Date</th><th>Utilisateur</th><th>Action</th><th>Ressource</th><th>Résultat</th><th>IP</th><th>Détails</th></tr></thead>
                <tbody>
                  @for (e of d.items; track e.id) {
                    <tr>
                      <td style="white-space:nowrap">{{ e.createdAt | date: 'dd/MM/yyyy HH:mm:ss' }}</td>
                      <td>{{ userName(e.userId) }}</td>
                      <td class="mono">{{ e.action }}</td>
                      <td class="mono">{{ e.resourceType ?? '–' }}</td>
                      <td>
                        <span class="badge" [class.ok]="e.outcome === 'SUCCESS'" [class.warn]="e.outcome === 'DENIED'" [class.bad]="e.outcome === 'FAILURE'">
                          {{ e.outcome === 'SUCCESS' ? 'Réussite' : e.outcome === 'DENIED' ? 'Refus' : 'Échec' }}
                        </span>
                      </td>
                      <td class="mono">{{ e.ip ?? '–' }}</td>
                      <td class="mono meta" [title]="json(e.metadata)">{{ json(e.metadata) }}</td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
            <div class="row between" style="margin-top:.8rem">
              <span class="muted">{{ d.total }} entrée(s) · page {{ page() }} / {{ pages() }}</span>
              <div class="row">
                <button class="btn small" type="button" (click)="go(-1)" [disabled]="page() <= 1">Précédent</button>
                <button class="btn small" type="button" (click)="go(1)" [disabled]="page() >= pages()">Suivant</button>
              </div>
            </div>
          }
        } @else if (!error()) { <div class="empty"><span class="spinner"></span></div> }
      </section>
    </div>
  `,
})
export class AuditPage {
  private readonly api = inject(ApiService);
  protected readonly data = signal<Page<AuditEntry> | null>(null);
  protected readonly users = signal<User[]>([]);
  protected readonly error = signal('');
  protected readonly userId = signal('');
  protected readonly action = signal('');
  protected readonly outcome = signal('');
  protected readonly from = signal('');
  protected readonly to = signal('');
  protected readonly page = signal(1);
  protected readonly pages = computed(() => Math.max(1, Math.ceil((this.data()?.total ?? 0) / 50)));
  private timer?: ReturnType<typeof setTimeout>;

  constructor() {
    this.api.get<User[]>('/utilisateurs').then((u) => this.users.set(u)).catch(() => undefined);
    void this.load();
  }

  protected userName(id: string | null): string { return id ? (this.users().find((u) => u.id === id)?.name ?? id.slice(0, 8)) : '–'; }
  protected json(m: unknown): string { return m ? JSON.stringify(m) : '–'; }
  protected reset(): void { this.page.set(1); clearTimeout(this.timer); this.timer = setTimeout(() => void this.load(), 250); }
  protected go(d: number): void { this.page.update((p) => p + d); void this.load(); }

  private async load(): Promise<void> {
    this.error.set('');
    try {
      this.data.set(await this.api.get<Page<AuditEntry>>('/audit', {
        userId: this.userId() || undefined,
        action: this.action().trim() || undefined,
        outcome: this.outcome() || undefined,
        from: this.from() ? new Date(this.from()).toISOString() : undefined,
        to: this.to() ? new Date(this.to() + 'T23:59:59').toISOString() : undefined,
        page: this.page(),
        pageSize: 50,
      }));
    } catch (err) {
      this.error.set(errorMessage(err));
    }
  }
}
