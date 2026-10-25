import { DatePipe } from '@angular/common';
import { ChangeDetectionStrategy, Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { ApiService, errorMessage } from '../core/api.service';
import { AuthService } from '../core/auth.service';
import { ROLE_LABEL, type Role, type User } from '../core/models';
import { ToastService } from '../core/toast.service';
import { IconComponent } from '../shared/ui';

@Component({
  selector: 'app-users',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, DatePipe, IconComponent],
  template: `
    <div class="page">
      <div class="page-header">
        <div><h1>Utilisateurs</h1><p>Créez les comptes analyste et décideur. Aucune inscription publique n'existe.</p></div>
        <button class="btn primary" type="button" (click)="creating.set(!creating())"><app-icon name="plus" />Nouveau compte</button>
      </div>

      @if (secret(); as s) {
        <div class="alert ok" role="status">
          <strong>Mot de passe temporaire de {{ s.email }} :</strong>
          <code style="user-select:all; margin-left:.5rem">{{ s.password }}</code>
          <div class="field-hint">Affiché une seule fois. La personne devra le changer à sa première connexion.</div>
          <button class="btn small" type="button" style="margin-top:.5rem" (click)="secret.set(null)">J'ai noté le mot de passe</button>
        </div>
      }

      @if (creating()) {
        <section class="glass card">
          <h2>Nouveau compte</h2>
          <form class="stack" (ngSubmit)="create()">
            <div class="form-grid">
              <label class="field">Nom<input name="name" required minlength="2" maxlength="100" [ngModel]="name()" (ngModelChange)="name.set($event)" /></label>
              <label class="field">Courriel<input name="email" type="email" required maxlength="254" [ngModel]="email()" (ngModelChange)="email.set($event)" /></label>
              <label class="field">Rôle
                <select name="role" [ngModel]="role()" (ngModelChange)="role.set($event)">
                  @for (r of roles; track r) { <option [value]="r">{{ roleLabel(r) }}</option> }
                </select>
              </label>
            </div>
            <div class="row"><button class="btn primary" type="submit" [disabled]="busy()">Créer</button></div>
          </form>
        </section>
      }

      <section class="glass card">
        @if (loading()) { <div class="empty"><span class="spinner"></span></div> }
        @else {
          <div class="table-wrap">
            <table>
              <thead><tr><th>Nom</th><th>Courriel</th><th>Rôle</th><th>État</th><th>Créé le</th><th></th></tr></thead>
              <tbody>
                @for (u of users(); track u.id) {
                  <tr>
                    <td><strong>{{ u.name }}</strong>@if (u.id === auth.user()?.id) { <span class="badge neutral" style="margin-left:.4rem">Vous</span> }</td>
                    <td>{{ u.email }}</td>
                    <td>
                      <select [attr.aria-label]="'Rôle de ' + u.name" style="width:auto" [ngModel]="u.role" (ngModelChange)="setRole(u, $event)">
                        @for (r of roles; track r) { <option [value]="r">{{ roleLabel(r) }}</option> }
                      </select>
                    </td>
                    <td>
                      @if (u.active) { <span class="badge ok">Actif</span> } @else { <span class="badge bad">Désactivé</span> }
                      @if (u.mustChangePassword) { <span class="badge warn" style="margin-left:.3rem">Mot de passe temporaire</span> }
                    </td>
                    <td>{{ u.createdAt | date: 'dd/MM/yyyy' }}</td>
                    <td>
                      <div class="row" style="justify-content:flex-end">
                        <button class="btn small" type="button" (click)="reset(u)">Réinitialiser</button>
                        <button class="btn small" [class.danger]="u.active" type="button" (click)="toggle(u)">{{ u.active ? 'Désactiver' : 'Réactiver' }}</button>
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
export class UsersPage {
  private readonly api = inject(ApiService);
  private readonly toast = inject(ToastService);
  protected readonly auth = inject(AuthService);

  protected readonly roles: Role[] = ['ANALYST', 'DECISION_MAKER', 'ADMIN'];
  protected readonly users = signal<User[]>([]);
  protected readonly loading = signal(true);
  protected readonly busy = signal(false);
  protected readonly creating = signal(false);
  protected readonly secret = signal<{ email: string; password: string } | null>(null);
  protected readonly name = signal('');
  protected readonly email = signal('');
  protected readonly role = signal<Role>('ANALYST');

  constructor() {
    void this.load();
  }

  protected roleLabel(r: Role): string { return ROLE_LABEL[r]; }

  private async load(): Promise<void> {
    this.loading.set(true);
    try { this.users.set(await this.api.get<User[]>('/utilisateurs')); }
    catch (err) { this.toast.error(errorMessage(err)); }
    finally { this.loading.set(false); }
  }

  protected async create(): Promise<void> {
    this.busy.set(true);
    try {
      const r = await this.api.post<{ user: User; temporaryPassword: string }>('/utilisateurs', {
        name: this.name().trim(), email: this.email().trim(), role: this.role(),
      });
      this.secret.set({ email: r.user.email, password: r.temporaryPassword });
      this.name.set(''); this.email.set(''); this.creating.set(false);
      await this.load();
    } catch (err) {
      this.toast.error(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  protected async setRole(u: User, role: Role): Promise<void> {
    if (role === u.role) return;
    try { await this.api.put(`/utilisateurs/${u.id}`, { role }); this.toast.ok('Rôle mis à jour.'); }
    catch (err) { this.toast.error(errorMessage(err)); }
    await this.load();
  }

  protected async toggle(u: User): Promise<void> {
    if (u.active && !confirm(`Désactiver le compte de ${u.name} ? Ses sessions seront fermées.`)) return;
    try { await this.api.put(`/utilisateurs/${u.id}`, { active: !u.active }); this.toast.ok(u.active ? 'Compte désactivé.' : 'Compte réactivé.'); }
    catch (err) { this.toast.error(errorMessage(err)); }
    await this.load();
  }

  protected async reset(u: User): Promise<void> {
    if (!confirm(`Réinitialiser le mot de passe de ${u.name} ?`)) return;
    try {
      const r = await this.api.post<{ temporaryPassword: string }>(`/utilisateurs/${u.id}/reinitialiser-mot-de-passe`);
      this.secret.set({ email: u.email, password: r.temporaryPassword });
      await this.load();
    } catch (err) {
      this.toast.error(errorMessage(err));
    }
  }
}
