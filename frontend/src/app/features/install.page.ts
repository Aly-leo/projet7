import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { ApiService, errorMessage } from '../core/api.service';
import { markInstalled } from '../core/guards';
import { ToastService } from '../core/toast.service';
import { PasswordFieldComponent } from '../shared/password-field.component';
import { PasswordStrengthComponent } from '../shared/ui';
import { AuthLayoutComponent } from './auth-layout';

@Component({
  selector: 'app-install',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, AuthLayoutComponent, PasswordStrengthComponent, PasswordFieldComponent],
  template: `
    <app-auth-layout>
      <h1>Installation</h1>
      <p class="muted">Aucun compte n'existe. Créez le compte administrateur.</p>
      <form class="stack" (ngSubmit)="submit()">
        <label class="field">Nom
          <input type="text" name="name" autocomplete="name" required minlength="2" maxlength="100" [(ngModel)]="name" />
        </label>
        <label class="field">Courriel
          <input type="email" name="email" autocomplete="username" required maxlength="254" [(ngModel)]="email" />
        </label>
        <div class="field">Mot de passe
          <app-password-field [(value)]="password" name="password" label="Mot de passe" autocomplete="new-password" [minlength]="12" />
          <app-password-strength [value]="password()" />
        </div>
        <div class="field">Confirmation
          <app-password-field [(value)]="confirm" name="confirm" label="Confirmation du mot de passe" autocomplete="new-password" />
          @if (confirm() && !matches()) { <span class="field-error">Les mots de passe ne correspondent pas.</span> }
        </div>
        @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
        <button class="btn primary" type="submit" [disabled]="busy() || !valid()">
          @if (busy()) { <span class="spinner"></span> } Créer le compte administrateur
        </button>
      </form>
    </app-auth-layout>
  `,
})
export class InstallPage {
  private readonly api = inject(ApiService);
  private readonly router = inject(Router);
  private readonly toast = inject(ToastService);
  protected readonly name = signal('');
  protected readonly email = signal('');
  protected readonly password = signal('');
  protected readonly confirm = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly matches = computed(() => this.password() === this.confirm());
  protected readonly valid = computed(
    () => this.name().trim().length >= 2 && this.email().includes('@') && this.password().length >= 12 && this.matches(),
  );

  protected async submit(): Promise<void> {
    if (!this.valid()) return;
    this.busy.set(true);
    this.error.set('');
    try {
      await this.api.post('/installation', {
        nom: this.name().trim(),
        courriel: this.email().trim(),
        motDePasse: this.password(),
      });
      markInstalled();
      this.toast.ok('Compte administrateur créé. Vous pouvez vous connecter.');
      await this.router.navigateByUrl('/connexion');
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}
