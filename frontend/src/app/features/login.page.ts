import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { Router } from '@angular/router';
import { errorMessage } from '../core/api.service';
import { AuthService } from '../core/auth.service';
import { PasswordFieldComponent } from '../shared/password-field.component';
import { AuthLayoutComponent } from './auth-layout';

@Component({
  selector: 'app-login',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [FormsModule, AuthLayoutComponent, PasswordFieldComponent],
  template: `
    <app-auth-layout>
      <h1>Connexion</h1>
      <p class="muted">Accédez à la priorisation de vos vulnérabilités.</p>
      <form class="stack" (ngSubmit)="submit()">
        <label class="field">Courriel
          <input type="email" name="email" autocomplete="username" required maxlength="254" [(ngModel)]="email" />
        </label>
        <div class="field">Mot de passe
          <app-password-field [(value)]="password" name="password" label="Mot de passe" autocomplete="current-password" />
        </div>
        @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
        <button class="btn primary" type="submit" [disabled]="busy() || !valid()">
          @if (busy()) { <span class="spinner"></span> } Se connecter
        </button>
      </form>
    </app-auth-layout>
  `,
})
export class LoginPage {
  private readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  protected readonly email = signal('');
  protected readonly password = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly valid = computed(() => this.email().includes('@') && this.password().length > 0);

  protected async submit(): Promise<void> {
    if (!this.valid()) return;
    this.busy.set(true);
    this.error.set('');
    try {
      const user = await this.auth.login(this.email().trim(), this.password());
      await this.router.navigateByUrl(user.mustChangePassword ? '/changer-mot-de-passe' : '/tableau-de-bord');
    } catch (err) {
      // Message générique côté serveur : identique pour un courriel inconnu et un mauvais mot de passe.
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
      this.password.set('');
    }
  }
}
