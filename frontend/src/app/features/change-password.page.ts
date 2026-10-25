import { ChangeDetectionStrategy, Component, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';
import { errorMessage } from '../core/api.service';
import { AuthService } from '../core/auth.service';
import { ToastService } from '../core/toast.service';
import { PasswordFieldComponent } from '../shared/password-field.component';
import { PasswordStrengthComponent } from '../shared/ui';
import { AuthLayoutComponent } from './auth-layout';

@Component({
  selector: 'app-change-password',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [AuthLayoutComponent, PasswordStrengthComponent, PasswordFieldComponent],
  template: `
    <app-auth-layout>
      <h1>Nouveau mot de passe</h1>
      @if (auth.user()?.mustChangePassword) {
        <p class="muted">Pour continuer, remplacez votre mot de passe temporaire.</p>
      }
      <form class="stack" (submit)="$event.preventDefault(); submit()">
        <div class="field">Mot de passe actuel
          <app-password-field [(value)]="current" name="current" label="Mot de passe actuel" autocomplete="current-password" />
        </div>
        <div class="field">Nouveau mot de passe
          <app-password-field [(value)]="next" name="next" label="Nouveau mot de passe" autocomplete="new-password" [minlength]="12" />
          <app-password-strength [value]="next()" />
        </div>
        <div class="field">Confirmation
          <app-password-field [(value)]="confirm" name="confirm" label="Confirmation du mot de passe" autocomplete="new-password" />
          @if (confirm() && !matches()) { <span class="field-error">Les mots de passe ne correspondent pas.</span> }
        </div>
        @if (error()) { <div class="alert error" role="alert">{{ error() }}</div> }
        <button class="btn primary" type="submit" [disabled]="busy() || !valid()">
          @if (busy()) { <span class="spinner"></span> } Enregistrer
        </button>
      </form>
    </app-auth-layout>
  `,
})
export class ChangePasswordPage {
  protected readonly auth = inject(AuthService);
  private readonly router = inject(Router);
  private readonly toast = inject(ToastService);
  protected readonly current = signal('');
  protected readonly next = signal('');
  protected readonly confirm = signal('');
  protected readonly busy = signal(false);
  protected readonly error = signal('');
  protected readonly matches = computed(() => this.next() === this.confirm());
  protected readonly valid = computed(() => this.current().length > 0 && this.next().length >= 12 && this.matches());

  protected async submit(): Promise<void> {
    if (!this.valid()) return;
    this.busy.set(true);
    this.error.set('');
    try {
      await this.auth.changePassword(this.current(), this.next());
      this.toast.ok('Mot de passe modifié.');
      await this.router.navigateByUrl('/tableau-de-bord');
    } catch (err) {
      this.error.set(errorMessage(err));
    } finally {
      this.busy.set(false);
      this.current.set('');
      this.next.set('');
      this.confirm.set('');
    }
  }
}
