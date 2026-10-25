import { ChangeDetectionStrategy, Component, input, model, signal } from '@angular/core';
import { IconComponent } from './ui';

/** Champ de mot de passe avec bouton pour afficher ou masquer la saisie. */
@Component({
  selector: 'app-password-field',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [IconComponent],
  styles: `
    :host { display: block; }
    .wrap { position: relative; }
    input { padding-right: 2.8rem; }
    button {
      position: absolute; top: 50%; right: 0.35rem; transform: translateY(-50%); display: grid; place-items: center;
      width: 2rem; height: 2rem; border: 0; border-radius: 8px; background: transparent; color: var(--text-soft); cursor: pointer;
    }
    button:hover { background: var(--accent-soft); color: var(--text); }
  `,
  template: `
    <div class="wrap">
      <input
        [type]="visible() ? 'text' : 'password'"
        [attr.name]="name()"
        [attr.autocomplete]="autocomplete()"
        [attr.minlength]="minlength()"
        [attr.maxlength]="128"
        [attr.aria-label]="label()"
        [value]="value()"
        (input)="value.set($any($event.target).value)"
        required
      />
      <button type="button" (click)="visible.set(!visible())" [attr.aria-label]="visible() ? 'Masquer le mot de passe' : 'Afficher le mot de passe'" [attr.aria-pressed]="visible()">
        <app-icon [name]="visible() ? 'eye-off' : 'eye'" />
      </button>
    </div>
  `,
})
export class PasswordFieldComponent {
  readonly value = model('');
  readonly name = input('password');
  readonly label = input('Mot de passe');
  readonly autocomplete = input('current-password');
  readonly minlength = input<number | null>(null);
  protected readonly visible = signal(false);
}
