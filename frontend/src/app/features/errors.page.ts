import { ChangeDetectionStrategy, Component } from '@angular/core';
import { RouterLink } from '@angular/router';

@Component({
  selector: 'app-forbidden',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <section class="glass card empty">
      <h1 style="font-size:3rem;color:var(--accent)">403</h1>
      <h2>Accès refusé</h2>
      <p>Votre rôle ne permet pas d'ouvrir cette page.</p>
      <a class="btn primary" routerLink="/tableau-de-bord">Retour au tableau de bord</a>
    </section>
  `,
})
export class ForbiddenPage {}

@Component({
  selector: 'app-not-found',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink],
  template: `
    <section class="glass card empty">
      <h1 style="font-size:3rem;color:var(--accent)">404</h1>
      <h2>Page introuvable</h2>
      <p>Cette page n'existe pas ou a été déplacée.</p>
      <a class="btn primary" routerLink="/tableau-de-bord">Retour au tableau de bord</a>
    </section>
  `,
})
export class NotFoundPage {}
