import { ChangeDetectionStrategy, Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';
import { ThemeService } from '../core/theme.service';
import { IconComponent } from '../shared/ui';

interface Feature { icon: string; title: string; text: string }

/** Page d'accueil publique : présente le projet puis invite à se connecter. */
@Component({
  selector: 'app-landing',
  changeDetection: ChangeDetectionStrategy.OnPush,
  imports: [RouterLink, IconComponent],
  styles: `
    :host { display: block; min-height: 100vh; }
    .wrap { width: min(1120px, 100% - 2rem); margin: 0 auto; }
    header.top { display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 1rem 0; }
    .brand { display: flex; align-items: center; gap: 0.65rem; font-weight: 700; color: var(--accent-strong); }
    .logo { width: 38px; height: 38px; border-radius: 12px; display: grid; place-items: center; color: #fff;
      background: linear-gradient(135deg, #6aa5e0, #29375f); box-shadow: 0 8px 20px rgba(58, 103, 157, 0.35); }
    .hero { display: grid; grid-template-columns: 1.05fr 0.95fr; gap: 2.2rem; align-items: center; padding: 3.2rem 0 2.6rem; }
    .eyebrow { display: inline-block; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
      color: var(--accent); background: var(--accent-soft); padding: 0.3rem 0.8rem; border-radius: 999px; margin-bottom: 1rem; }
    h1.title { font-size: clamp(2rem, 4.6vw, 3.2rem); line-height: 1.08; letter-spacing: -0.03em; margin-bottom: 1.1rem; }
    h1.title em { font-style: normal; background: linear-gradient(120deg, var(--accent), var(--accent-strong)); -webkit-background-clip: text; background-clip: text; color: transparent; }
    .lead { font-size: 1.1rem; color: var(--text-soft); max-width: 34rem; margin-bottom: 1.6rem; }
    .cta { display: flex; gap: 0.7rem; flex-wrap: wrap; }
    .btn.big { padding: 0.8rem 1.5rem; font-size: 1rem; }
    .preview { padding: 1.2rem; display: flex; flex-direction: column; gap: 0.9rem; }
    .preview .kpis { display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.6rem; }
    .kpi { padding: 0.7rem 0.5rem; border-radius: 12px; text-align: center; background: var(--glass-strong); border: 1px solid var(--glass-edge); }
    .kpi b { display: block; font-size: 1.5rem; letter-spacing: -0.02em; }
    .kpi span { font-size: 0.72rem; color: var(--text-soft); font-weight: 600; }
    .bars { display: flex; flex-direction: column; gap: 0.5rem; }
    .bar { display: grid; grid-template-columns: 90px 1fr 34px; align-items: center; gap: 0.6rem; font-size: 0.82rem; color: var(--text-soft); }
    .bar i { height: 10px; border-radius: 99px; background: var(--glass-edge); position: relative; overflow: hidden; display: block; }
    .bar i::after { content: ''; position: absolute; inset: 0 auto 0 0; width: var(--w); border-radius: 99px; background: var(--c); }
    .row-mock { display: flex; align-items: center; gap: 0.6rem; padding: 0.6rem 0.7rem; border-radius: 10px; background: var(--glass-strong); border: 1px solid var(--glass-edge); font-size: 0.85rem; }
    section.block { padding: 2.4rem 0; }
    section.block > h2 { font-size: clamp(1.4rem, 3vw, 1.9rem); margin-bottom: 0.4rem; letter-spacing: -0.02em; }
    section.block > p.sub { color: var(--text-soft); margin-bottom: 1.5rem; max-width: 40rem; }
    .features { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; }
    .feature { padding: 1.3rem; }
    .feature .ico { width: 42px; height: 42px; border-radius: 13px; display: grid; place-items: center; margin-bottom: 0.8rem; color: var(--accent); background: var(--accent-soft); }
    .feature h3 { margin-bottom: 0.3rem; }
    .feature p { margin: 0; color: var(--text-soft); font-size: 0.93rem; }
    .steps { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; counter-reset: step; }
    .step { padding: 1.3rem; position: relative; }
    .step::before { counter-increment: step; content: counter(step); display: grid; place-items: center; width: 30px; height: 30px; border-radius: 50%;
      font-weight: 700; color: #fff; background: linear-gradient(135deg, #5b94cc, #2c4a7e); margin-bottom: 0.7rem; }
    .step p { margin: 0.3rem 0 0; color: var(--text-soft); font-size: 0.93rem; }
    .roles { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1rem; }
    .role { padding: 1.2rem 1.3rem; }
    .role p { margin: 0.3rem 0 0; color: var(--text-soft); font-size: 0.92rem; }
    .final { padding: 2.2rem 1.6rem; text-align: center; margin: 1rem 0 2.5rem; }
    .final h2 { margin-bottom: 0.5rem; }
    .final p { color: var(--text-soft); margin-bottom: 1.2rem; }
    footer { padding: 1.4rem 0 2.2rem; text-align: center; color: var(--text-faint); font-size: 0.85rem; }
    @media (max-width: 860px) { .hero { grid-template-columns: 1fr; padding-top: 1.6rem; } }
  `,
  template: `
    <div class="wrap">
      <header class="top">
        <div class="brand"><span class="logo"><app-icon name="shield" /></span>Priorisation des vulnérabilités</div>
        <div class="row">
          <button class="btn ghost small" type="button" (click)="theme.toggle()" [attr.aria-label]="theme.theme() === 'dark' ? 'Passer au thème clair' : 'Passer au thème sombre'">
            <app-icon [name]="theme.theme() === 'dark' ? 'sun' : 'moon'" />
          </button>
          <a class="btn small" routerLink="/connexion">Se connecter</a>
        </div>
      </header>

      <section class="hero">
        <div>
          <span class="eyebrow">Sécurité des applications Web · OWASP</span>
          <h1 class="title">Corrigez d'abord ce qui <em>compte vraiment</em>.</h1>
          <p class="lead">
            Un audit produit des dizaines de constats, mais l'équipe n'a le temps d'en corriger qu'une partie.
            Cette application classe chaque vulnérabilité de P1 à P4 selon sa gravité, l'exposition de l'application,
            la sensibilité de ses données et sa probabilité d'exploitation.
          </p>
          <div class="cta">
            <a class="btn primary big" routerLink="/connexion">Se connecter</a>
            <a class="btn big" href="#fonctionnement">Comment ça marche</a>
          </div>
        </div>

        <div class="preview glass" aria-hidden="true">
          <div class="kpis">
            <div class="kpi"><b style="color: var(--p1)">6</b><span>P1</span></div>
            <div class="kpi"><b style="color: var(--p2)">27</b><span>P2</span></div>
            <div class="kpi"><b style="color: var(--p3)">18</b><span>P3</span></div>
            <div class="kpi"><b style="color: var(--p4)">7</b><span>P4</span></div>
          </div>
          <div class="bars">
            <div class="bar"><span>Juice Shop</span><i style="--w: 78%; --c: var(--p1)"></i><span>10</span></div>
            <div class="bar"><span>Portail</span><i style="--w: 100%; --c: var(--accent)"></i><span>48</span></div>
          </div>
          <div class="row-mock"><span class="badge P1">P1</span>SQL Injection</div>
          <div class="row-mock"><span class="badge P2">P2</span>Absence de jetons anti-CSRF</div>
          <div class="row-mock"><span class="badge P3">P3</span>En-tête CSP absent</div>
        </div>
      </section>

      <section class="block" id="fonctionnement">
        <h2>Comment ça marche</h2>
        <p class="sub">Du rapport brut à la liste d'actions, en quatre étapes.</p>
        <div class="steps">
          <div class="step glass"><h3>Importer</h3><p>Déposez un rapport OWASP ZAP (JSON). Il est contrôlé, nettoyé et dédoublonné avant toute analyse.</p></div>
          <div class="step glass"><h3>Prioriser</h3><p>Chaque constat reçoit une probabilité d'exploitation, une priorité P1 à P4 et une explication.</p></div>
          <div class="step glass"><h3>Traiter</h3><p>L'analyste ajuste la priorité, assigne la correction et suit son avancement, étape par étape.</p></div>
          <div class="step glass"><h3>Décider</h3><p>Le décideur consulte un tableau de bord agrégé et télécharge un rapport PDF.</p></div>
        </div>
      </section>

      <section class="block">
        <h2>Ce que vous y trouvez</h2>
        <p class="sub">Un outil sobre, pensé pour les équipes de sécurité comme pour les décideurs.</p>
        <div class="features">
          @for (f of features; track f.title) {
            <article class="feature glass">
              <div class="ico"><app-icon [name]="f.icon" /></div>
              <h3>{{ f.title }}</h3>
              <p>{{ f.text }}</p>
            </article>
          }
        </div>
      </section>

      <section class="block">
        <h2>Trois profils, trois vues</h2>
        <p class="sub">Les droits sont vérifiés côté serveur à chaque requête.</p>
        <div class="roles">
          <div class="role glass"><h3>Administrateur</h3><p>Gère les comptes et les applications, relance les analyses, consulte le journal d'audit.</p></div>
          <div class="role glass"><h3>Analyste</h3><p>Importe les rapports, examine les constats, annote les priorités et suit les corrections.</p></div>
          <div class="role glass"><h3>Décideur</h3><p>Voit uniquement des indicateurs agrégés : aucun détail technique n'est exposé.</p></div>
        </div>
      </section>

      <section class="final glass">
        <h2>Prêt à explorer ?</h2>
        <p>L'accès se fait sur invitation : demandez vos identifiants à l'administrateur.</p>
        <a class="btn primary big" routerLink="/connexion">Se connecter</a>
      </section>

      <footer>Projet 7 · Master 2 · Sécurité des applications Web avec OWASP</footer>
    </div>
  `,
})
export class LandingPage {
  protected readonly theme = inject(ThemeService);
  protected readonly features: Feature[] = [
    { icon: 'upload', title: 'Import sécurisé', text: 'Rapports ZAP validés, texte assaini, doublons fusionnés. Rien n\'est exécuté ni interprété.' },
    { icon: 'dashboard', title: 'Tableau de bord', text: 'Répartition par priorité, par application, par statut et par gravité, avec filtres.' },
    { icon: 'model', title: 'Priorité expliquée', text: 'Chaque priorité est accompagnée des facteurs qui l\'ont fait monter ou baisser.' },
    { icon: 'list', title: 'Suivi de correction', text: 'Un cycle de vie strict : validé, assigné, en correction, vérifié, clos.' },
    { icon: 'report', title: 'Rapports PDF', text: 'Rapport d\'import, d\'application ou synthèse agrégée, générés à la demande.' },
    { icon: 'audit', title: 'Journal d\'audit', text: 'Les actions sensibles, réussies ou refusées, sont enregistrées en ajout seul.' },
  ];
}
