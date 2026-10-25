# Sécurité : correspondance exigences → mesures → vérification

Référentiels : OWASP Top 10 et ASVS (niveau 2 visé). Chaque ligne indique où la mesure est mise en œuvre et quel test la vérifie.
Un prototype qui applique ces mesures **réduit** les risques, il ne garantit pas l'absence de vulnérabilités : un audit externe reste nécessaire avant tout usage réel.

## Contrôle d'accès (A01)

| Exigence | Mesure | Vérification |
|---|---|---|
| Refus par défaut | Gardes globales : authentification, puis rôles. Une route sans `@Roles` est refusée (403) sauf `@Public()` | `backend/src/common/guards.ts` ; `test/access.e2e-spec.ts` (matrice route × rôle, 401 sans jeton) |
| Rôle issu du serveur | Le rôle et l'état du compte sont relus en base à chaque requête | `access.e2e-spec.ts` : « ignore le rôle envoyé par le client » |
| Décideur : agrégats seulement | `DashboardService.aggregate` ne charge aucun titre, URL ni identifiant ; la synthèse PDF est calculée côté serveur | `findings.e2e-spec.ts`, `reports.e2e-spec.ts` (analyse du texte du PDF) |
| Pas d'assignation de masse | `ValidationPipe` avec `whitelist` et `forbidNonWhitelisted` | `auth.e2e-spec.ts` : « assignation de masse » |
| Dernier administrateur protégé | Transaction + verrou consultatif PostgreSQL, 409 | `installation.e2e-spec.ts` |
| Pas de création publique de compte | Seule `/installation` existe (sans jeton, limitée à 5/h/IP), verrouillée dès le premier compte | `installation.e2e-spec.ts`, `access.e2e-spec.ts` |

## Authentification et sessions (A07)

| Exigence | Mesure | Vérification |
|---|---|---|
| Mots de passe | Argon2id (45 Mio, t=3), calcul factice si l'utilisateur n'existe pas | `password.service.ts`, `auth.service.ts` |
| Politique | 12 caractères au moins, estimation de robustesse (zxcvbn), changement obligatoire du mot de passe temporaire | `auth.e2e-spec.ts` |
| Verrouillage | 5 échecs → 15 min, puis durée doublée à chaque échec ; limite 5/15 min par IP + courriel (429) | `auth.e2e-spec.ts` |
| Message identique | « Identifiants incorrects. » pour courriel inconnu, mauvais mot de passe, compte verrouillé ou désactivé | `auth.e2e-spec.ts` |
| Jetons | JWT 15 min en cookie `HttpOnly`, `SameSite=Strict`, `Secure` en production ; rafraîchissement opaque 256 bits, haché (SHA-256), rotation et détection de réutilisation (révocation de la famille) | `auth.e2e-spec.ts` |
| Révocation | `tokenVersion` : un changement de mot de passe, une désactivation ou un changement de rôle invalide aussitôt les JWT déjà émis | `auth.e2e-spec.ts` |
| Pas de jeton dans le navigateur | Aucun `localStorage`/`sessionStorage` pour l'authentification (seul le thème est mémorisé) | revue de `frontend/src/app/core` |

## Entrées, injection, XSS (A03)

| Exigence | Mesure | Vérification |
|---|---|---|
| Validation | DTO `class-validator` sur toutes les entrées, pagination bornée à 100, corps JSON ≤ 1 Mo | `findings.e2e-spec.ts`, `access.e2e-spec.ts` (413) |
| SQL | Prisma uniquement ; seul SQL brut : `pg_advisory_xact_lock(<constante>)` en gabarit étiqueté, sans entrée utilisateur ; aucun `$queryRawUnsafe` | revue ; `findings.e2e-spec.ts` (recherche `' OR 1=1 --`) |
| Rapport ZAP | Pipeline de la section 8 : MIME, extension, premier caractère, profondeur, `secure-json-parse`, schéma Zod, plafonds, HTML converti en texte brut | `zap.parser.spec.ts`, `scans.e2e-spec.ts` |
| XSS | Angular encode par défaut ; `bypassSecurityTrust*`, `innerHTML` et `eval` interdits par ESLint | `frontend/eslint.config.mjs` ; `scans.e2e-spec.ts` (HTML neutralisé) |
| Injection de consigne (LLM) | Liste blanche de champs, titre tronqué, ni description ni URL, données délimitées et déclarées non fiables, sortie validée par Zod et bornée, identifiants vérifiés, repli sur les règles | `predictions.spec.ts`, `access.e2e-spec.ts` |
| PDF | Texte brut uniquement, caractères de contrôle retirés, pas de lien, script, pièce jointe ni formulaire | `reports.e2e-spec.ts` |

## Configuration et en-têtes (A05)

| Exigence | Mesure | Vérification |
|---|---|---|
| Helmet | CSP stricte, HSTS (production), `nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`, pas de `X-Powered-By` | `app.setup.ts` ; `access.e2e-spec.ts` |
| CSP | Aucune exception `unsafe-eval` ni script en ligne. **Exception documentée** : `style-src 'unsafe-inline'` (styles des composants Angular) | `app.setup.ts` |
| CORS | Liste blanche (`APP_ORIGIN`), jamais `*` | `app.setup.ts` |
| CSRF | `SameSite=Strict`, contrôle d'`Origin`, jeton à double soumission sur toute requête modifiante authentifiée | `auth.e2e-spec.ts` |
| Configuration | Variables validées par Zod au démarrage ; en production : secret JWT ≥ 64 caractères, cookies `Secure`, origine https | `backend/src/config/env.ts` |
| Erreurs | Réponses génériques sans trace de pile ; OpenAPI non exposée | `scans.e2e-spec.ts`, `access.e2e-spec.ts` |

## Déni de service

| Exigence | Mesure | Vérification |
|---|---|---|
| Débit | 100 requêtes/min/IP ; connexion 5/15 min ; import 10/h ; exports PDF 20/h ; installation 5/h/IP ; administration 60/min | `auth`, `scans`, `reports`, `installation` e2e (429) |
| Tailles | Fichier ≤ `MAX_IMPORT_MB`, 5 000 alertes, profondeur 20, 50 URL par constat, plafonds PDF (constats et pages), délai de génération | `scans.e2e-spec.ts`, `reports.e2e-spec.ts` |

## Journalisation (A09)

| Exigence | Mesure | Vérification |
|---|---|---|
| Journal en ajout seul | Déclencheurs PostgreSQL (`UPDATE`, `DELETE`, `TRUNCATE` refusés) | `auth.e2e-spec.ts` |
| Couverture | Connexions, déconnexions, mots de passe, utilisateurs, applications, imports (réussis, refusés, en échec), annotations, statuts, relance des modèles, installation, exports PDF, accès refusés (403), consultations d'un constat | `auth`, `scans`, `findings`, `reports` e2e |
| Pas de secret | Masquage des métadonnées (`sanitizeMetadata`) et des journaux `pino` (cookies, mots de passe) ; contenu de rapport jamais journalisé | `scans.e2e-spec.ts`, `auth.e2e-spec.ts` |

## Chaîne d'approvisionnement (A06, A08)

`package-lock.json` versionné, `npm ci`, Dependabot, `npm audit --audit-level=high`, CodeQL et gitleaks dans la CI (`.github/workflows/ci.yml`). Aucune fonctionnalité ne télécharge ni n'exécute de code distant. Polices embarquées (pas de ressource externe).

## Correspondance STRIDE

| Menace | Mesures principales |
|---|---|
| **S**poofing (usurpation) | Argon2id, verrouillage, rotation des jetons, cookies `HttpOnly`/`Strict`, CSRF |
| **T**ampering (falsification) | Validation stricte, schéma Zod du rapport, Prisma paramétré, journal en ajout seul, machine à états |
| **R**epudiation | Journal d'audit (réussites et refus) avec IP, agent, identifiant de requête |
| **I**nformation disclosure | Décideur en agrégats, erreurs génériques, pas de secret en journal, CSP, `Cache-Control: no-store` sur les PDF |
| **D**enial of service | Limites de débit, de taille, de profondeur et de pages, délais |
| **E**levation of privilege | Refus par défaut, rôle relu en base, pas d'assignation de masse, protection du dernier administrateur |

## Limites connues

- Limiteur de débit en mémoire (une seule instance).
- Pas d'authentification multifacteur, pas d'annuaire d'entreprise.
- Le journal d'audit est protégé par la base ; un administrateur de la base PostgreSQL pourrait supprimer les déclencheurs. Exporter le journal vers un puits externe en production.
- La CSP autorise les styles en ligne (Angular).
