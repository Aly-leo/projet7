# Architecture

```
Navigateur ── HTTPS ──▶ NestJS (une seule origine)
                          ├─ /            build Angular (fichiers statiques, repli sur index.html)
                          └─ /api/*       API REST
                                │
        Gardes globales : débit IP → CSRF → authentification → rôles → débit de route
                                │
   auth · installation · users · applications · scans · findings · dashboard · models · reports · audit
                                │
                  Prisma (adaptateur pg) ──▶ PostgreSQL (Neon)
                                │
        predictions : PredictionProvider ◀── RuleBasedProvider | AnthropicSimulatedProvider
```

## Modules back-end (`backend/src`)

| Module | Rôle |
|---|---|
| `common` | Décorateurs (`@Public`, `@Roles`, `@AuditAs`, `@RateLimit`), gardes, filtre d'exceptions, limiteur de débit |
| `config` | Variables d'environnement validées par Zod |
| `auth` | Connexion, rotation des jetons, changement de mot de passe, politique de mot de passe |
| `installation` | Création du premier administrateur (verrou consultatif, verrouillage définitif) |
| `users`, `applications` | Gestion par l'administrateur |
| `scans` | Import ZAP : `zap.parser.ts` (pur, testé seul) et `scans.service.ts` (transaction, prédictions, audit) |
| `predictions` | Interface `PredictionProvider`, règles, API Claude, orchestration, cache |
| `findings` | Liste, détail, annotation, machine à états de correction |
| `dashboard` | Agrégats (`aggregate`) partagés avec les rapports |
| `models` | État des modèles, relance des prédictions simulées |
| `reports` | PDF (`pdf.builder.ts` : surcouche `pdfkit`) |
| `audit` | Écriture et lecture du journal |

## Flux d'import

1. Gardes : authentification → rôle (403 journalisé) → limite 10/h/utilisateur.
2. Multer en mémoire (un fichier, taille bornée).
3. `parseZapReport` : type, JSON sécurisé, profondeur, plafonds, schéma Zod, HTML → texte, fusion des doublons.
4. Empreinte SHA-256 du fichier : 409 si déjà importé.
5. Transaction : scan, constats nouveaux (`createManyAndReturn`), corrections, mises à jour des constats connus.
6. `PredictionService.predictFindings` : M1 puis M2, hors transaction (un échec bascule sur les règles).
7. Réponse 201 et entrée d'audit `SCAN_IMPORT`.

## Simulation de M1 et M2

`RuleBasedProvider` (déterministe) :

- **M1** : `p = clamp((base(gravité) + bonus(CWE)) × facteur(confiance) + 0,15 si CVE, 0,01, 0,99)` avec `base = [0,03 ; 0,10 ; 0,25 ; 0,45]`. Les bonus par CWE sont des valeurs de démonstration, **non issues de données réelles**.
- **M2** : somme de contributions : gravité/3 × 0,25, exposition (0,30 / 0,12 / 0,03), sensibilité (0,25 / 0,12 / 0,04), 0,35 × M1, contrôles en place (−0,04 hors exposition publique), historique (+0,03 au-delà de 10 instances). Probabilité bornée à [0,01 ; 0,99]. Seuils : ≥ 0,70 P1, ≥ 0,45 P2, ≥ 0,25 P3, sinon P4 ; gravité 0 → P4 et probabilité ≤ 0,2.

**Identifiant CVE** : à l'import, le parseur cherche le premier `CVE-AAAA-NNNN` valide (année de 1999 à l'an prochain) dans la description, les informations complémentaires (`otherinfo`) et les références (`reference`) de chaque alerte, après conversion en texte brut. Il est enregistré dans `Finding.cveId` **à la création du constat uniquement** (un constat déjà connu n'est pas modifié, ses prédictions ne sont pas recalculées) et n'entre pas dans l'empreinte. Si une alerte en cite plusieurs, seul le premier est retenu.

Quand **M1 entraîné** est actif (`M1_PROVIDER=trained`), M2 reçoit un niveau relatif (0 à 1, échelle logarithmique du risque relatif à la prévalence, mise au carré ; 1 pour un CVE déjà dans KEV) au lieu de la probabilité brute, qui serait inaudible (≈ 0,06 %) : voir `m1LevelForM2` et `ml/m1/docs/INTEGRATION_M1.md`. La logique de M2 est inchangée.

Les contributions sont renvoyées comme « explication de type SHAP » (simulée).
Pour brancher de vrais modèles : implémenter `PredictionProvider` (appel d'un service Python), l'enregistrer dans `PredictionService.getLlm`/`predictFindings`, mettre `simulated = false` pour ses prédictions et alimenter la page Modèles en métriques.

## Front-end (`frontend/src/app`)

- `core` : `ApiService` (cookies, téléchargement PDF par blob), `AuthService` (signaux), intercepteur (en-tête CSRF, un seul rafraîchissement sur 401), gardes (installation, authentification, rôle), thème, notifications.
- `shared` : coque (menu filtré par rôle, bandeau de simulation permanent), graphique Chart.js qui suit le thème, pastilles de priorité et étiquette « Simulé ».
- `features` : une page par fonctionnalité, chargée à la demande.
- Style : variables CSS, effet verre (`backdrop-filter`), fond blanc à dégradés bleus très légers, thème clair/sombre qui suit le système puis le choix de l'utilisateur.
