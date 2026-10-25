# Décisions de conception

Ce document consigne les choix qui s'écartent du cahier des charges ou le précisent. Quand deux exigences entraient en conflit, la plus stricte a été appliquée.

## Versions et outillage

| Sujet | Décision | Pourquoi |
|---|---|---|
| Angular | **21.2** au lieu de la 22 | Angular 22 exige Node ≥ 22.22.3. Le poste de développement fournit Node 22.14 ; Angular 21 est la dernière version compatible. Remonter à la 22 ne demande que de changer Node. |
| NestJS | **12** (ESM uniquement) | Dernière version stable. Tout le code back-end est donc en ESM (`module: nodenext`, imports relatifs avec `.js`). |
| Prisma | **7.10** (pas la 8 « rc ») | La balise `latest` de npm pointe sur une préversion ; la dernière version stable est la 7.10. En Prisma 7, l'URL n'est plus dans `schema.prisma` : `DIRECT_URL` est lue par `prisma.config.ts` (migrations) et `DATABASE_URL` par l'adaptateur `@prisma/adapter-pg` (application). Même usage « pooled / directe » que prévu pour Neon. |
| Tests | **Vitest + SWC** (au lieu de Jest) | Le gabarit officiel NestJS 12 utilise Vitest. SWC fournit les métadonnées de décorateurs nécessaires à l'injection de dépendances. |
| Compilation | `tsc` directement | Le CLI Nest (schematics) plante sous Node 22.14 (cycle ESM). Le build et le mode développement n'en ont pas besoin. |
| TypeScript | 6 côté back-end | Version du gabarit officiel NestJS 12. La version 7 (compilateur natif, `latest` sur npm) n'a pas été évaluée : le binaire `tsc` installé était incompatible avec la chaîne d'outils. |
| Interface | **Design maison** (CSS, variables, effet verre) au lieu d'Angular Material | Contrôle total du thème clair/sombre et de l'effet verre demandés, aucune dépendance visuelle lourde, éléments HTML natifs (accessibilité clavier et lecteurs d'écran). Chart.js est conservé pour les graphiques. |
| Limiteur de débit | Implémentation maison, en mémoire | Moins de dépendances et contrôle fin (par IP, par utilisateur, par IP + courriel). **Limite** : l'état n'est pas partagé entre instances ; pour plusieurs instances, passer à Redis. |
| Rapports PDF | `pdfkit`, police Noto Sans (OFL) embarquée | Aucun navigateur sans tête ni conversion HTML : pas de SSRF ni de lecture de fichiers locaux. |

## Modèle de données : ajouts

- `User.tokenVersion` : incrémenté à chaque changement de mot de passe, désactivation, changement de rôle ou réinitialisation. Le JWT porte cette valeur ; un JWT émis avant le changement est refusé immédiatement (sinon un jeton volé resterait valide jusqu'à 15 minutes).
- `Finding.exploitProbability`, `modelProbability`, `modelPriority`, `expertPriority`, `effectivePriority` : valeurs dérivées tenues à jour par le serveur pour trier et agréger par priorité en SQL. La priorité effective est celle de l'expert si elle existe, sinon celle de M2. Les `Prediction` restent l'historique complet.
- Migration `audit_append_only` : déclencheurs sur `UPDATE`/`DELETE` (exigé) **et** sur `TRUNCATE` (qui contourne les déclencheurs par ligne).

## API

- Champs de formulaire en français pour la connexion, l'installation et le changement de mot de passe (`courriel`, `motDePasse`, …), comme le cahier des charges le fixe pour l'installation ; champs anglais pour les entités, alignés sur la base.
- `GET /utilisateurs/assignables` (ADMIN, ANALYST) : liste réduite (id, nom) pour assigner une correction, car la liste complète des utilisateurs reste réservée à l'administrateur.
- Aucune route `DELETE /utilisateurs` : un compte se désactive, il ne se supprime pas (le dernier administrateur actif est protégé de toute façon).
- Une route inconnue répond 404 avant les gardes (aucune information sur l'existence des routes protégées).
- Le jeton anti-CSRF n'est pas exigé sur les routes publiques (connexion, rafraîchissement, installation) : elles sont protégées par le contrôle d'`Origin` et `SameSite=Strict`. Toute autre requête qui modifie des données et porte des cookies exige le jeton (double soumission).

## Import

- Un rapport conservé (`Scan.rawReport`) ne l'est que sous `RAW_REPORT_MAX_MB` (1 Mo par défaut). Il n'est jamais rendu ni journalisé.
- Statuts : les corrections naissent `IMPORTED`, passent `VALIDATED` dans la transaction d'import, puis `PRIORITIZED` après M2.
- Les alertes dupliquées d'un même rapport sont fusionnées (instances additionnées, 50 URL au plus).

## Simulation

- Priorité `P4` forcée pour un constat purement informatif (gravité 0), quelle que soit l'exposition.
- Le cache des sorties du LLM est en mémoire (clé = empreinte du constat et de son contexte).
- `LLM_MAX_CALLS_PER_IMPORT` plafonne les appels : au-delà, les constats restants passent par le fournisseur à règles et la réponse indique le fournisseur effectivement utilisé (`mixed` si les deux ont servi).

## Installation sans jeton (demande explicite)

Le jeton d'installation (`SETUP_TOKEN`) prévu par le cahier des charges a été **retiré** à la demande du propriétaire du projet. Conséquence assumée : tant qu'aucun compte n'existe, la première personne qui atteint `/installation` devient administrateur. Mesures conservées : verrou consultatif PostgreSQL (un seul administrateur même en cas de requêtes simultanées), verrouillage définitif (404) dès le premier compte, limite de 5 tentatives par heure et par IP, politique de mot de passe, journal d'audit. **Recommandation** : créer le compte administrateur immédiatement après le déploiement, avant d'exposer l'application sur Internet.
