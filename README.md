# Projet 7 : priorisation intelligente des vulnérabilités (prototype)

Prototype fonctionnel, sécurisé et testé : import de rapports OWASP ZAP (JSON), priorisation **P1 à P4** par deux modèles **simulés** (M1 : exploitabilité, M2 : priorité contextuelle), suivi de correction, tableau de bord, rapports PDF et journal d'audit.

> **Mode simulation.** M1 et M2 ne sont pas entraînés. Toutes leurs sorties sont simulées, étiquetées « Simulé » dans l'interface, la base et les PDF. Aucune métrique de performance n'est affichée.

- **Front-end** : Angular 21 (composants autonomes, signaux), design épuré à effet verre, thème **clair et sombre**, Chart.js.
- **Back-end** : NestJS 12 (ESM), Prisma 7, PostgreSQL (Neon), Argon2id, Zod, pdfkit.
- Interface en français ; routes de l'API en français (`/api/constats`, `/api/tableaux-de-bord`, …).

## Prérequis

- Node.js ≥ 22.12 (testé avec 22.14)
- Une base PostgreSQL : **Neon** (recommandé) ou la base locale embarquée (voir plus bas)

## Installation

```bash
npm ci
cp .env.example backend/.env      # puis renseigner les valeurs (voir ci-dessous)
```

Si npm signale des scripts d'installation non approuvés (`argon2`, `prisma`…), approuvez-les avec `npm approve-scripts` ; les binaires précompilés fonctionnent normalement sans cela.

### Configuration (`backend/.env`)

| Variable | Rôle |
|---|---|
| `DATABASE_URL` | Connexion Neon **pooled** (hôte avec `-pooler`), `sslmode=require` |
| `DIRECT_URL` | Connexion Neon **directe**, utilisée par `prisma migrate` |
| `JWT_ACCESS_SECRET` | 64 caractères aléatoires : `node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"` |
| `APP_ORIGIN` | Origine du front (`http://localhost:4200` en développement, l'URL publique en production) |
| `PREDICTION_PROVIDER` | `rules` (défaut) ou `anthropic` (+ `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL`) |

Les autres variables (plafonds d'import, de rapports, limites) sont documentées dans `.env.example`. L'application refuse de démarrer si la configuration est invalide ; en production elle exige un secret ≥ 64 caractères, `COOKIE_SECURE=true` et une origine en https.

### Base de données

**Neon** : créez un projet, copiez les deux chaînes de connexion (pooled et directe) dans `.env`, puis :

```bash
npm run db:migrate     # applique les migrations (dont le journal d'audit en ajout seul)
npm run db:seed        # facultatif : SEED_DEMO=true crée seulement les 2 applications de laboratoire
```

**Sans Neon (développement hors ligne)** : un PostgreSQL embarqué est fourni.

```bash
npm run dev:db         # démarre PostgreSQL sur le port 54329 et affiche DATABASE_URL / DIRECT_URL
```

## Lancement

### Développement (deux terminaux)

```bash
npm run dev:api        # API sur http://localhost:3000
npm run dev:web        # front sur http://localhost:4200 (proxy /api → 3000)
```

### Production (une seule origine)

```bash
npm run build          # build Angular puis compilation du back-end
# dans backend/.env : FRONTEND_DIST=../frontend/dist/frontend/browser
npm start              # NestJS sert le front sur / et l'API sur /api
```

Placez l'application derrière un proxy TLS (cookies `Secure`, HSTS, `trust proxy`).

## Premier démarrage

1. Base vide : toute page redirige vers **/installation**.
2. Saisissez un nom, un courriel et un mot de passe (12 caractères au moins, affichable avec l'icône en forme d'œil). Le compte **administrateur** est créé, l'installation se verrouille définitivement (la route répond 404 ensuite).
> **Attention.** L'installation n'exige plus de jeton : la première personne qui ouvre l'application devient administrateur. Ne l'exposez sur Internet qu'après avoir créé le compte (la route se verrouille alors définitivement).

3. Connectez-vous. L'administrateur hérite des droits de l'analyste : il peut tout faire seul. Il peut aussi créer, depuis **Utilisateurs**, des comptes analyste et décideur (mot de passe temporaire à changer à la première connexion).

## Obtenir un rapport ZAP

ZAP ne doit scanner qu'une **application de laboratoire autorisée** (par exemple OWASP Juice Shop en local) :

```bash
docker run --rm -v "$(pwd):/zap/wrk:rw" -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://cible-de-labo -J rapport.json
```

Des rapports **synthétiques** (jamais issus d'un scan non autorisé) sont fournis dans `fixtures/zap/` (`node fixtures/generate.mjs` les régénère) : `valid-small.json`, `valid-medium.json`, et des fichiers d'attaque `bad-*` utilisés par les tests.

## Tests

```bash
npm run lint           # oxlint + tsc (back), ESLint (front, avec règles de sécurité)
npm test               # unitaires back (Vitest) et front
npm run test:e2e       # e2e API : authentification, droits, installation, import, PDF…
```

Les tests e2e utilisent `TEST_ADMIN_URL` (serveur PostgreSQL, CI ou Neon de test) ; à défaut, un PostgreSQL embarqué éphémère est démarré. Chaque fichier de test crée sa propre base.

## Documentation

- [docs/DECISIONS.md](docs/DECISIONS.md) : choix et écarts par rapport au cahier des charges
- [docs/SECURITY.md](docs/SECURITY.md) : exigences → mesures → tests, correspondance STRIDE
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) : modules, flux d'import, formules de simulation
- [docs/FONTS.md](docs/FONTS.md) : licence de la police des PDF

## Limites

- Les prédictions sont **simulées** : elles ne reflètent aucune performance réelle et ne doivent pas servir à décider de vraies priorités de sécurité.
- Un prototype appliquant ces mesures **réduit** les risques, il ne garantit pas l'absence de vulnérabilités : un audit externe (ZAP, WSTG, ASVS) reste nécessaire avant tout usage réel.
- Le rapport PDF est un **instantané** généré à la demande : il reflète l'état des données à ce moment et mentionne que les prédictions sont simulées. Il ne remplace ni une évaluation des modèles ni un audit.
- Le limiteur de débit est en mémoire (une seule instance).
- Hors périmètre : authentification multifacteur, annuaire d'entreprise, import d'autres outils que ZAP, entraînement réel de M1 et M2, haute disponibilité.
