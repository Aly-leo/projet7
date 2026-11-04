# Intégration de M1 entraîné dans l'application Web

## Service d'inférence (`ml/m1`)

Lancement (depuis `ml/m1`) :

```bash
M1_SERVICE_TOKEN=<16 caractères au moins> PYTHONPATH=src python -m m1 service
```

Variables : `M1_SERVICE_TOKEN` (obligatoire : sans lui, le service refuse de démarrer), `M1_HOST` (défaut `127.0.0.1`), `M1_PORT` (défaut `8001`).
Avant le premier lancement, construire la table de consultation des CVE : `PYTHONPATH=src python -m m1.infer build-lookup`.

| Route | Jeton | Rôle |
|---|---|---|
| `GET /health` | non | état du service |
| `GET /model-info` | oui (`X-M1-Token`) | version, modèle, horizon, date d'entraînement |
| `POST /m1/predict` | oui | probabilités pour une liste (500 éléments au plus, corps ≤ 256 Ko) |

Requête :

```json
{ "items": [ { "cveId": "CVE-2021-44228" }, { "cweId": "CWE-89" }, { "features": { "cvss_base": 9.8, "av": "N", "pr": "N", "cwe": "CWE-94", "exploitdb_before_t0": 1 } } ] }
```

Réponse (même ordre) :

```json
{ "predictions": [
  { "probability": 0.0277, "source": "m1", "modelVersion": "m1_v1", "calibrated": true, "alreadyInKev": true, "relativeRisk": 47.9 },
  { "probability": 0.0015, "source": "cwe_rate", "modelVersion": "m1_v1", "calibrated": false, "relativeRisk": 2.57 },
  { "probability": 0.000578, "source": "prior", "modelVersion": "m1_v1", "calibrated": false, "relativeRisk": 1.0 } ] }
```

`source` indique toujours l'origine de la valeur :

- `m1` : le modèle entraîné (CVE connu de la table de consultation, ou variables fournies) ; `calibrated: true` ;
- `cwe_rate` : taux historique, lissé, des CVE ayant ce CWE (un fait statistique, pas une prédiction du modèle) ;
- `prior` : prévalence globale, dernier recours quand rien n'est connu.

`alreadyInKev: true` signale un CVE déjà listé : M1 n'a pas été entraîné sur ces cas (ils sont exclus de la cohorte), sa valeur n'a alors pas de sens.

Déploiement en ligne (Docker, Railway, réseau privé) : voir `DEPLOIEMENT_RAILWAY.md`.

## Application Web (NestJS)

Variables de `backend/.env` :

| Variable | Valeur |
|---|---|
| `M1_PROVIDER` | `simulated` (défaut) ou `trained` |
| `M1_SERVICE_URL` | par exemple `http://127.0.0.1:8001` |
| `M1_SERVICE_TOKEN` | le même jeton que le service |
| `M1_TIMEOUT_MS` | délai maximal d'un appel (défaut 5000) |

Comportement :

- Avec `M1_PROVIDER=trained`, l'import appelle le service pour M1 (seuls `cveId` et `cweId` sont envoyés : jamais le titre, la description ni les URL). Chaque prédiction M1 est enregistrée avec `simulated = false`, `provider = 'm1-trained'`, `version` = version du modèle, et son origine (`m1`, `cwe_rate` ou `prior`) dans `explanation.source`.
- **M2 reste simulé** (`simulated = true`). Il ne reçoit **pas** la probabilité brute de M1 (≈ 0,06 % en moyenne, inaudible pour les seuils de M2 écrits pour l'échelle 0,03–0,99) mais un **niveau relatif** calculé par `m1LevelForM2` (`prediction.types.ts`) : `niveau = clamp((log10(risque relatif) + 1) / 3)²`, où le risque relatif est la probabilité divisée par la prévalence d'entraînement (renvoyé par le service dans `relativeRisk`). 0,1× la moyenne → 0 ; 1× → 0,11 ; 10× → 0,44 ; 100× → 1. Le carré fait peser un risque moyen comme un M1 simulé « ordinaire » (0,03–0,1) : sans lui (version initiale, 1× = 0,33), un import réel faisait passer des constats mineurs de P2 à P1 (43 P1 sur 48). Vérifié de bout en bout avec le vrai service sur `valid-medium.json` : P1/P2/P4 = 33/10/5 avec M1 entraîné, 32/11/5 avec M1 simulé. Un CVE déjà dans KEV (`alreadyInKev`) vaut 1. La logique de M2 n'est pas modifiée.
- La fiche d'un constat affiche la probabilité avec des décimales adaptées, le risque relatif (« N× la moyenne ») et la mention « déjà dans le catalogue KEV ». L'explication enregistrée contient `relativeRisk`, `alreadyInKev` et `levelForM2`.
- Constats sans CVE (cas courant avec ZAP) : le service renvoie le taux historique du CWE (`cwe_rate`), lissé avec un prior de 1 positif fictif, ou la prévalence (`prior`, risque relatif 1). Les CWE très courants dans le jeu sans positif (CWE-79, CWE-89) obtiennent ≈ 0,16–0,18× la moyenne : c'est la mesure sur les données post-2021, pas un jugement sur leur gravité.
- **Repli :** si le service est indisponible, injoignable, répond une erreur ou une sortie invalide, M1 est calculé par le fournisseur à règles et **marqué simulé** ; l'événement est journalisé (`M1_SERVICE_FALLBACK`, sans secret) et l'import n'échoue pas.
- **Constats ZAP sans CVE :** la plupart des constats ZAP n'ont pas de CVE ; la valeur vient alors du taux historique du CWE (`cwe_rate`), ce que l'interface indique.
- **Interface :** la page Modèles affiche « M1 : modèle entraîné (version) » et « M2 : simulation » ; la fiche d'un constat indique l'origine de M1 (modèle, taux du CWE ou prévalence) et que M2 est simulé.

## Fichiers du prototype modifiés

`backend/src/config/env.ts`, `backend/src/predictions/{prediction.service.ts, predictions.module.ts, trained-m1.provider.ts}`, `backend/src/models/models.controller.ts`, `backend/src/scans/scans.service.ts`, `backend/test/m1.e2e-spec.ts`, `frontend/src/app/core/models.ts`, `frontend/src/app/features/{finding-detail,import,models}.page.ts`, `.env.example`.
