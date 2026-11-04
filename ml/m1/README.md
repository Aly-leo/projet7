# M1 — modèle d'exploitabilité

M1 estime la probabilité qu'un CVE soit **ajouté au catalogue KEV de la CISA dans les h jours (90 par défaut) qui suivent un instant de référence t0**.
Il est entraîné sur des **données publiques réelles** (NVD, KEV, EPSS, Exploit-DB) avec des protections contre la fuite d'information.

> **Limite à retenir.** KEV ne couvre qu'une partie de l'exploitation réelle (surtout des produits suivis par la CISA). M1 prédit « sera listé dans KEV », pas « sera exploité ».
> M2 reste simulé dans le prototype ; ce dossier ne l'entraîne pas.

## Installation

```bash
cd ml/m1
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt      # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux / macOS
```

## Commandes (sans `make`, utilisables partout)

Toutes les commandes se lancent depuis `ml/m1` avec `PYTHONPATH=src` (ou `python -m m1 …` après `pip install -e .`, non fourni : on utilise `PYTHONPATH`).

| Étape | Commande | Durée / taille indicatives |
|---|---|---|
| 1. KEV | `python -m m1 collect-kev` | quelques secondes, 3 Mo |
| 2. Exploit-DB | `python -m m1 collect-exploitdb` | < 1 min, 10 Mo |
| 3. NVD | `python -m m1 collect-nvd` | **~20 min avec clé, 1 h environ sans clé** ; ~1,5 Go compressé. Reprenable : relancer la même commande |
| 4. Dates EPSS | `python -m m1.build_dataset --prepare-only` | 1 min |
| 5. EPSS | `python -m m1 collect-epss` | ~60 fichiers de 3 Mo |
| 6. Jeux de données | `python -m m1 dataset --all-horizons` | quelques minutes |
| 7. Entraînement | `python -m m1 train` | 5 à 30 min |
| 8. Test (une seule fois) + explications | `python -m m1 evaluate` puis `python -m m1.explain` | quelques minutes |
| 9. Sensibilité (validation) | `python -m m1.sensitivity` | 10 à 30 min |
| 10. Table de consultation | `python -m m1.infer build-lookup` | 1 min |
| Service | `M1_SERVICE_TOKEN=<16+ caractères> python -m m1 service` | écoute sur 127.0.0.1:8001 |
| Tests | `python -m pytest -q tests` | CI (job `ml-tests`) : style + tests sur données synthétiques. Les contrôles sur données réelles ne tournent qu'en local, après `make dataset`. Le test du seuil de 30 positifs est `xfail` (strict) tant que l'écart n° 11 existe. |

Avec `make` : `make collect`, `make dataset train evaluate` refait tous les résultats à partir des données brutes.

La clé NVD (facultative, gratuite : https://nvd.nist.gov/developers/request-an-api-key) se donne par la variable d'environnement `NVD_API_KEY`.
Elle n'est jamais écrite dans un fichier, un journal ou Git.

## Contenu

- `config/m1.yaml` : horizon, graine, variables, paramètres.
- `src/m1/` : collecte, construction du jeu de données, entraînement, évaluation, explications, sensibilité, inférence, `service/` (FastAPI).
- `models/m1_v1/` : artefacts (modèle, calibrateur, taux par CWE, métriques, carte du modèle, environnement, manifeste).
- `reports/` : profil du jeu de données, figures, exemples locaux.
- `docs/` : rapport complet (`M1_REPORT.md`), note pour la soutenance (`M1_EXPLICATION_ORALE.md`), décisions, accès aux ressources, contrat d'intégration.
- `tests/` : tests unitaires, contrôles anti-fuite sur les données réelles, test de permutation des étiquettes, tests du service. Les données synthétiques (préfixe `SYN`) ne servent qu'aux tests de bon fonctionnement.
