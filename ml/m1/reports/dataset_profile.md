# Profil du jeu de données (h = 90 jours)

Date de collecte : 2026-11-04 · lancement de KEV détecté le 2021-11-03.

## Construction de la cohorte

- CVE dans la NVD collectée : 320088 (dont 14517 rejetés, retirés).
- Après retrait des rejetés : 305571.
- Cohorte après le lancement de KEV (t0 > 2021-11-03) : 238371.
- Exclus car déjà dans KEV avant t0 : 629.
- Exclus car étiquette non mûre (t0 + h > date de collecte) : 54991.
- **Lignes retenues : 182751 ; positifs : 103 (prévalence 0.0564%).**

## Découpage chronologique

Coupures sur t0 : entraînement ≤ 2025-04-01 ; validation ≤ 2026-01-01 ; test au-delà. Les lignes « purged » sont retirées : leur fenêtre d'étiquette déborde sur la période suivante.

| split | cve | positifs | prevalence | t0_min | t0_max |
|---|---|---|---|---|---|
| purged | 18563 | 10 | 0.0005 | 2025-02-01 | 2026-01-01 |
| test | 41455 | 22 | 0.0005 | 2026-02-01 | 2026-08-01 |
| train | 95203 | 54 | 0.0006 | 2021-12-01 | 2025-01-01 |
| val | 27530 | 17 | 0.0006 | 2025-05-01 | 2025-11-01 |

## Effectifs et prévalence par année de t0

| année de t0 | cve | positifs | prevalence |
|---|---|---|---|
| 2021.0000 | 1625.0000 | 0.0000 | 0.0000 |
| 2022.0000 | 24072.0000 | 17.0000 | 0.0007 |
| 2023.0000 | 27985.0000 | 17.0000 | 0.0006 |
| 2024.0000 | 37463.0000 | 18.0000 | 0.0005 |
| 2025.0000 | 46993.0000 | 26.0000 | 0.0006 |
| 2026.0000 | 44613.0000 | 25.0000 | 0.0006 |

## Valeurs manquantes

La part inclut la valeur `UNK` pour les variables catégorielles. EPSS est une référence, jamais une variable.

| variable | part manquante |
|---|---|
| cvss_base | 0.0055 |
| av | 0.0000 |
| ac | 0.0000 |
| pr | 0.0000 |
| ui | 0.0000 |
| s | 0.0000 |
| c | 0.0000 |
| i | 0.0000 |
| a | 0.0000 |
| cwe | 0.0000 |
| vendor_cve_count | 0.2153 |
| exploitdb_before_t0 | 0.0000 |
| n_references | 0.0000 |
| epss_t0 | 0.0292 |

## Version de CVSS utilisée

| version CVSS | part |
|---|---|
| 3.1 | 0.9644 |
| 4.0 | 0.0203 |
| 3.0 | 0.0098 |
| aucune | 0.0055 |

Part de CVE sans score CVSS à la collecte : 0.55%. Couverture EPSS à t0 : 97.08%.
