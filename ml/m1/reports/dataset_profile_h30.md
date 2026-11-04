# Profil du jeu de données (h = 30 jours)

Date de collecte : 2026-11-04 · lancement de KEV détecté le 2021-11-03.

## Construction de la cohorte

- CVE dans la NVD collectée : 320088 (dont 14517 rejetés, retirés).
- Après retrait des rejetés : 305571.
- Cohorte après le lancement de KEV (t0 > 2021-11-03) : 238371.
- Exclus car déjà dans KEV avant t0 : 629.
- Exclus car étiquette non mûre (t0 + h > date de collecte) : 33373.
- **Lignes retenues : 204369 ; positifs : 47 (prévalence 0.0230%).**

## Découpage chronologique

Coupures sur t0 : entraînement ≤ 2025-09-01 ; validation ≤ 2026-03-01 ; test au-delà. Les lignes « purged » sont retirées : leur fenêtre d'étiquette déborde sur la période suivante.

| split | cve | positifs | prevalence | t0_min | t0_max |
|---|---|---|---|---|---|
| test | 53618 | 10 | 0.0002 | 2026-04-01 | 2026-10-01 |
| train | 126046 | 28 | 0.0002 | 2021-12-01 | 2025-09-01 |
| val | 24705 | 9 | 0.0004 | 2025-10-01 | 2026-03-01 |

## Effectifs et prévalence par année de t0

| année de t0 | cve | positifs | prevalence |
|---|---|---|---|
| 2021.0000 | 1625.0000 | 0.0000 | 0.0000 |
| 2022.0000 | 24072.0000 | 6.0000 | 0.0002 |
| 2023.0000 | 27985.0000 | 3.0000 | 0.0001 |
| 2024.0000 | 37463.0000 | 9.0000 | 0.0002 |
| 2025.0000 | 46993.0000 | 16.0000 | 0.0003 |
| 2026.0000 | 66231.0000 | 13.0000 | 0.0002 |

## Valeurs manquantes

La part inclut la valeur `UNK` pour les variables catégorielles. EPSS est une référence, jamais une variable.

| variable | part manquante |
|---|---|
| cvss_base | 0.0088 |
| av | 0.0000 |
| ac | 0.0000 |
| pr | 0.0000 |
| ui | 0.0000 |
| s | 0.0000 |
| c | 0.0000 |
| i | 0.0000 |
| a | 0.0000 |
| cwe | 0.0000 |
| vendor_cve_count | 0.2528 |
| exploitdb_before_t0 | 0.0000 |
| n_references | 0.0000 |
| epss_t0 | 0.0261 |

## Version de CVSS utilisée

| version CVSS | part |
|---|---|
| 3.1 | 0.9560 |
| 4.0 | 0.0258 |
| 3.0 | 0.0094 |
| aucune | 0.0088 |

Part de CVE sans score CVSS à la collecte : 0.88%. Couverture EPSS à t0 : 97.39%.
