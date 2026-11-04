# Profil du jeu de données (h = 365 jours)

Date de collecte : 2026-11-04 · lancement de KEV détecté le 2021-11-03.

## Construction de la cohorte

- CVE dans la NVD collectée : 320088 (dont 14517 rejetés, retirés).
- Après retrait des rejetés : 305571.
- Cohorte après le lancement de KEV (t0 > 2021-11-03) : 238371.
- Exclus car déjà dans KEV avant t0 : 629.
- Exclus car étiquette non mûre (t0 + h > date de collecte) : 103627.
- **Lignes retenues : 134115 ; positifs : 168 (prévalence 0.1253%).**

## Découpage chronologique

Coupures sur t0 : entraînement ≤ 2024-08-01 ; validation ≤ 2025-04-01 ; test au-delà. Les lignes « purged » sont retirées : leur fenêtre d'étiquette déborde sur la période suivante.

| split | cve | positifs | prevalence | t0_min | t0_max |
|---|---|---|---|---|---|
| purged | 60101 | 67 | 0.0011 | 2023-10-01 | 2025-04-01 |
| test | 27530 | 36 | 0.0013 | 2025-05-01 | 2025-11-01 |
| train | 46484 | 65 | 0.0014 | 2021-12-01 | 2023-09-01 |

## Effectifs et prévalence par année de t0

| année de t0 | cve | positifs | prevalence |
|---|---|---|---|
| 2021.0000 | 1625.0000 | 3.0000 | 0.0018 |
| 2022.0000 | 24072.0000 | 38.0000 | 0.0016 |
| 2023.0000 | 27985.0000 | 37.0000 | 0.0013 |
| 2024.0000 | 37463.0000 | 37.0000 | 0.0010 |
| 2025.0000 | 42970.0000 | 53.0000 | 0.0012 |

## Valeurs manquantes

La part inclut la valeur `UNK` pour les variables catégorielles. EPSS est une référence, jamais une variable.

| variable | part manquante |
|---|---|
| cvss_base | 0.0002 |
| av | 0.0000 |
| ac | 0.0000 |
| pr | 0.0000 |
| ui | 0.0000 |
| s | 0.0000 |
| c | 0.0000 |
| i | 0.0000 |
| a | 0.0000 |
| cwe | 0.0000 |
| vendor_cve_count | 0.1502 |
| exploitdb_before_t0 | 0.0000 |
| n_references | 0.0000 |
| epss_t0 | 0.0041 |

## Version de CVSS utilisée

| version CVSS | part |
|---|---|
| 3.1 | 0.9776 |
| 4.0 | 0.0123 |
| 3.0 | 0.0099 |
| aucune | 0.0002 |

Part de CVE sans score CVSS à la collecte : 0.02%. Couverture EPSS à t0 : 99.59%.
