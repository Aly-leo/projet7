# Rapport M1 (exploitabilité à 90 jours)

Tous les chiffres viennent de `models/m1_v1/*.json` et `reports/`, produits par `python -m m1 …`. Aucun n'est estimé à la main.

## 1. Données
- NVD (177 pages, publications depuis 2018-01-01), KEV (1 767 CVE), Exploit-DB, EPSS (59 dates sur 60 ; absente : 2026-04-01).
- À h=90 : 182 751 CVE, **103 positifs** (prévalence ≈ 0,06 %). Découpage : entraînement 95 203 (54 positifs), validation 27 530 (17), test 41 455 (22), purgé 18 563 (10).
- ⚠ Le seuil de 30 positifs en validation et en test n'est **pas atteint** (décision n° 11).

## 2. Modèles (validation, PR-AUC)
| Modèle | PR-AUC validation |
|---|---|
| Régression logistique (C=0,05) | **0,0076** |
| Forêt aléatoire | 0,0025 |
| XGBoost | 0,0036 |
Prévalence en validation : 0,0006. Retenu : régression logistique, calibration de Platt.

## 3. Résultats sur le test (évalué une fois, 22 positifs)
| Mesure | M1 calibré | CVSS | EPSS (sous-ensemble couvert, 18 positifs) |
|---|---|---|---|
| PR-AUC | 0,0036 | 0,0019 | **0,058** |
| ROC-AUC | 0,815 | 0,730 | 0,707 |
| Précision@1 % | 0,0048 | 0,0024 | 0,0109 |
| Rappel@5 % | 0,23 | 0,23 | 0,50 |
Prévalence (aléatoire) : PR-AUC 0,0005. Couverture EPSS : 88,4 %. ECE du M1 calibré : 0,0003 (brut : 0,23). Brier : 0,00053.

Intervalles de confiance à 95 % (bootstrap, 1 000 tirages) :
- PR-AUC M1 [0,0011 ; 0,0167] ; CVSS [0,0009 ; 0,0040].
- Différence M1 − CVSS : +0,0029, IC [−0,0010 ; +0,0146] → **non significative**.
- Différence M1 − EPSS (sous-ensemble) : −0,072, IC [−0,218 ; +0,00007] → EPSS meilleur, à la limite de la significativité.

**Lecture honnête** : M1 fait mieux que le hasard (≈ 7× la prévalence en PR-AUC) et mieux que CVSS en valeur, mais l'écart avec CVSS est dans le bruit. L'EPSS, qui intègre des signaux d'exploitation que M1 n'a pas, le surpasse nettement. Avec 22 positifs, aucune de ces conclusions n'est solide.

## 4. Sensibilité (validation uniquement)
- **Horizon** : h=30 PR-AUC 0,057 (9 positifs en validation) ; h=90 : 0,0076 ; h=365 : non évaluable (validation sans positif après purge).
- **Ablations (h=90)** : toutes variables 0,0076 ; sans `vendor_cve_count` 0,0046 ; sans `exploitdb_before_t0` 0,0050 ; sans variables CVSS 0,0114 ; **avec `n_references` 0,0463**.
- Le bond avec `n_references` (×6) confirme le risque de fuite : cette variable reste exclue.
- Sans variables CVSS, le score monte : avec si peu de positifs, ces variables ajoutent surtout du bruit. À ne pas sur-interpréter.
- **Classes** : pondération 0,0076 contre SMOTE 0,0044 → pondération conservée.

## 5. Explications
Importance SHAP moyenne par variable : `cwe` 1,32 ; `ui` 1,07 ; `i` 0,92 ; `cvss_base` 0,59 ; `a` 0,55 ; `c` 0,44 ; `pr` 0,35 ; `av` 0,31. Stabilité entre deux moitiés chronologiques du test : Spearman 0,99. Exemples locaux : `reports/examples.md`. `vendor_cve_count` pèse beaucoup dans les exemples (+2,7 à +4,2 log-odds) : le modèle repère surtout les éditeurs très touchés.

## 6. Limites
Très peu de positifs ; un seul test (2026) ; KEV est biaisé vers les produits d'entreprise connus ; enrichissement NVD (CVSS/CWE/CPE) ajouté après publication, donc possible regard légèrement vers l'avant ; `vendor_cve_count` limité aux données NVD depuis 2018 ; CVSS v4 sans composante « S » ; les résultats ZAP n'ont presque jamais de CVE, donc le prototype renverra surtout `cwe_rate` ou `prior`.

## 7. Reproduire
`make dataset train evaluate` depuis `ml/m1` (le test ne peut être évalué qu'une fois ; supprimer `test_evaluation.lock` pour recommencer, en le documentant).
