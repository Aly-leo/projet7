# Décisions de conception de M1

| # | Décision | Raison |
|---|---|---|
| 1 | Étiquette = « ajouté à KEV dans ]t0, t0+h] », h = 90 jours | Définition du cahier des charges ; intervalle ouvert à gauche, fermé à droite (testé). |
| 2 | t0 = 1er jour du mois suivant (publication + 30 jours) | Laisse 30 jours pour que NVD enrichisse la fiche ; une seule date de référence par CVE. |
| 3 | Cohorte restreinte aux CVE dont t0 est postérieur au lancement de KEV (2021-11-03, détecté dans les données) | Avant, KEV était un rattrapage historique (287 ajouts), pas un signal d'exploitation. |
| 4 | Exclusion des CVE déjà dans KEV avant t0 et des étiquettes immatures (t0 + h > date de collecte) | Évite une cible déjà connue et des faux négatifs artificiels. |
| 5 | Découpage chronologique par t0 (~60/20/20 des positifs), purge des lignes dont la fenêtre déborde sur la période suivante | Aucun chevauchement temporel ; 18 563 lignes purgées à h=90. |
| 6 | EPSS jamais utilisé comme variable, seulement comme référence de comparaison | Évite de comparer M1 à un score qu'il aurait en entrée. |
| 7 | `n_references` exclu par défaut | Suspect de fuite : le nombre de références grandit après la publication. L'ablation le confirme (voir rapport). |
| 8 | Trois modèles (régression logistique, forêt aléatoire, XGBoost), réglage par validation croisée chronologique, sélection sur la validation, tolérance 0,002 → le plus simple | Évite de choisir un modèle complexe pour un gain dans le bruit. |
| 9 | Calibration de Platt (isotonique comparée) | Plus stable avec très peu de positifs. |
| 10 | Test évalué une seule fois (fichier verrou) | Évite de régler le modèle sur le test. |
| 11 | **Écart à la règle des 30 positifs** : à h=90 la validation compte 17 positifs et le test 22 | Décision de l'utilisateur de continuer à h=90 plutôt que de changer d'horizon après avoir vu les données. Les résultats sont donc indicatifs et présentés avec leurs intervalles de confiance. |
| 12 | Service d'inférence FastAPI avec jeton, validation stricte, champ `source` toujours renvoyé (m1, cwe_rate, prior) | Le prototype sait toujours d'où vient une probabilité. Repli sur le taux par CWE, puis sur la prévalence. |
| 13 | Dans le prototype, M2 reste simulé ; si le service M1 est indisponible, repli sur la simulation avec audit `M1_SERVICE_FALLBACK` | Pas de panne du prototype ; traçabilité du repli. |
| 14 | M2 reçoit un **niveau relatif** de M1 (log du risque relatif élevé au carré : 1× la moyenne = 0,11, 10× = 0,44, 100× = 1, déjà dans KEV = 1) et non la probabilité brute | La probabilité brute (≈ 0,06 %) rendait M1 inaudible dans M2 dont les seuils sont écrits pour 0,03–0,99. L'adaptateur est dans l'intégration ; la logique de M2 n'est pas modifiée. |
| 15 | Taux historique par CWE lissé avec un prior de 1 positif fictif (alpha = 1 / prévalence), au lieu de 20 observations | Avec 20 observations, un CWE à 0 positif sur 6 387 CVE tombait à 0,000001 : fausse certitude. Décision prise sur les effectifs d'entraînement et de validation, **sans regarder le test** ; le modèle et ses métriques de test sont inchangés (prédictions identiques après réentraînement). |
