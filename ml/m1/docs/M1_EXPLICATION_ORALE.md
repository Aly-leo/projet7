# M1 expliqué à l'oral (3 minutes)

**En une phrase** : M1 estime la probabilité qu'une faille (CVE) soit ajoutée au catalogue KEV de la CISA, c'est-à-dire exploitée pour de vrai, dans les 90 jours.

**Les données** : les fiches NVD (description technique), le catalogue KEV (la vérité), Exploit-DB (exploits publics) et EPSS (un score tiers, utilisé seulement pour comparer).

**Le piège à éviter** : regarder le futur. Donc : la date de référence est fixée à un mois après la publication, les variables ne regardent que le passé, les périodes d'entraînement, validation et test se suivent dans le temps sans se chevaucher, et le test n'est utilisé qu'une fois.

**Le modèle** : une régression logistique, choisie parce qu'elle fait aussi bien que les modèles plus complexes sur la validation, et qu'elle est plus simple à expliquer.

**Les résultats** : M1 fait environ sept fois mieux que le hasard, et un peu mieux que le score CVSS seul, mais la différence avec CVSS n'est pas statistiquement établie. L'EPSS est meilleur que M1.

**Pourquoi c'est limité** : seulement 22 failles exploitées dans le test. C'est trop peu pour conclure solidement. On le dit clairement plutôt que de le cacher.

**Ce que le prototype en fait** : si le service M1 tourne, il l'utilise et l'indique ; sinon il se replie sur une estimation simulée et le note dans le journal d'audit. M2 reste simulé.

**Questions probables**
- *Pourquoi ne pas utiliser EPSS comme variable ?* Parce qu'on veut le comparer à M1, pas l'y mettre.
- *Pourquoi retirer le nombre de références ?* Il augmente après la publication : le modèle trichait (PR-AUC ×6 quand on l'ajoute).
- *Est-ce fiable ?* Pas assez pour décider seul : c'est une aide à la priorisation, à confirmer avec plus de données.
