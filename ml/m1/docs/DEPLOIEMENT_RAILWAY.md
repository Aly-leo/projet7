# Déployer le service M1 sur Railway

But : que la démo en ligne utilise le vrai M1 V1 (page Modèles : « Modèle entraîné · logreg »), au lieu de l'estimation de repli.

Architecture : un **second service** `m1` dans le projet Railway existant (`projet7-vulnerabilites`, environnement `production`). Le service `app` (API + front) l'appelle par le **réseau privé** de Railway. M1 n'a **pas de domaine public**.

## Fichiers (dans `ml/m1`)
| Fichier | Rôle |
|---|---|
| `Dockerfile` | Image Python 3.13 slim, utilisateur non root, démarre `python -m m1 service` |
| `requirements-service.txt` | Dépendances d'exécution seulement (sans xgboost, shap, matplotlib) |
| `.dockerignore` | Exclut données, tests, rapports, `.venv` |
| `railway.json` | Builder Dockerfile, sonde de santé `/health`, redémarrage sur échec |
| `models/m1_v1/` | Modèle, calibrateur, taux par CWE, **table des CVE (3,7 Mo) et liste KEV**, mesures |

## Étapes

1. **Pousser** les fichiers ci-dessus (Railway construit depuis GitHub).
2. **Créer le service `m1`** : source `Aly-leo/projet7`, branche `main`, **répertoire racine `ml/m1`**, builder Dockerfile (déjà indiqué par `railway.json`). Ne pas générer de domaine public.
3. **Variables du service `m1`** :
   | Variable | Valeur |
   |---|---|
   | `M1_SERVICE_TOKEN` | valeur aléatoire d'au moins 32 caractères, **jamais dans Git** (ex. `python -c "import secrets;print(secrets.token_urlsafe(48))"`). Poser `${{ secret(48) }}` via l'API ne garantit pas la génération (valeurs masquées, non vérifiable) : saisir une valeur connue ou la générer dans l'interface Railway. |
   | `M1_PORT` | `8001` |
   | `PORT` | `8001` (le port que la sonde de santé de Railway interroge) |
   | `M1_HOST` | `0.0.0.0` (écoute IPv4). **Pas `::`** : avec `::`, la sonde de santé de Railway n'aboutit jamais (la connexion TCP n'est pas établie) et le déploiement échoue en « Healthcheck failure », constaté lors du premier déploiement. |
4. Attendre que `m1` soit **sain** (sonde `/health`).
5. **Variables du service `app`** (déclenchent son redéploiement) :
   | Variable | Valeur |
   |---|---|
   | `M1_PROVIDER` | `trained` |
   | `M1_SERVICE_URL` | `http://m1.railway.internal:8001` |
   | `M1_SERVICE_TOKEN` | `${{ m1.M1_SERVICE_TOKEN }}` (référence : le même jeton, sans le copier) |
6. **Vérifier** : page Modèles (administrateur) → M1 « V1 · Modèle entraîné · logreg » et mesures de test affichées ; importer `fixtures/zap/valid-with-cve.json` → M1 « V1 », CVE-2021-44228 détecté et marqué « déjà dans le catalogue KEV ».

## Si le déploiement échoue
- Les journaux de `m1` sont presque vides par défaut (niveau « warning »). Un échec « Healthcheck failure » sans trace signifie en général que la sonde n'atteint pas le port : vérifier `PORT` et `M1_HOST=0.0.0.0`.
- Le jeton ne doit jamais être le texte `${{ secret(48) }}` stocké tel quel : les valeurs sont masquées dans Railway, donc le plus sûr est de le saisir ou de le régénérer dans l'interface.

## Retour arrière
`M1_PROVIDER=simulated` sur `app` (ou supprimer la variable) : l'application repasse immédiatement à l'estimation de repli. Si le service `m1` tombe, l'application se replie seule et journalise `M1_SERVICE_FALLBACK`.

## Sécurité
- Aucun domaine public : seul `app` peut joindre `m1` (réseau privé). Le jeton `X-M1-Token` est exigé quand même, et le service refuse de démarrer sans jeton d'au moins 16 caractères.
- `app` n'envoie que `cveId` et `cweId` (jamais titre, description ni URL du constat).
- Aucun secret dans le dépôt : le jeton n'existe que dans les variables Railway.
- Conteneur non root ; erreurs génériques, documentation de l'API désactivée.

## Limites
- Mémoire : prévoir quelques centaines de Mo (pandas, scikit-learn, table de 305 571 CVE).
- La table des CVE et la liste KEV sont un **instantané du 2026-11-04** : un CVE publié après n'est pas dans la table et reçoit le taux de son CWE. Pour actualiser : refaire la collecte, `python -m m1.infer build-lookup`, versionner, redéployer.
- Un changement de modèle (v2) impose de versionner les nouveaux artefacts et de redéployer `m1`.
- Le `Dockerfile` n'a pas pu être construit sur la machine de développement (Docker Desktop arrêté). Ce qui a été vérifié : un environnement vierge avec **uniquement** `requirements-service.txt` démarre le service et renvoie les mêmes probabilités que l'environnement complet. Le premier build sur Railway valide le reste. Pour tester l'image en local : `docker build -t m1-service ml/m1`, puis `docker run --rm -e M1_SERVICE_TOKEN=<16+ caractères> -p 8001:8001 m1-service`.
