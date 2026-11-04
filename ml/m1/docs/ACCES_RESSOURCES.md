# Accès aux ressources externes

Test réalisé depuis la machine de développement le 2026-11-04 (délai de 15 s par requête, `User-Agent` explicite).

| Ressource | Adresse | Résultat | Action nécessaire |
|---|---|---|---|
| Catalogue KEV (JSON) | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | HTTP 200, 1,8 Mo | Aucune |
| Catalogue KEV (CSV) | `https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv` | HTTP 200, 1,1 Mo | Aucune |
| API NVD 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1` | HTTP 200 | **Clé `NVD_API_KEY` absente** : la collecte reste possible mais lente (pause de 6,5 s entre requêtes). Une clé gratuite l'accélère : https://nvd.nist.gov/developers/request-an-api-key |
| Plafond de dates de la NVD | même API, intervalle de publication | 120 jours : HTTP 200 ; 121 jours : HTTP 404 | Fenêtres de 100 jours utilisées (vérifié empiriquement) |
| Scores EPSS quotidiens | `https://epss.empiricalsecurity.com/epss_scores-AAAA-MM-JJ.csv.gz` | HTTP 200, 2,8 Mo (fichier d'il y a 3 jours) | Aucune |
| API EPSS (FIRST) | `https://api.first.org/data/v1/epss?cve=CVE-2021-44228` | HTTP 200 | Aucune (alternative non utilisée) |
| Exploit-DB | `https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv` | HTTP 200 ; colonnes vérifiées (`id`, `file`, `description`, `date_published`, `codes`, …) ; le téléchargement dépasse 15 s, le collecteur utilise 180 s | Aucune |
| PyPI | `https://pypi.org/simple/pandas/` | HTTP 200 | Aucune |

Aucune ressource n'est inaccessible : le protocole « ressource inaccessible » (`RESSOURCES_A_FOURNIR.md`) n'a pas été déclenché.
