# Fiche du modèle M1 v1

- **Objectif** : probabilité qu'un CVE entre dans KEV dans les 90 jours suivant t0.
- **Modèle** : régression logistique pondérée, calibration de Platt. Variables : vecteur CVSS (av, ac, pr, ui, s, c, i, a), CWE (30 plus fréquents), score de base CVSS, `vendor_cve_count`, `exploitdb_before_t0`.
- **Données** : NVD, KEV, Exploit-DB jusqu'au 2026-11-04 ; 103 positifs à h=90.
- **Performance (test, 22 positifs)** : PR-AUC 0,0036 [0,0011 ; 0,0167] ; ROC-AUC 0,815 ; ECE 0,0003. Non distinguable de CVSS ; inférieur à EPSS.
- **Usage prévu** : aide à la priorisation dans le prototype. **Pas** une décision automatique.
- **Limites** : très peu de positifs, un seul test, biais de KEV, enrichissement NVD postérieur à la publication.
- **Reproductibilité** : `config.yaml`, `environment.json`, `data_manifest.json`, graine 42.
