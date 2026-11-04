# Exemples locaux (jeu de test)

Seuil de décision (F1 sur la validation) : 0.0062. Les contributions sont en log-odds (SHAP), regroupées par variable.

## Vrais positifs

- **CVE-2026-20963** — probabilité calibrée 0.0139, CWE CWE-502, CVSS 9.8, vecteur d'attaque N, exploit public avant t0 : 0 ; facteurs principaux : vendor_cve_count (+2.72), cwe (+1.98), cvss_base (+1.10).
- **CVE-2026-53266** — probabilité calibrée 0.0084, CWE NVD-CWE-noinfo, CVSS 8.8, vecteur d'attaque L, exploit public avant t0 : 0 ; facteurs principaux : vendor_cve_count (+4.17), ui (+0.94), cvss_base (+0.72).
- **CVE-2026-33824** — probabilité calibrée 0.0077, CWE OTHER, CVSS 9.8, vecteur d'attaque N, exploit public avant t0 : 0 ; facteurs principaux : vendor_cve_count (+2.87), cvss_base (+1.10), ui (+0.94).

## Faux négatifs

- **CVE-2025-43520** — probabilité calibrée 0.0001, CWE CWE-120, CVSS 5.5, vecteur d'attaque L, exploit public avant t0 : 0 ; facteurs principaux : cwe (-2.80), i (-1.42), vendor_cve_count (+1.28).
- **CVE-2026-21643** — probabilité calibrée 0.0002, CWE CWE-89, CVSS 9.8, vecteur d'attaque N, exploit public avant t0 : 0 ; facteurs principaux : cwe (-3.93), cvss_base (+1.10), ui (+0.94).
- **CVE-2025-68461** — probabilité calibrée 0.0004, CWE CWE-79, CVSS 6.1, vecteur d'attaque N, exploit public avant t0 : 0 ; facteurs principaux : ui (-1.60), i (+1.37), cwe (+1.29).

## Faux positifs

- **CVE-2026-11720** — probabilité calibrée 0.0247, CWE CWE-22, CVSS 9.1, vecteur d'attaque N, exploit public avant t0 : 0 ; facteurs principaux : vendor_cve_count (+3.42), cwe (+2.13), ui (+0.94).
- **CVE-2026-43291** — probabilité calibrée 0.0239, CWE OTHER, CVSS 8.3, vecteur d'attaque A, exploit public avant t0 : 0 ; facteurs principaux : vendor_cve_count (+3.95), i (+1.37), ui (+0.94).
- **CVE-2026-43284** — probabilité calibrée 0.0228, CWE OTHER, CVSS 8.8, vecteur d'attaque L, exploit public avant t0 : 1 ; facteurs principaux : vendor_cve_count (+3.95), exploitdb_before_t0 (+1.42), ui (+0.94).
