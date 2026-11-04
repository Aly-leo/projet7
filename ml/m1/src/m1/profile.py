"""Profil du jeu de données (reports/dataset_profile.md) : effectifs, prévalences, valeurs manquantes, versions de CVSS."""
from __future__ import annotations

import pandas as pd

from m1.common import REPORTS


def md_table(df: pd.DataFrame) -> str:
    cols = list(df.columns)
    lines = ["| " + " | ".join(map(str, cols)) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for _, r in df.iterrows():
        lines.append("| " + " | ".join(f"{v:.4f}" if isinstance(v, float) else str(v) for v in r) + " |")
    return "\n".join(lines)


def write_profile(df: pd.DataFrame, report: dict, features: list[str]) -> None:
    h = report["h"]
    by_year = df.groupby(df["t0"].dt.year).agg(cve=("cve_id", "size"), positifs=("label", "sum"), prevalence=("label", "mean")).reset_index().rename(columns={"t0": "année de t0"})
    by_split = df.groupby("split").agg(cve=("cve_id", "size"), positifs=("label", "sum"), prevalence=("label", "mean"), t0_min=("t0", lambda s: s.min().date()), t0_max=("t0", lambda s: s.max().date())).reset_index()
    missing = pd.DataFrame({"variable": features + ["epss_t0"],
                            "part manquante": [float(df[c].isna().mean() + (df[c].eq("UNK").mean() if df[c].dtype == object else 0)) for c in features + ["epss_t0"]]})
    cvss = df["cvss_version"].fillna("aucune").value_counts(normalize=True).rename_axis("version CVSS").reset_index(name="part")
    parts = [
        f"# Profil du jeu de données (h = {h} jours)", "",
        f"Date de collecte : {report['collection_date']} · lancement de KEV détecté le {report['kev_launch_date']}.", "",
        "## Construction de la cohorte", "",
        f"- CVE dans la NVD collectée : {report['n_nvd_total']} (dont {report['n_rejected']} rejetés, retirés).",
        f"- Après retrait des rejetés : {report['n_before_cohort']}.",
        f"- Cohorte après le lancement de KEV (t0 > {report['kev_launch_date']}) : {report['n_after_kev_launch']}.",
        f"- Exclus car déjà dans KEV avant t0 : {report['n_excluded_already_in_kev']}.",
        f"- Exclus car étiquette non mûre (t0 + h > date de collecte) : {report['n_excluded_immature_label']}.",
        f"- **Lignes retenues : {len(df)} ; positifs : {int(df.label.sum())} (prévalence {df.label.mean():.4%}).**", "",
        "## Découpage chronologique", "",
        f"Coupures sur t0 : entraînement ≤ {report['cutoffs']['train_end_t0']} ; validation ≤ {report['cutoffs']['val_end_t0']} ; test au-delà. "
        "Les lignes « purged » sont retirées : leur fenêtre d'étiquette déborde sur la période suivante.", "", md_table(by_split), "",
        "## Effectifs et prévalence par année de t0", "", md_table(by_year), "",
        "## Valeurs manquantes", "", "La part inclut la valeur `UNK` pour les variables catégorielles. EPSS est une référence, jamais une variable.", "", md_table(missing), "",
        "## Version de CVSS utilisée", "", md_table(cvss), "",
        f"Part de CVE sans score CVSS à la collecte : {report['share_without_cvss_at_collection']:.2%}. Couverture EPSS à t0 : {report['epss_coverage']:.2%}.", "",
    ]
    REPORTS.mkdir(parents=True, exist_ok=True)
    (REPORTS / f"dataset_profile{'' if h == 90 else f'_h{h}'}.md").write_text("\n".join(parts), encoding="utf-8")
