"""Évaluation de M1 sur le jeu de TEST, UNE SEULE FOIS (après tous les choix faits sur l'entraînement et la validation).

Un verrou (models/m1_v1/test_evaluation.lock) enregistre l'empreinte du modèle évalué : une seconde exécution sur le même
modèle est refusée (option --allow-rerun pour les contrôles techniques, qui invalide l'usage « une seule fois »).
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.calibration import calibration_curve  # noqa: E402
from sklearn.metrics import average_precision_score, f1_score, precision_recall_curve  # noqa: E402

from m1.common import MODELS, PROCESSED, REPORTS, load_config, sha256_file, utc_now, write_json  # noqa: E402
from m1.modeling import apply_top_cwe, bootstrap, metrics_block, precision_recall_at_k  # noqa: E402
from m1.train import load_dataset  # noqa: E402


def score_frame(art: dict, cal: dict, d: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    d = apply_top_cwe(d, art["top_cwe"])
    raw = art["pipeline"].predict_proba(d[art["features"]])[:, 1]
    return raw, cal["obj"].predict(raw)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default=str(PROCESSED / "m1_dataset.csv"))
    ap.add_argument("--model-dir", default=str(MODELS))
    ap.add_argument("--allow-rerun", action="store_true")
    a = ap.parse_args()
    mdir = Path(a.model_dir)
    cfg = load_config()
    lock = mdir / "test_evaluation.lock"
    fingerprint = sha256_file(mdir / "model.joblib")
    if lock.exists() and not a.allow_rerun and lock.read_text().split()[0] == fingerprint:
        raise SystemExit("Le jeu de test a déjà été évalué pour ce modèle (règle « une seule fois »). Réentraînez, ou --allow-rerun (déconseillé).")

    art, cal = joblib.load(mdir / "model.joblib"), joblib.load(mdir / "calibrator.joblib")
    df = load_dataset(Path(a.data))
    te = df[df.split == "test"].reset_index(drop=True)
    va = df[df.split == "val"]
    assert te.label.sum() >= 1, "aucun positif dans le test"
    y = te.label.to_numpy()
    raw, calibrated = score_frame(art, cal, te)
    cvss = te.cvss_base.fillna(0).to_numpy()
    epss_ok = te.epss_t0.notna().to_numpy()

    thr = cal["threshold_f1_validation"]
    report: dict = {
        "model": art["best"], "model_version": art["version"], "horizon_days": art["horizon_days"], "evaluated_at": utc_now().isoformat(timespec="seconds"),
        "n": {"train": int((df.split == "train").sum()), "val": int(len(va)), "test": int(len(te)), "purged": int((df.split == "purged").sum())},
        "positives": {s: int(df.loc[df.split == s, "label"].sum()) for s in ("train", "val", "test", "purged")},
        "threshold_f1_on_validation": thr, "calibration": cal["method"],
    }
    report["test_m1_brut"] = metrics_block(y, raw, np.clip(raw, 0, 1))
    report["test_m1_calibre"] = metrics_block(y, calibrated, calibrated)
    report["test_m1_calibre"]["f1_at_threshold"] = float(f1_score(y, calibrated >= thr, zero_division=0))
    report["reference_cvss"] = metrics_block(y, cvss)
    report["epss_coverage"] = float(epss_ok.mean())
    if epss_ok.sum() > 0 and y[epss_ok].sum() > 0:
        report["reference_epss_t0_subset"] = metrics_block(y[epss_ok], te.epss_t0.to_numpy()[epss_ok])
        report["m1_calibre_same_subset_as_epss"] = metrics_block(y[epss_ok], calibrated[epss_ok], calibrated[epss_ok])
        report["reference_cvss_same_subset_as_epss"] = metrics_block(y[epss_ok], cvss[epss_ok])
    report["reference_prevalence_random"] = {"pr_auc": float(y.mean())}

    # Intervalles de confiance et différences appariées (mêmes lignes tirées pour tous les scores).
    k1 = max(1, int(len(y) * 0.01))
    fns = {"pr_auc": average_precision_score, "precision@1%": lambda yy, ss: precision_recall_at_k(yy, ss, max(1, int(len(yy) * 0.01)))[0]}
    report["bootstrap_all_rows"] = bootstrap(y, {"m1": calibrated, "cvss": cvss}, fns, cfg["bootstrap_draws"], cfg["seed"])
    if "reference_epss_t0_subset" in report:
        ye = y[epss_ok]
        report["bootstrap_epss_subset"] = bootstrap(ye, {"m1": calibrated[epss_ok], "epss": te.epss_t0.to_numpy()[epss_ok], "cvss": cvss[epss_ok]},
                                                    fns, cfg["bootstrap_draws"], cfg["seed"])

    # Performance par année de t0 (dans le test).
    by_year = {}
    for yr, g in te.groupby(te["t0"].dt.year):
        idx = g.index.to_numpy()
        if y[idx].sum() == 0:
            by_year[int(yr)] = {"n": int(len(idx)), "positives": 0, "pr_auc": None}
        else:
            by_year[int(yr)] = {"n": int(len(idx)), "positives": int(y[idx].sum()), "pr_auc_m1": float(average_precision_score(y[idx], calibrated[idx])),
                                "pr_auc_cvss": float(average_precision_score(y[idx], cvss[idx])), "prevalence": float(y[idx].mean())}
    report["by_year_test"] = by_year
    report["note_k"] = f"k = 1 % du test = {k1} lignes"
    write_json(mdir / "metrics.json", report)

    # Figures.
    fig_dir = REPORTS / "figures"
    fig_dir.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6, 4.5))
    for label, s, mask in (("M1 calibré", calibrated, None), ("CVSS", cvss, None)):
        p, r, _ = precision_recall_curve(y, s)
        ax.plot(r, p, label=f"{label} (PR-AUC {average_precision_score(y, s):.3f})")
    if "reference_epss_t0_subset" in report:
        p, r, _ = precision_recall_curve(y[epss_ok], te.epss_t0.to_numpy()[epss_ok])
        ax.plot(r, p, label=f"EPSS à t0, sous-ensemble ({average_precision_score(y[epss_ok], te.epss_t0.to_numpy()[epss_ok]):.3f})")
    ax.axhline(y.mean(), ls=":", c="grey", label=f"prévalence ({y.mean():.4f})")
    ax.set(xlabel="Rappel", ylabel="Précision", title="Test : courbes précision-rappel", yscale="log")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(fig_dir / "precision_recall.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(5.2, 4.5))
    for label, s in (("M1 brut", np.clip(raw, 0, 1)), ("M1 calibré", calibrated)):
        frac, mean = calibration_curve(y, s, n_bins=10, strategy="quantile")
        ax.plot(mean, frac, marker="o", label=label)
    top = max(0.05, float(np.max(calibrated)))
    ax.plot([0, top], [0, top], ls="--", c="grey", label="calibration parfaite")
    ax.set(xlabel="Probabilité prédite (moyenne par classe)", ylabel="Fréquence observée", title="Test : diagramme de fiabilité", xscale="log", yscale="log")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(fig_dir / "calibration.png", dpi=150)
    plt.close(fig)

    lock.write_text(f"{fingerprint} evaluated_at={report['evaluated_at']}\n")
    print(json.dumps({k: report[k] for k in ("test_m1_calibre", "reference_cvss", "epss_coverage")}, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
