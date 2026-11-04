"""Entraînement de M1 : réglage chronologique, comparaison sur la VALIDATION, calibration, sauvegarde des artefacts.

Le jeu de TEST n'est jamais lu ici (voir evaluate.py, qui l'évalue une seule fois).
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, brier_score_loss

from m1.common import MODELS, PROCESSED, ROOT, load_config, read_json, seed_everything, sha256_file, utc_now, write_json
from m1.modeling import (
    GRIDS,
    MODEL_ORDER,
    IsotonicCalibrator,
    PlattCalibrator,
    apply_top_cwe,
    best_f1_threshold,
    ece,
    feature_lists,
    make_pipeline,
    oof_calibrated,
)


def load_dataset(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["published", "t0", "kev_date_added", "collection_date"])
    assert df["cve_id"].is_unique, "une seule ligne par CVE est exigée (anti-fuite)"
    return df


def time_cv_folds(train: pd.DataFrame, h: int, bounds=(0.4, 0.6, 0.8, 1.0)):
    """3 découpages à fenêtre croissante, par t0, bornes définies sur la part cumulée des POSITIFS ; purge des étiquettes."""
    per_t0 = train.groupby("t0")["label"].sum().sort_index()
    cum = (per_t0.cumsum() / max(1, per_t0.sum())).to_numpy()
    edges = [per_t0.index[int(np.argmax(cum >= b))] for b in bounds]
    for i in range(len(edges) - 1):
        tr_mask = train["t0"] <= edges[i]
        va_mask = (train["t0"] > edges[i]) & (train["t0"] <= edges[i + 1])
        if not va_mask.any():
            continue
        va_start = train.loc[va_mask, "t0"].min()
        tr_mask &= (train["t0"] + pd.Timedelta(days=h)) <= va_start  # purge
        yield train[tr_mask], train[va_mask]


def tune(name: str, train: pd.DataFrame, h: int, cat, num, seed: int, quick: bool) -> tuple[dict, list[dict]]:
    grid = GRIDS[name][: 2 if quick else None]
    table = []
    for params in grid:
        scores = []
        for tr, va in time_cv_folds(train, h):
            if va["label"].sum() == 0 or tr["label"].sum() == 0:
                continue
            pw = float((tr.label == 0).sum() / max(1, tr.label.sum()))
            pipe = make_pipeline(name, params, cat, num, seed, pw).fit(tr[cat + num], tr.label)
            scores.append(float(average_precision_score(va.label, pipe.predict_proba(va[cat + num])[:, 1])))
        table.append({"params": params, "cv_pr_auc_mean": float(np.mean(scores)) if scores else float("nan"), "folds": scores})
    best = max((t for t in table if not np.isnan(t["cv_pr_auc_mean"])), key=lambda t: t["cv_pr_auc_mean"])
    return best["params"], table


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default=str(PROCESSED / "m1_dataset.csv"))
    ap.add_argument("--out", default=str(MODELS))
    ap.add_argument("--drop-features", default="", help="variables à exclure, séparées par des virgules")
    ap.add_argument("--add-features", default="", help="variables à ajouter (ex. n_references) : analyse d'ablation")
    ap.add_argument("--model", default="auto", choices=["auto", *MODEL_ORDER])
    ap.add_argument("--quick", action="store_true", help="grilles réduites (tests rapides)")
    a = ap.parse_args()

    cfg = load_config()
    seed = cfg["seed"]
    seed_everything(seed)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    df = load_dataset(Path(a.data))
    h = int(df["h"].iloc[0])
    cat, num = feature_lists(cfg, [c for c in a.drop_features.split(",") if c], [c for c in a.add_features.split(",") if c])

    tr = df[df.split == "train"]
    va = df[df.split == "val"]
    assert len(tr) and len(va), "découpage vide"
    assert tr.label.sum() > 0 and va.label.sum() > 0, "aucun positif dans l'entraînement ou la validation"
    top = tr["cwe"].value_counts().head(cfg["cwe_top_n"]).index.tolist()
    tr, va = apply_top_cwe(tr, top), apply_top_cwe(va, top)

    t_start = time.time()
    chosen, cv_tables, val_scores, fitted = {}, {}, {}, {}
    for name in MODEL_ORDER:
        if a.model not in ("auto", name):
            continue
        params, table = tune(name, tr, h, cat, num, seed, a.quick)
        pw = float((tr.label == 0).sum() / tr.label.sum())
        pipe = make_pipeline(name, params, cat, num, seed, pw).fit(tr[cat + num], tr.label)
        val_scores[name] = float(average_precision_score(va.label, pipe.predict_proba(va[cat + num])[:, 1]))
        chosen[name], cv_tables[name], fitted[name] = params, table, pipe
        print(f"[{time.time() - t_start:6.0f}s] {name:14s} params={params}  CV PR-AUC={max(t['cv_pr_auc_mean'] for t in table):.4f}  validation PR-AUC={val_scores[name]:.4f}")

    # Sélection sur la VALIDATION ; à égalité (écart < 0,002), le modèle le plus simple. Jamais selon le test.
    top_score = max(val_scores.values())
    best = next(n for n in MODEL_ORDER if n in val_scores and val_scores[n] >= top_score - 0.002)
    model = fitted[best]
    print("modèle retenu :", best)

    # Calibration : Platt par défaut, isotonique comparée en ajustement croisé sur la validation.
    y_va = va.label.to_numpy()
    p_va = model.predict_proba(va[cat + num])[:, 1]
    oof_platt = oof_calibrated(PlattCalibrator, p_va, y_va)
    oof_iso = oof_calibrated(IsotonicCalibrator, p_va, y_va)
    cal_cmp = {
        "brut": {"brier": float(brier_score_loss(y_va, p_va)), "ece": ece(y_va, p_va)},
        "platt_oof": {"brier": float(brier_score_loss(y_va, oof_platt)), "ece": ece(y_va, oof_platt)},
        "isotonic_oof": {"brier": float(brier_score_loss(y_va, oof_iso)), "ece": ece(y_va, oof_iso)},
    }
    iso_clearly_better = (cal_cmp["isotonic_oof"]["brier"] <= 0.9 * cal_cmp["platt_oof"]["brier"]
                          and cal_cmp["isotonic_oof"]["ece"] < cal_cmp["platt_oof"]["ece"])
    calibrator = (IsotonicCalibrator() if iso_clearly_better else PlattCalibrator()).fit(p_va, y_va)
    thr = best_f1_threshold(y_va, calibrator.predict(p_va))

    # Taux historique par CWE (repli sans CVE), lissé vers la prévalence globale ; entraînement + validation seulement.
    trv = pd.concat([tr, va])
    # Lissage bayésien : le prior pèse « k positifs fictifs » (alpha = k / prévalence). Avec un alpha fixe de quelques dizaines
    # d'observations, un CWE sans aucun positif sur des milliers de CVE tombait à ~1e-6, une certitude que les données ne justifient pas.
    p0 = trv.label.mean()
    alpha = cfg["cwe_smoothing_pseudo_positives"] / p0
    g = trv.groupby("cwe").agg(n=("label", "size"), positifs=("label", "sum")).reset_index()
    g["taux_historique"] = (g.positifs + alpha * p0) / (g.n + alpha)
    g.to_csv(out / "cwe_rates.csv", index=False)

    joblib.dump({"pipeline": model, "features": cat + num, "cat": cat, "num": num, "top_cwe": top, "best": best, "params": chosen[best],
                 "horizon_days": h, "version": "m1_v1", "trained_at": utc_now().isoformat(timespec="seconds")}, out / "model.joblib")
    joblib.dump({"method": calibrator.method, "obj": calibrator, "threshold_f1_validation": thr, "global_prior": float(p0)}, out / "calibrator.joblib")
    val_report = {"model": best, "horizon_days": h, "chosen_params": chosen, "validation_pr_auc": val_scores, "cv_tables": cv_tables,
                  "calibration_comparison": cal_cmp, "calibration_used": calibrator.method, "isotonic_clearly_better": bool(iso_clearly_better),
                  "threshold_f1_on_validation": thr, "features": cat + num, "dropped": a.drop_features, "added": a.add_features,
                  "n": {"train": len(tr), "val": len(va)}, "positives": {"train": int(tr.label.sum()), "val": int(va.label.sum())},
                  "train_seconds": round(time.time() - t_start, 1)}
    write_json(out / "validation_report.json", val_report)

    shutil.copy(ROOT / "config" / "m1.yaml", out / "config.yaml")
    import importlib.metadata as md
    pkgs = ["pandas", "numpy", "scikit-learn", "xgboost", "shap", "scipy", "joblib", "pyarrow", "fastapi", "pydantic"]
    write_json(out / "environment.json", {"python": sys.version, "platform": platform.platform(), "packages": {p: md.version(p) for p in pkgs}})
    manifest = read_json(PROCESSED.parent / "raw" / "manifest.json") if (PROCESSED.parent / "raw" / "manifest.json").exists() else {}
    write_json(out / "data_manifest.json", {"raw": manifest, "dataset": {"file": Path(a.data).name, "sha256": sha256_file(Path(a.data)), "rows": len(df)}})
    print(json.dumps({k: val_report[k] for k in ("model", "validation_pr_auc", "calibration_used", "threshold_f1_on_validation")}, indent=2))


if __name__ == "__main__":
    main()
