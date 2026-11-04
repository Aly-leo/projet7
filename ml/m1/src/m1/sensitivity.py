"""Analyses de sensibilité, évaluées sur la VALIDATION uniquement (le test n'est utilisé qu'une fois, par evaluate.py).

1. Horizon h : 30, 90, 365 jours (un jeu de données et un modèle par horizon).
2. Ablation des variables : toutes / sans vendor_cve_count / sans exploitdb_before_t0 / sans variables CVSS / avec n_references.
3. Pondération des classes contre SMOTE (SMOTE appliqué à l'entraînement seulement).
"""
from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from imblearn.over_sampling import SMOTE
from sklearn.metrics import average_precision_score, roc_auc_score

from m1.common import MODELS, PROCESSED, load_config, write_json
from m1.modeling import apply_top_cwe, feature_lists, make_pipeline, precision_recall_at_k
from m1.train import load_dataset

CVSS_COLS = ["cvss_base", "av", "ac", "pr", "ui", "s", "c", "i", "a"]


def fit_eval(df: pd.DataFrame, cat: list[str], num: list[str], name: str, params: dict, seed: int, smote: bool = False) -> dict:
    tr, va = df[df.split == "train"], df[df.split == "val"]
    top = tr["cwe"].value_counts().head(30).index.tolist() if "cwe" in cat else []
    if "cwe" in cat:
        tr, va = apply_top_cwe(tr, top), apply_top_cwe(va, top)
    pw = 1.0 if smote else float((tr.label == 0).sum() / max(1, tr.label.sum()))
    pipe = make_pipeline(name, params, cat, num, seed, pw)
    if not smote:
        pipe.fit(tr[cat + num], tr.label)
        p = pipe.predict_proba(va[cat + num])[:, 1]
    else:
        pre = pipe.named_steps["pre"]
        Xt = pre.fit_transform(tr[cat + num], tr.label)
        Xs, ys = SMOTE(sampling_strategy=0.1, random_state=seed, k_neighbors=min(5, int(tr.label.sum()) - 1)).fit_resample(Xt, tr.label)
        pipe.named_steps["m"].fit(Xs, ys)
        p = pipe.named_steps["m"].predict_proba(pre.transform(va[cat + num]))[:, 1]
    y = va.label.to_numpy()
    k = max(1, int(len(y) * 0.01))
    return {"pr_auc": float(average_precision_score(y, p)), "roc_auc": float(roc_auc_score(y, p)),
            "precision@1%": precision_recall_at_k(y, p, k)[0], "n_train": int(len(tr)), "positives_train": int(tr.label.sum()),
            "positives_val": int(y.sum()), "prevalence_val": float(y.mean())}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model-dir", default=str(MODELS))
    a = ap.parse_args()
    cfg = load_config()
    seed = cfg["seed"]
    art = joblib.load(Path(a.model_dir) / "model.joblib")
    name, params = art["best"], art["params"]
    out: dict = {"model": name, "params": params, "evaluated_on": "validation"}

    # 1. Horizon h
    horizons = {}
    for h in cfg["sensitivity_horizons"]:
        f = PROCESSED / ("m1_dataset.csv" if h == cfg["horizon_days"] else f"m1_dataset_h{h}.csv")
        if not f.exists():
            horizons[str(h)] = "jeu de données absent : lancer `python -m m1 dataset --all-horizons`"
            continue
        d = load_dataset(f)
        if (d.split == "val").sum() == 0 or d.loc[d.split == "val", "label"].sum() == 0:
            horizons[str(h)] = "non évaluable : validation sans positif avec ce découpage chronologique (purge des étiquettes immatures)"
            continue
        cat, num = feature_lists(cfg)
        horizons[str(h)] = fit_eval(d, cat, num, name, params, seed)
        print("h =", h, horizons[str(h)])
    out["horizon"] = horizons

    # 2. Ablations
    d = load_dataset(PROCESSED / "m1_dataset.csv")
    variants = {
        "toutes les variables": ([], []),
        "sans vendor_cve_count": (["vendor_cve_count"], []),
        "sans exploitdb_before_t0": (["exploitdb_before_t0"], []),
        "sans variables CVSS": (CVSS_COLS, []),
        "avec n_references (risque de fuite)": ([], ["n_references"]),
    }
    abl = {}
    for label, (drop, add) in variants.items():
        cat, num = feature_lists(cfg, drop, add)
        abl[label] = fit_eval(d, cat, num, name, params, seed)
        print(label, round(abl[label]["pr_auc"], 4))
    out["ablation"] = abl

    # 3. Pondération contre SMOTE
    cat, num = feature_lists(cfg)
    out["classes"] = {"pondération des classes": fit_eval(d, cat, num, name, params, seed),
                      "SMOTE (entraînement seulement, stratégie 0,1)": fit_eval(d, cat, num, name, params, seed, smote=True)}
    print({k: round(v["pr_auc"], 4) for k, v in out["classes"].items()})
    write_json(Path(a.model_dir) / "sensitivity.json", out)


if __name__ == "__main__":
    main()
