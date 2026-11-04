"""Briques communes de modélisation : variables, pipelines, calibration, métriques."""
from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, brier_score_loss, f1_score, roc_auc_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from xgboost import XGBClassifier

MODEL_ORDER = ["logreg", "random_forest", "xgboost"]  # du plus simple au plus complexe (départage des égalités)


def feature_lists(cfg: dict, drop: list[str] | None = None, add: list[str] | None = None) -> tuple[list[str], list[str]]:
    drop = set(drop or [])
    cat = [c for c in cfg["features"]["categorical"] if c not in drop]
    num = [c for c in cfg["features"]["numeric"] if c not in drop]
    for extra in add or []:
        (num if extra in ("n_references",) else cat).append(extra)
    assert "epss_t0" not in cat + num, "epss_t0 est une référence, jamais une variable"
    return cat, num


def apply_top_cwe(df: pd.DataFrame, top: list[str]) -> pd.DataFrame:
    out = df.copy()
    out["cwe"] = out["cwe"].where(out["cwe"].isin(top), "OTHER")
    return out


def make_pipeline(name: str, params: dict[str, Any], cat: list[str], num: list[str], seed: int, pos_weight: float = 1.0) -> Pipeline:
    ohe = lambda: OneHotEncoder(handle_unknown="ignore", sparse_output=False)  # noqa: E731
    imp = lambda: SimpleImputer(strategy="median", add_indicator=True, keep_empty_features=True)  # noqa: E731
    if name == "logreg":
        pre = ColumnTransformer([("cat", ohe(), cat), ("num", Pipeline([("imp", imp()), ("sc", StandardScaler())]), num)])
        est = LogisticRegression(class_weight="balanced", max_iter=3000, **params)
    elif name == "random_forest":
        pre = ColumnTransformer([("cat", ohe(), cat), ("num", imp(), num)])
        est = RandomForestClassifier(class_weight="balanced_subsample", n_jobs=-1, random_state=seed, **{"n_estimators": 300, **params})
    elif name == "xgboost":
        pre = ColumnTransformer([("cat", ohe(), cat), ("num", imp(), num)])
        est = XGBClassifier(subsample=0.8, colsample_bytree=0.8, scale_pos_weight=pos_weight, eval_metric="aucpr",
                            tree_method="hist", random_state=seed, n_jobs=-1, **params)
    else:
        raise ValueError(name)
    return Pipeline([("pre", pre), ("m", est)])


GRIDS: dict[str, list[dict[str, Any]]] = {
    "logreg": [{"C": c} for c in (0.05, 0.2, 1.0, 5.0)],
    "random_forest": [{"min_samples_leaf": m} for m in (3, 10, 20)],
    "xgboost": [{"max_depth": d, "learning_rate": lr, "n_estimators": n} for d in (3, 4, 6) for lr in (0.03, 0.1) for n in (200, 400, 600)],
}


# ----------------------------------------------------------------------------------------------------------------
# Calibration
# ----------------------------------------------------------------------------------------------------------------
def logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p)).reshape(-1, 1)


class PlattCalibrator:
    method = "platt"

    def fit(self, p: np.ndarray, y: np.ndarray) -> "PlattCalibrator":
        self.lr = LogisticRegression(C=1e6, max_iter=1000).fit(logit(p), y)
        return self

    def predict(self, p: np.ndarray) -> np.ndarray:
        return self.lr.predict_proba(logit(p))[:, 1]


class IsotonicCalibrator:
    method = "isotonic"

    def fit(self, p: np.ndarray, y: np.ndarray) -> "IsotonicCalibrator":
        self.iso = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0).fit(p, y)
        return self

    def predict(self, p: np.ndarray) -> np.ndarray:
        return self.iso.predict(p)


def oof_calibrated(make, p: np.ndarray, y: np.ndarray, folds: int = 5, seed: int = 0) -> np.ndarray:
    """Probabilités calibrées « hors échantillon » sur la validation (ajustement croisé)."""
    from sklearn.model_selection import StratifiedKFold

    out = np.zeros_like(p, dtype=float)
    for tr, te in StratifiedKFold(folds, shuffle=True, random_state=seed).split(p, y):
        out[te] = make().fit(p[tr], y[tr]).predict(p[te])
    return out


# ----------------------------------------------------------------------------------------------------------------
# Métriques
# ----------------------------------------------------------------------------------------------------------------
def ece(y: np.ndarray, p: np.ndarray, bins: int = 10) -> float:
    """Expected Calibration Error avec des classes de même effectif."""
    df = pd.DataFrame({"y": y, "p": p}).sort_values("p", kind="stable")
    df["bin"] = pd.qcut(np.arange(len(df)), bins, labels=False, duplicates="drop")
    g = df.groupby("bin").agg(n=("y", "size"), conf=("p", "mean"), acc=("y", "mean"))
    return float((g["n"] / g["n"].sum() * (g["conf"] - g["acc"]).abs()).sum())


def precision_recall_at_k(y: np.ndarray, score: np.ndarray, k: int) -> tuple[float, float]:
    k = max(1, int(k))
    idx = np.argsort(-score, kind="stable")[:k]
    return float(y[idx].mean()), float(y[idx].sum() / max(1, y.sum()))


def metrics_block(y: np.ndarray, score: np.ndarray, prob: np.ndarray | None = None) -> dict[str, float]:
    out = {"pr_auc": float(average_precision_score(y, score)), "roc_auc": float(roc_auc_score(y, score)),
           "prevalence": float(y.mean()), "n": int(len(y)), "positives": int(y.sum())}
    for frac in (0.01, 0.05):
        pk, rk = precision_recall_at_k(y, score, int(len(y) * frac))
        out[f"precision@{int(frac * 100)}%"] = pk
        out[f"recall@{int(frac * 100)}%"] = rk
    if prob is not None:
        out["brier"] = float(brier_score_loss(y, prob))
        out["ece"] = ece(y, prob)
    return out


def best_f1_threshold(y: np.ndarray, p: np.ndarray) -> float:
    grid = np.unique(np.quantile(p, np.linspace(0.5, 0.9995, 200)))
    scores = [f1_score(y, p >= t, zero_division=0) for t in grid]
    return float(grid[int(np.argmax(scores))])


def bootstrap(y: np.ndarray, scores: dict[str, np.ndarray], fns: dict[str, Any], draws: int, seed: int = 0) -> dict[str, Any]:
    """Bootstrap apparié : mêmes lignes tirées pour tous les scores ; IC 95 % par score et différences M1 − autre."""
    rng = np.random.default_rng(seed)
    n = len(y)
    names = list(scores)
    vals = {(s, f): [] for s in names for f in fns}
    for _ in range(draws):
        idx = rng.integers(0, n, n)
        if y[idx].sum() == 0:
            continue
        for s in names:
            for f, fn in fns.items():
                vals[(s, f)].append(fn(y[idx], scores[s][idx]))
    ci = lambda v: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))]  # noqa: E731
    out: dict[str, Any] = {"ci95": {s: {f: ci(vals[(s, f)]) for f in fns} for s in names}, "paired_diff": {}}
    ref = names[0]
    for s in names[1:]:
        out["paired_diff"][f"{ref}_minus_{s}"] = {
            f: {"mean": float(np.mean(np.array(vals[(ref, f)]) - np.array(vals[(s, f)]))),
                "ci95": ci(np.array(vals[(ref, f)]) - np.array(vals[(s, f)]))}
            for f in fns
        }
    out["draws_used"] = len(vals[(ref, next(iter(fns)))])
    return out
