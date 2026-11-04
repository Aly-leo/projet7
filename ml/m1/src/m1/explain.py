"""Explicabilité de M1 : SHAP (importances par variable d'origine), exemples locaux, stabilité.

Les explications décrivent le modèle ; elles ne servent à aucun choix (le test n'est pas utilisé pour sélectionner).
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import shap  # noqa: E402
from scipy.stats import spearmanr  # noqa: E402

from m1.common import MODELS, PROCESSED, REPORTS, load_config, write_json  # noqa: E402
from m1.modeling import apply_top_cwe, make_pipeline  # noqa: E402
from m1.train import load_dataset  # noqa: E402


def original_feature(name: str, cat: list[str], num: list[str]) -> str:
    """cat__av_N -> av ; num__missingindicator_cvss_base -> cvss_base ; ..."""
    body = name.split("__", 1)[1]
    body = re.sub(r"^missingindicator_", "", body)
    for c in sorted(cat + num, key=len, reverse=True):
        if body == c or body.startswith(c + "_"):
            return c
    return body


def shap_values(pipe, X: pd.DataFrame, background: pd.DataFrame | None = None):
    pre, est = pipe.named_steps["pre"], pipe.named_steps["m"]
    Xt = pre.transform(X)
    if hasattr(est, "feature_importances_"):
        sv = shap.TreeExplainer(est).shap_values(Xt)
        sv = sv[:, :, 1] if getattr(sv, "ndim", 2) == 3 else sv
    else:
        bt = pre.transform(background if background is not None else X.head(2000))
        sv = shap.LinearExplainer(est, bt).shap_values(Xt)
    return np.asarray(sv), list(pre.get_feature_names_out())


def grouped_importance(sv: np.ndarray, names: list[str], cat: list[str], num: list[str]) -> pd.Series:
    """Importance moyenne |SHAP| par VARIABLE D'ORIGINE (les colonnes indicatrices d'une même variable sont additionnées avant la valeur absolue)."""
    groups: dict[str, list[int]] = {}
    for i, n in enumerate(names):
        groups.setdefault(original_feature(n, cat, num), []).append(i)
    return pd.Series({g: float(np.abs(sv[:, idx].sum(axis=1)).mean()) for g, idx in groups.items()}).sort_values(ascending=False)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", default=str(PROCESSED / "m1_dataset.csv"))
    ap.add_argument("--model-dir", default=str(MODELS))
    ap.add_argument("--sample", type=int, default=15000)
    a = ap.parse_args()
    mdir = Path(a.model_dir)
    cfg = load_config()
    art, cal = joblib.load(mdir / "model.joblib"), joblib.load(mdir / "calibrator.joblib")
    df = load_dataset(Path(a.data))
    cat, num, feats = art["cat"], art["num"], art["features"]
    te = apply_top_cwe(df[df.split == "test"].reset_index(drop=True), art["top_cwe"])
    tr = apply_top_cwe(df[df.split == "train"].reset_index(drop=True), art["top_cwe"])

    rng = np.random.default_rng(cfg["seed"])
    sample = te.iloc[np.sort(rng.choice(len(te), size=min(a.sample, len(te)), replace=False))]
    sv, names = shap_values(art["pipeline"], sample[feats], tr[feats].sample(2000, random_state=cfg["seed"]))
    imp = grouped_importance(sv, names, cat, num)
    imp.rename("mean_abs_shap").to_csv(mdir / "shap_top.csv")

    fig, ax = plt.subplots(figsize=(6, 4))
    imp.head(12)[::-1].plot.barh(ax=ax, color="#477BAD")
    ax.set(xlabel="Moyenne de |SHAP| (échelle log-odds)", title="Importance des variables (M1)")
    fig.tight_layout()
    (REPORTS / "figures").mkdir(parents=True, exist_ok=True)
    fig.savefig(REPORTS / "figures" / "shap_importance.png", dpi=150)
    plt.close(fig)

    # Stabilité : (1) deux moitiés chronologiques du test ; (2) plusieurs graines (réentraînement sur le même jeu d'entraînement).
    order = np.argsort(sample["t0"].to_numpy(), kind="stable")
    half = len(order) // 2
    i1 = grouped_importance(sv[order[:half]], names, cat, num)
    i2 = grouped_importance(sv[order[half:]], names, cat, num).reindex(i1.index)
    stability = {"spearman_deux_moities_chronologiques": float(spearmanr(i1, i2).statistic)}
    seed_imps = []
    if art["best"] != "logreg":
        trn = df[df.split == "train"]
        pw = float((trn.label == 0).sum() / trn.label.sum())
        for s in (1, 2, 3):
            p = make_pipeline(art["best"], art["params"], cat, num, s, pw).fit(apply_top_cwe(trn, art["top_cwe"])[feats], trn.label)
            sv_s, nm_s = shap_values(p, sample[feats])
            seed_imps.append(grouped_importance(sv_s, nm_s, cat, num).reindex(imp.index))
        rho = [float(spearmanr(seed_imps[i], seed_imps[j]).statistic) for i in range(3) for j in range(i + 1, 3)]
        stability["spearman_entre_graines"] = {"min": min(rho), "moyenne": float(np.mean(rho)), "graines": [1, 2, 3]}

    # Exemples locaux : 3 vrais positifs, 3 faux négatifs, 3 faux positifs (seuil F1 de la validation).
    raw = art["pipeline"].predict_proba(te[feats])[:, 1]
    p = cal["obj"].predict(raw)
    thr = cal["threshold_f1_validation"]
    te = te.assign(p=p)
    picks = {
        "vrais positifs": te[(te.label == 1) & (te.p >= thr)].nlargest(3, "p"),
        "faux négatifs": te[(te.label == 1) & (te.p < thr)].nsmallest(3, "p"),
        "faux positifs": te[(te.label == 0) & (te.p >= thr)].nlargest(3, "p"),
    }
    lines = ["# Exemples locaux (jeu de test)", "", f"Seuil de décision (F1 sur la validation) : {thr:.4f}. Les contributions sont en log-odds (SHAP), regroupées par variable.", ""]
    for title, rows in picks.items():
        lines += [f"## {title.capitalize()}", ""]
        if rows.empty:
            lines += ["_Aucun cas dans cette catégorie._", ""]
            continue
        sv_r, nm_r = shap_values(art["pipeline"], rows[feats], tr[feats].sample(2000, random_state=cfg["seed"]))
        for k, (_, r) in enumerate(rows.iterrows()):
            signed = {}
            for g, idx in {original_feature(n, cat, num): [i for i, m in enumerate(nm_r) if original_feature(m, cat, num) == original_feature(n, cat, num)] for n in nm_r}.items():
                signed[g] = float(sv_r[k, idx].sum())
            top3 = sorted(signed.items(), key=lambda kv: -abs(kv[1]))[:3]
            expl = ", ".join(f"{g} ({v:+.2f})" for g, v in top3)
            lines.append(f"- **{r.cve_id}** — probabilité calibrée {r.p:.4f}, CWE {r.cwe}, CVSS {r.cvss_base}, vecteur d'attaque {r.av}, exploit public avant t0 : {int(r.exploitdb_before_t0)} ; facteurs principaux : {expl}.")
        lines.append("")
    (REPORTS / "examples.md").write_text("\n".join(lines), encoding="utf-8")
    write_json(mdir / "explain_report.json", {"importance": imp.round(5).to_dict(), "stability": stability, "sample_size": int(len(sample))})
    print(imp.head(10).round(4).to_string())
    print(stability)


if __name__ == "__main__":
    main()
