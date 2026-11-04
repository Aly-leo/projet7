"""Inférence de M1 : probabilité calibrée par CVE (ou par variables fournies), repli par CWE puis prévalence globale.

Aucune valeur n'est inventée : `source` indique toujours d'où vient la probabilité.
  - m1        : le modèle entraîné (CVE connu de la table de consultation, ou variables fournies) ;
  - cwe_rate  : taux historique (lissé) des CVE ayant ce CWE ;
  - prior     : prévalence globale (dernier recours).
"""
from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from m1.common import INTERIM, MODELS, RAW, read_json

COMPONENTS = ["av", "ac", "pr", "ui", "s", "c", "i", "a"]
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def normalize_cwe(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip().upper()
    if re.fullmatch(r"\d{1,5}", s):
        return f"CWE-{s}"
    return s if re.fullmatch(r"(CWE-\d{1,5}|NVD-CWE-OTHER|NVD-CWE-NOINFO)", s) else None


@dataclass
class Prediction:
    probability: float
    source: str
    model_version: str
    calibrated: bool
    already_in_kev: bool | None = None


class M1Predictor:
    def __init__(self, model_dir: Path | str = MODELS):
        mdir = Path(model_dir)
        self.art = joblib.load(mdir / "model.joblib")
        cal = joblib.load(mdir / "calibrator.joblib")
        self.calibrator, self.prior = cal["obj"], float(cal["global_prior"])
        rates = pd.read_csv(mdir / "cwe_rates.csv")
        self.cwe_rates = dict(zip(rates["cwe"].str.upper(), rates["taux_historique"]))
        self.version: str = self.art["version"]
        lookup_path = mdir / "cve_lookup.parquet"
        self.lookup = pd.read_parquet(lookup_path).set_index("cve_id") if lookup_path.exists() else None
        self.kev_ids: set[str] = set(json.loads((mdir / "kev_ids.json").read_text())) if (mdir / "kev_ids.json").exists() else set()

    def info(self) -> dict[str, Any]:
        return {"modelVersion": self.version, "model": self.art["best"], "horizonDays": self.art["horizon_days"],
                "label": "CVE ajouté au catalogue KEV (CISA) dans les h jours suivant t0", "trainedAt": self.art["trained_at"],
                "lookupCves": 0 if self.lookup is None else int(len(self.lookup)), "calibration": self.calibrator.method,
                "prior": self.prior}

    def _row(self, cve_id: str | None, features: dict[str, Any] | None) -> dict[str, Any] | None:
        base: dict[str, Any] = {}
        if cve_id and self.lookup is not None and cve_id in self.lookup.index:
            base = self.lookup.loc[cve_id].to_dict()
        elif not features:
            return None
        base.update({k: v for k, v in (features or {}).items() if v is not None})
        row: dict[str, Any] = {c: base.get(c, "UNK") for c in COMPONENTS}
        row["cwe"] = normalize_cwe(base.get("cwe")) or "UNK"
        row["cvss_base"] = float(base["cvss_base"]) if base.get("cvss_base") is not None and not pd.isna(base.get("cvss_base")) else np.nan
        row["vendor_cve_count"] = float(base["vendor_cve_count"]) if base.get("vendor_cve_count") is not None and not pd.isna(base.get("vendor_cve_count")) else np.nan
        row["exploitdb_before_t0"] = int(base.get("exploitdb_before_t0") or 0)
        row["n_references"] = base.get("n_references", np.nan)
        return row

    def predict(self, items: list[dict[str, Any]]) -> list[Prediction]:
        out: list[Prediction | None] = [None] * len(items)
        rows, idx = [], []
        for i, it in enumerate(items):
            cve = (it.get("cveId") or "").upper() or None
            row = self._row(cve, it.get("features"))
            if row is not None:
                rows.append(row)
                idx.append(i)
            else:
                rate = self.cwe_rates.get(normalize_cwe(it.get("cweId")) or "")
                out[i] = Prediction(float(rate), "cwe_rate", self.version, False) if rate is not None else Prediction(self.prior, "prior", self.version, False)
        if rows:
            df = pd.DataFrame(rows)
            df["cwe"] = df["cwe"].where(df["cwe"].isin(self.art["top_cwe"]), "OTHER")
            raw = self.art["pipeline"].predict_proba(df[self.art["features"]])[:, 1]
            cal = self.calibrator.predict(raw)
            for j, i in enumerate(idx):
                cve = (items[i].get("cveId") or "").upper() or None
                out[i] = Prediction(float(np.clip(cal[j], 0.0, 1.0)), "m1", self.version, True, (cve in self.kev_ids) if cve else None)
        return [p for p in out if p is not None]


def build_lookup(model_dir: Path = MODELS) -> None:
    """Table de consultation : variables de chaque CVE connu de la NVD à la date de collecte (instantané), pour l'inférence par `cveId`."""
    from m1.build_dataset import load_nvd, vendor_index

    nvd = load_nvd()
    nvd = nvd[nvd["vuln_status"].fillna("").str.lower() != "rejected"]
    vidx = vendor_index(nvd)
    exp = pd.read_parquet(INTERIM / "exploitdb_cve_dates.parquet").set_index("cve_id")["exploit_date"]
    kev_meta = read_json(INTERIM / "kev_meta.json")
    kev = json.loads((RAW / "kev" / kev_meta["file"]).read_text(encoding="utf-8"))["vulnerabilities"]
    now = pd.Timestamp.now().normalize()
    df = nvd[["cve_id", "cvss_base", *COMPONENTS, "cwe", "vendor", "n_references"]].copy()
    df["vendor_cve_count"] = [max(0, len(vidx[v]) - 1) if v in vidx else np.nan for v in nvd["vendor"]]
    df["exploitdb_before_t0"] = df["cve_id"].map(exp).le(now).fillna(False).astype(int)
    df.to_parquet(model_dir / "cve_lookup.parquet", index=False)
    (model_dir / "kev_ids.json").write_text(json.dumps(sorted(v["cveID"].upper() for v in kev)))
    print(f"table de consultation : {len(df)} CVE ; {len(kev)} CVE dans KEV")


def main() -> None:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("build-lookup")
    p = sub.add_parser("predict")
    p.add_argument("--cve", nargs="*", default=[])
    p.add_argument("--cwe", nargs="*", default=[])
    p.add_argument("--model-dir", default=str(MODELS))
    a = ap.parse_args()
    if a.cmd == "build-lookup":
        build_lookup()
        return
    m = M1Predictor(a.model_dir)
    items = [{"cveId": c} for c in a.cve] + [{"cweId": c} for c in a.cwe]
    for it, pr in zip(items, m.predict(items)):
        print(it, f"{pr.probability:.5f}", pr.source)


if __name__ == "__main__":
    main()
