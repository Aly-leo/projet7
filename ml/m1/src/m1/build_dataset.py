"""Construction du jeu de données de M1 : une ligne par CVE, étiquette KEV à l'horizon h, variables calculées avant t0.

Protections contre la fuite d'information (voir docs/M1_REPORT.md) :
- t0 = premier jour du mois suivant (publication + 30 jours) ; cohorte après le lancement de KEV ;
- CVE déjà dans KEV avant t0 : exclus ; étiquettes non mûres (t0 + h > date de collecte) : exclues ;
- epss_t0 est une RÉFÉRENCE de comparaison, jamais une variable ; n_references est exclue des variables par défaut ;
- découpage chronologique par t0, avec purge : une ligne d'entraînement (ou de validation) dont la fenêtre d'étiquette
  [t0, t0 + h] déborde sur la période suivante est retirée (« purged »), pour que l'apprentissage n'utilise aucun
  événement postérieur au début de la période de validation (ou de test).
"""
from __future__ import annotations

import argparse
import gzip
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd

from m1.common import INTERIM, PROCESSED, RAW, load_config, read_json, sha256_file, update_manifest, utc_now, write_json

CVSS_COMPONENTS_V3 = {"AV": "av", "AC": "ac", "PR": "pr", "UI": "ui", "S": "s", "C": "c", "I": "i", "A": "a"}
CVSS_COMPONENTS_V4 = {"AV": "av", "AC": "ac", "PR": "pr", "UI": "ui", "VC": "c", "VI": "i", "VA": "a"}  # v4 : pas de « S »
COMPONENT_COLS = ["av", "ac", "pr", "ui", "s", "c", "i", "a"]


# ----------------------------------------------------------------------------------------------------------------
# NVD
# ----------------------------------------------------------------------------------------------------------------
def pick_metric(entries: list[dict]) -> dict | None:
    if not entries:
        return None
    primary = [e for e in entries if e.get("type") == "Primary"]
    return (primary or entries)[0]


def parse_cvss(metrics: dict) -> dict:
    """CVSS v3.1, sinon v3.0, sinon v4.0 (composantes compatibles), sinon vide. Valeur UNK si absente."""
    out: dict = {"cvss_base": np.nan, "cvss_version": None, **{c: "UNK" for c in COMPONENT_COLS}}
    for key, mapping in (("cvssMetricV31", CVSS_COMPONENTS_V3), ("cvssMetricV30", CVSS_COMPONENTS_V3), ("cvssMetricV40", CVSS_COMPONENTS_V4)):
        m = pick_metric(metrics.get(key) or [])
        if not m:
            continue
        data = m.get("cvssData", {})
        out["cvss_base"] = data.get("baseScore", np.nan)
        out["cvss_version"] = data.get("version")
        vec = data.get("vectorString", "")
        parts = dict(p.split(":", 1) for p in vec.split("/")[1:] if ":" in p)
        for src, col in mapping.items():
            if src in parts:
                out[col] = parts[src]
        return out
    return out


def parse_cwe(weaknesses: list[dict]) -> str:
    """Faiblesse principale : source nvd@nist.gov d'abord, sinon la première. Valeurs spéciales conservées."""
    for source in ("nvd@nist.gov", None):
        for w in weaknesses or []:
            if source and w.get("source") != source:
                continue
            for d in w.get("description", []):
                if d.get("value"):
                    return d["value"]
    return "UNK"


def parse_vendor(configurations: list[dict]) -> str:
    """Éditeur le plus fréquent parmi les CPE vulnérables (champ 4 de cpe:2.3:part:vendor:product:...)."""
    vendors: Counter = Counter()

    def walk(nodes):
        for n in nodes or []:
            for cm in n.get("cpeMatch", []):
                if cm.get("vulnerable", True):
                    parts = cm.get("criteria", "").split(":")
                    if len(parts) > 4 and parts[3] not in ("*", "-", ""):
                        vendors[parts[3]] += 1
            walk(n.get("children"))

    for cfg in configurations or []:
        walk(cfg.get("nodes"))
    return vendors.most_common(1)[0][0] if vendors else "unknown"


def parse_nvd_pages(raw_dir: Path) -> pd.DataFrame:
    rows: dict[str, dict] = {}
    files = sorted(raw_dir.glob("*.json.gz"))
    if not files:
        raise SystemExit(f"Aucune page NVD dans {raw_dir} : lancer d'abord `python -m m1 collect-nvd`.")
    for f in files:
        with gzip.open(f, "rt", encoding="utf-8") as fh:
            data = json.load(fh)
        for item in data.get("vulnerabilities", []):
            c = item["cve"]
            rows[c["id"]] = {
                "cve_id": c["id"].upper(),
                "published": c["published"],
                "vuln_status": c.get("vulnStatus"),
                **parse_cvss(c.get("metrics", {})),
                "cwe": parse_cwe(c.get("weaknesses", [])),
                "vendor": parse_vendor(c.get("configurations", [])),
                "n_references": len(c.get("references", [])),
            }
    df = pd.DataFrame(rows.values())
    df["published"] = pd.to_datetime(df["published"], utc=True).dt.tz_localize(None)
    return df.sort_values("published").reset_index(drop=True)


def load_nvd(force: bool = False) -> pd.DataFrame:
    cache = INTERIM / "nvd_parsed.parquet"
    stamp = INTERIM / "nvd_parsed.stamp"
    files = sorted((RAW / "nvd").glob("*.json.gz"))
    signature = f"{len(files)}|{sum(f.stat().st_size for f in files)}"
    if cache.exists() and stamp.exists() and stamp.read_text() == signature and not force:
        return pd.read_parquet(cache)
    df = parse_nvd_pages(RAW / "nvd")
    INTERIM.mkdir(parents=True, exist_ok=True)
    df.to_parquet(cache, index=False)
    stamp.write_text(signature)
    return df


# ----------------------------------------------------------------------------------------------------------------
# Instant de référence, étiquette, variables d'historique
# ----------------------------------------------------------------------------------------------------------------
def compute_t0(published: pd.Series, delay_days: int = 30) -> pd.Series:
    """t0 = premier jour du mois qui suit (publication + délai) : peu de dates distinctes (utile pour EPSS)."""
    shifted = published.dt.normalize() + pd.Timedelta(days=delay_days)
    return (shifted.dt.to_period("M") + 1).dt.start_time


def label_from_kev(t0: pd.Series, kev_added: pd.Series, h: int) -> pd.Series:
    """1 si ajout à KEV dans ]t0, t0 + h]."""
    end = t0 + pd.Timedelta(days=h)
    return ((kev_added > t0) & (kev_added <= end)).astype(int)


def count_before(pub_by_group: dict[str, np.ndarray], group: pd.Series, when: pd.Series, exclude_self: bool = True) -> np.ndarray:
    """Nombre de CVE du même groupe publiés strictement avant `when` (cumul), hors le CVE lui-même."""
    out = np.full(len(group), np.nan)
    for i, (g, t) in enumerate(zip(group.to_numpy(), when.to_numpy())):
        arr = pub_by_group.get(g)
        if arr is None:
            continue
        n = int(np.searchsorted(arr, t, side="left"))
        out[i] = max(0, n - 1) if exclude_self else n
    return out


def vendor_index(nvd: pd.DataFrame) -> dict[str, np.ndarray]:
    known = nvd[nvd["vendor"] != "unknown"]
    return {v: np.sort(g["published"].to_numpy()) for v, g in known.groupby("vendor")}


# ----------------------------------------------------------------------------------------------------------------
# Découpage chronologique (par positifs) avec purge
# ----------------------------------------------------------------------------------------------------------------
def choose_cutoffs(t0: pd.Series, y: pd.Series, train_share: float, val_share: float) -> tuple[pd.Timestamp, pd.Timestamp]:
    """Dates de coupure (sur t0) telles que les POSITIFS se répartissent à peu près 60 / 20 / 20."""
    pos = pd.DataFrame({"t0": t0, "y": y}).groupby("t0")["y"].sum().sort_index()
    cum = pos.cumsum() / pos.sum()
    t1 = (cum - train_share).abs().idxmin()
    t2 = (cum - (train_share + val_share)).abs().idxmin()
    if t2 <= t1:
        t2 = cum.index[min(len(cum) - 1, list(cum.index).index(t1) + 1)]
    return t1, t2


def assign_split(df: pd.DataFrame, t1: pd.Timestamp, t2: pd.Timestamp, h: int) -> pd.Series:
    split = np.where(df["t0"] <= t1, "train", np.where(df["t0"] <= t2, "val", "test")).astype(object)
    first_val = df.loc[df["t0"] > t1, "t0"].min()
    first_test = df.loc[df["t0"] > t2, "t0"].min()
    window_end = df["t0"] + pd.Timedelta(days=h)
    split[(split == "train") & (window_end > first_val)] = "purged"
    split[(split == "val") & (window_end > first_test)] = "purged"
    return pd.Series(split, index=df.index)


# ----------------------------------------------------------------------------------------------------------------
# EPSS (référence)
# ----------------------------------------------------------------------------------------------------------------
def attach_epss(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["epss_t0"] = np.nan
    parts = []
    for d in sorted(df["t0"].dt.date.unique()):
        f = RAW / "epss" / f"epss_{d.isoformat()}.parquet"
        if not f.exists():
            continue
        e = pd.read_parquet(f).rename(columns={"cve": "cve_id", "epss": "epss_t0_new"})[["cve_id", "epss_t0_new"]]
        e["t0"] = pd.Timestamp(d)
        parts.append(e)
    if parts:
        e = pd.concat(parts)
        df = df.merge(e, on=["cve_id", "t0"], how="left")
        df["epss_t0"] = df["epss_t0_new"]
        df = df.drop(columns=["epss_t0_new"])
    return df


# ----------------------------------------------------------------------------------------------------------------
# Construction
# ----------------------------------------------------------------------------------------------------------------
def build(h: int, cfg: dict, collection_date: pd.Timestamp, use_epss: bool = True) -> tuple[pd.DataFrame, dict]:
    nvd = load_nvd()
    kev_meta = read_json(INTERIM / "kev_meta.json")
    kev = json.loads((RAW / "kev" / kev_meta["file"]).read_text(encoding="utf-8"))["vulnerabilities"]
    kev_added = pd.Series({v["cveID"].upper(): pd.Timestamp(v["dateAdded"]) for v in kev})
    launch = pd.Timestamp(kev_meta["kev_launch_date"])

    report: dict = {"h": h, "n_nvd_total": len(nvd), "collection_date": str(collection_date.date()), "kev_launch_date": str(launch.date())}
    rejected = nvd["vuln_status"].fillna("").str.lower().eq("rejected")
    report["n_rejected"] = int(rejected.sum())

    # Index des compteurs : calculés sur TOUTE la NVD collectée (hors rejetés), pas seulement sur la cohorte.
    nvd_ok = nvd[~rejected].copy()
    vidx = vendor_index(nvd_ok)

    exp_path = INTERIM / "exploitdb_cve_dates.parquet"
    exploit = pd.read_parquet(exp_path).set_index("cve_id")["exploit_date"] if exp_path.exists() else pd.Series(dtype="datetime64[ns]")

    df = nvd_ok.copy()
    df["t0"] = compute_t0(df["published"], cfg["t0_delay_days"])
    df["kev_date_added"] = df["cve_id"].map(kev_added)
    df["h"] = h
    df["collection_date"] = collection_date

    report["n_before_cohort"] = len(df)
    df = df[df["t0"] > launch]
    report["n_after_kev_launch"] = len(df)
    already = df["kev_date_added"].notna() & (df["kev_date_added"] <= df["t0"])
    report["n_excluded_already_in_kev"] = int(already.sum())
    df = df[~already]
    immature = df["t0"] + pd.Timedelta(days=h) > collection_date
    report["n_excluded_immature_label"] = int(immature.sum())
    df = df[~immature].copy()

    df["label"] = label_from_kev(df["t0"], df["kev_date_added"], h)
    # Variables d'historique : uniquement des informations antérieures à t0.
    df["vendor_cve_count"] = count_before(vidx, df["vendor"], df["t0"])
    ex_date = df["cve_id"].map(exploit)
    df["exploitdb_before_t0"] = (ex_date.notna() & (ex_date < df["t0"])).astype(int)

    if use_epss:
        df = attach_epss(df)
    else:
        df["epss_t0"] = np.nan

    t1, t2 = choose_cutoffs(df["t0"], df["label"], cfg["split"]["train_share"], cfg["split"]["val_share"])
    df["split"] = assign_split(df, t1, t2, h)
    report["cutoffs"] = {"train_end_t0": str(t1.date()), "val_end_t0": str(t2.date())}
    report["by_split"] = {s: {"n": int((df.split == s).sum()), "positives": int(df.loc[df.split == s, "label"].sum())} for s in ("train", "val", "test", "purged")}
    report["prevalence"] = float(df["label"].mean())
    report["share_without_cvss_at_collection"] = float(df["cvss_base"].isna().mean())
    report["cvss_version_share"] = df["cvss_version"].fillna("none").value_counts(normalize=True).round(4).to_dict()
    report["epss_coverage"] = float(df["epss_t0"].notna().mean())

    cols = ["cve_id", "published", "t0", "label", "split", "cvss_base", *COMPONENT_COLS, "cwe", "vendor", "vendor_cve_count",
            "exploitdb_before_t0", "n_references", "epss_t0", "kev_date_added", "h", "cvss_version", "collection_date"]
    return df[cols].sort_values(["t0", "cve_id"]).reset_index(drop=True), report


def epss_dates(cfg: dict, collection_date: pd.Timestamp) -> list[str]:
    """Liste des dates t0 distinctes (toutes les cohortes de sensibilité) : sert à ne télécharger que les fichiers EPSS utiles."""
    nvd = load_nvd()
    launch = pd.Timestamp(read_json(INTERIM / "kev_meta.json")["kev_launch_date"])
    t0 = compute_t0(nvd["published"], cfg["t0_delay_days"])
    t0 = t0[(t0 > launch) & (t0 <= collection_date)]
    return sorted({d.date().isoformat() for d in t0.unique()})


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--horizon", type=int, default=None, help="h en jours (défaut : config)")
    ap.add_argument("--all-horizons", action="store_true", help="construit aussi les jeux de sensibilité (30, 90, 365)")
    ap.add_argument("--prepare-only", action="store_true", help="écrit seulement data/interim/epss_dates.txt")
    ap.add_argument("--no-epss", action="store_true")
    a = ap.parse_args()
    cfg = load_config()
    manifest_path = RAW / "manifest.json"
    manifest = read_json(manifest_path) if manifest_path.exists() else {}
    cdate = manifest.get("nvd", {}).get("collection_date") or utc_now().date().isoformat()
    collection_date = pd.Timestamp(cdate)

    INTERIM.mkdir(parents=True, exist_ok=True)
    dates = epss_dates(cfg, collection_date)
    (INTERIM / "epss_dates.txt").write_text("\n".join(dates), encoding="utf-8")
    print(f"{len(dates)} dates EPSS nécessaires -> data/interim/epss_dates.txt")
    if a.prepare_only:
        return

    horizons = cfg["sensitivity_horizons"] if a.all_horizons else [a.horizon or cfg["horizon_days"]]
    PROCESSED.mkdir(parents=True, exist_ok=True)
    reports = {}
    for h in horizons:
        df, rep = build(h, cfg, collection_date, use_epss=not a.no_epss)
        name = "m1_dataset" if h == cfg["horizon_days"] else f"m1_dataset_h{h}"
        df.to_csv(PROCESSED / f"{name}.csv", index=False)
        df.to_parquet(PROCESSED / f"{name}.parquet", index=False)
        rep["file"] = f"{name}.csv"
        rep["sha256"] = sha256_file(PROCESSED / f"{name}.csv")
        rep["rows"] = len(df)
        reports[str(h)] = rep
        from m1.profile import write_profile
        write_profile(df, rep, [c for c in df.columns if c in COMPONENT_COLS or c in ("cvss_base", "cwe", "vendor_cve_count", "exploitdb_before_t0", "n_references")])
        print(f"h={h}: {len(df)} lignes, {int(df.label.sum())} positifs, coupures {rep['cutoffs']}, découpage {rep['by_split']}")
    write_json(INTERIM / "dataset_build_report.json", reports)
    update_manifest("dataset", {h: {"file": r["file"], "sha256": r["sha256"], "rows": r["rows"]} for h, r in reports.items()})


if __name__ == "__main__":
    main()
