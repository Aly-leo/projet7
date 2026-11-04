"""Collecte des scores EPSS quotidiens (référence de comparaison, JAMAIS une variable).

Ne télécharge que les dates listées dans data/interim/epss_dates.txt (une date AAAA-MM-JJ par ligne).
Si le fichier d'une date n'existe pas, on prend la date antérieure la plus proche dans les 7 jours, sinon on note l'absence.
"""
from __future__ import annotations

import argparse
import gzip
import io
import re
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
from tqdm import tqdm

from m1.common import INTERIM, RAW, FetchError, http_get, update_manifest, write_json

URL = "https://epss.empiricalsecurity.com/epss_scores-{d}.csv.gz"


def fetch_day(d: date) -> tuple[pd.DataFrame, str] | None:
    try:
        resp = http_get(URL.format(d=d.isoformat()), retries=2, timeout=120)
    except FetchError:
        return None
    text = gzip.decompress(resp.content).decode("utf-8")
    header, _, body = text.partition("\n")
    if not header.startswith("#"):  # certains fichiers anciens n'ont pas de ligne de commentaire
        header, body = "", text
    version = re.search(r"model_version:([^,]+)", header)
    df = pd.read_csv(io.StringIO(body), usecols=["cve", "epss", "percentile"])
    return df, (version.group(1) if version else "inconnue")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dates-file", default=str(INTERIM / "epss_dates.txt"))
    a = ap.parse_args()
    dates = [date.fromisoformat(x.strip()) for x in Path(a.dates_file).read_text().split() if x.strip()]
    out = RAW / "epss"
    out.mkdir(parents=True, exist_ok=True)
    resolved: dict[str, dict] = {}
    for d in tqdm(dates, desc="EPSS"):
        target = out / f"epss_{d.isoformat()}.parquet"
        meta = out / f"epss_{d.isoformat()}.meta.txt"
        if target.exists():
            resolved[d.isoformat()] = {"used": meta.read_text().split("|")[0], "version": meta.read_text().split("|")[1]}
            continue
        got = None
        for back in range(0, 8):
            day = d - timedelta(days=back)
            got = fetch_day(day)
            if got:
                df, version = got
                df.to_parquet(target, index=False)
                meta.write_text(f"{day.isoformat()}|{version}")
                resolved[d.isoformat()] = {"used": day.isoformat(), "version": version}
                break
        if not got:
            resolved[d.isoformat()] = {"used": None, "version": None}
    missing = [k for k, v in resolved.items() if v["used"] is None]
    write_json(INTERIM / "epss_resolved.json", resolved)
    update_manifest("epss", {"dates_requested": len(dates), "dates_missing": missing, "files": len(list(out.glob("*.parquet")))})
    print(f"EPSS : {len(dates) - len(missing)}/{len(dates)} dates résolues ; absentes : {missing[:10]}")


if __name__ == "__main__":
    main()
