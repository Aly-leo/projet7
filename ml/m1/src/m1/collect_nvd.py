"""Collecte de la NVD (API 2.0), par fenêtres de dates de publication, reprenable.

- La clé est lue dans NVD_API_KEY (en-tête `apiKey`) ; jamais écrite ni journalisée.
- Plafond vérifié : un intervalle de 120 jours répond 200, 121 jours répond 404. On utilise des fenêtres de 100 jours.
- Chaque page brute est enregistrée compressée : data/raw/nvd/AAAAMMJJ_debut_fin_pN.json.gz (reprise : une page déjà
  présente n'est pas retéléchargée).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tqdm import tqdm

from m1.common import RAW, http_get, load_config, sha256_file, update_manifest, utc_now

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
FMT = "%Y-%m-%dT%H:%M:%S.000"


def windows(start: datetime, end: datetime, days: int):
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=days), end)
        # bornes inclusives côté API : on retire 1 s à la fin pour ne pas compter deux fois la frontière
        yield cur, (nxt - timedelta(seconds=1) if nxt < end else end)
        cur = nxt


def page_path(out: Path, s: datetime, e: datetime, n: int) -> Path:
    return out / f"{s:%Y%m%d}_{e:%Y%m%d}_p{n}.json.gz"


def fetch_page(s: datetime, e: datetime, start_index: int, page_size: int, headers: dict[str, str]) -> dict:
    params = {"pubStartDate": s.strftime(FMT), "pubEndDate": e.strftime(FMT), "resultsPerPage": page_size, "startIndex": start_index}
    return http_get(API, params=params, headers=headers, retries=3, timeout=120).json()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--start", default=None, help="AAAA-MM-JJ (défaut : config nvd.start_date)")
    ap.add_argument("--end", default=None, help="AAAA-MM-JJ (défaut : maintenant)")
    a = ap.parse_args()
    cfg = load_config()["nvd"]
    key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": key} if key else {}
    pause = 0.7 if key else 6.5  # ~50 requêtes / 30 s avec clé, 5 / 30 s sans clé
    start = datetime.fromisoformat(a.start or cfg["start_date"]).replace(tzinfo=timezone.utc)
    end = datetime.fromisoformat(a.end).replace(tzinfo=timezone.utc) if a.end else utc_now().replace(microsecond=0)
    out = RAW / "nvd"
    out.mkdir(parents=True, exist_ok=True)
    wins = list(windows(start, end, cfg["window_days"]))
    print(f"NVD : {len(wins)} fenêtres de {cfg['window_days']} jours, clé {'présente' if key else 'ABSENTE (collecte lente)'}")

    total_pages = 0
    for s, e in tqdm(wins, desc="fenêtres"):
        first = page_path(out, s, e, 0)
        if first.exists():
            with gzip.open(first, "rt", encoding="utf-8") as fh:
                total = json.load(fh)["totalResults"]
        else:
            data = fetch_page(s, e, 0, cfg["page_size"], headers)
            first.write_bytes(gzip.compress(json.dumps(data).encode()))
            total = data["totalResults"]
            time.sleep(pause)
        n_pages = max(1, -(-total // cfg["page_size"]))
        for n in range(1, n_pages):
            p = page_path(out, s, e, n)
            if p.exists():
                continue
            data = fetch_page(s, e, n * cfg["page_size"], cfg["page_size"], headers)
            p.write_bytes(gzip.compress(json.dumps(data).encode()))
            time.sleep(pause)
        total_pages += n_pages

    files = sorted(out.glob("*.json.gz"))
    update_manifest("nvd", {
        "files": len(files), "pages_expected": total_pages, "start": start.date().isoformat(), "end": end.date().isoformat(),
        "api_key_used": bool(key), "bytes": sum(f.stat().st_size for f in files),
        "sha256_first_file": sha256_file(files[0]) if files else None, "collection_date": utc_now().date().isoformat(),
    })
    print(f"NVD : {len(files)} pages enregistrées dans {out}")


if __name__ == "__main__":
    main()
