"""Collecte du catalogue KEV (CISA) : JSON et CSV bruts datés, métadonnées, date de lancement du catalogue."""
from __future__ import annotations

import json
from collections import Counter

from m1.common import INTERIM, RAW, http_get, sha256_file, update_manifest, utc_now, write_json

KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CSV = "https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv"


def main() -> None:
    day = utc_now().strftime("%Y%m%d")
    out = RAW / "kev"
    out.mkdir(parents=True, exist_ok=True)
    jpath = out / f"known_exploited_vulnerabilities_{day}.json"
    cpath = out / f"known_exploited_vulnerabilities_{day}.csv"
    for url, path in ((KEV_JSON, jpath), (KEV_CSV, cpath)):
        if path.exists():
            print(f"déjà présent : {path.name}")
            continue
        path.write_bytes(http_get(url).content)
        print(f"téléchargé : {path.name} ({path.stat().st_size} octets)")

    data = json.loads(jpath.read_text(encoding="utf-8"))
    vulns = data["vulnerabilities"]
    counts = Counter(v["dateAdded"] for v in vulns)
    launch_date, launch_count = counts.most_common(1)[0]
    meta = {
        "catalogVersion": data.get("catalogVersion"),
        "dateReleased": data.get("dateReleased"),
        "count": data.get("count"),
        "n_entries": len(vulns),
        "download_date": utc_now().isoformat(timespec="seconds"),
        "kev_launch_date": launch_date,  # jour qui compte le plus d'ajouts (rattrapage du lancement)
        "kev_launch_additions": launch_count,
        "file": jpath.name,
    }
    write_json(INTERIM / "kev_meta.json", meta)
    update_manifest("kev", {"file": jpath.name, "sha256": sha256_file(jpath), "rows": len(vulns), **{k: meta[k] for k in ("catalogVersion", "dateReleased", "kev_launch_date")}})
    print(f"KEV : {len(vulns)} entrées, version {meta['catalogVersion']}, lancement détecté le {launch_date} ({launch_count} ajouts)")


if __name__ == "__main__":
    main()
