"""Utilitaires communs : chemins, configuration, accès réseau poli et reprenable, manifeste des données."""
from __future__ import annotations

import hashlib
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
import yaml

ROOT = Path(__file__).resolve().parents[2]  # ml/m1
RAW = ROOT / "data" / "raw"
INTERIM = ROOT / "data" / "interim"
PROCESSED = ROOT / "data" / "processed"
MODELS = ROOT / "models" / "m1_v1"
REPORTS = ROOT / "reports"
USER_AGENT = "projet7-m1-research/1.0 (recherche academique, Master 2 securite applications Web)"


def load_config(path: Path | None = None) -> dict[str, Any]:
    with open(path or ROOT / "config" / "m1.yaml", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def seed_everything(seed: int) -> None:
    random.seed(seed)
    try:
        import numpy as np

        np.random.seed(seed)
    except ImportError:  # pragma: no cover
        pass


class FetchError(RuntimeError):
    pass


def http_get(
    url: str,
    *,
    params: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    retries: int = 3,
    timeout: float = 60,
    stream: bool = False,
) -> requests.Response:
    """GET avec nouvel essai à attente croissante (3 essais au plus) ; jamais de boucle infinie."""
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    last: Exception | None = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, params=params, headers=hdrs, timeout=timeout, stream=stream)
            if resp.status_code in (403, 429, 500, 502, 503, 504):
                raise FetchError(f"HTTP {resp.status_code}")
            resp.raise_for_status()
            return resp
        except (requests.RequestException, FetchError) as exc:
            last = exc
            if attempt < retries - 1:
                time.sleep(min(60, 8 * 2**attempt))
    raise FetchError(f"{url} : échec après {retries} essais ({last})")


def update_manifest(name: str, entry: dict[str, Any]) -> None:
    """Manifeste des données brutes : empreinte, taille, date de téléchargement (data/raw/manifest.json)."""
    path = RAW / "manifest.json"
    manifest: dict[str, Any] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    manifest[name] = {**manifest.get(name, {}), **entry, "updated_at": utc_now().isoformat(timespec="seconds")}
    RAW.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))
