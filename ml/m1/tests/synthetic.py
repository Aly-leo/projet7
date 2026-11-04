"""Jeu de données SYNTHÉTIQUE (préfixe SYN) pour tester le bon fonctionnement du code.

Il n'a AUCUN lien avec la réalité : aucun chiffre calculé dessus ne doit apparaître comme un résultat.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from m1.build_dataset import assign_split, choose_cutoffs, compute_t0

COLLECTION = pd.Timestamp("2026-10-31")


def make_synthetic(n: int = 24000, seed: int = 0, h: int = 90) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    pub = pd.Timestamp("2021-10-01") + pd.to_timedelta(rng.integers(0, 365 * 4 + 200, n), unit="D")
    av = rng.choice(["N", "A", "L", "P"], n, p=[.6, .1, .25, .05])
    ac = rng.choice(["L", "H"], n, p=[.8, .2])
    pr = rng.choice(["N", "L", "H"], n, p=[.5, .35, .15])
    ui = rng.choice(["N", "R"], n, p=[.7, .3])
    s = rng.choice(["U", "C"], n, p=[.85, .15])
    c, i, a = (rng.choice(["N", "L", "H"], n) for _ in range(3))
    cwe = rng.choice(["CWE-79", "CWE-89", "CWE-787", "CWE-20", "CWE-22", "CWE-94", "CWE-416", "CWE-200", "NVD-CWE-Other", "NVD-CWE-noinfo"], n)
    cvss = np.clip(rng.normal(6.5, 1.8, n) + (av == "N") * .8, 0, 10).round(1)
    vendor_count = rng.integers(0, 800, n).astype(float)
    expl = (rng.random(n) < .06).astype(int)
    z = -6.0 + .35 * (cvss - 6.5) + 1.3 * (av == "N") + 1.0 * (pr == "N") + 2.0 * expl + .5 * (cwe == "CWE-94") + .0008 * vendor_count
    label = (rng.random(n) < 1 / (1 + np.exp(-z))).astype(int)
    df = pd.DataFrame(dict(cve_id=[f"CVE-SYN-{k:06d}" for k in range(n)], published=pub))
    df["t0"] = compute_t0(df["published"])
    df = df.assign(label=label, cvss_base=cvss, av=av, ac=ac, pr=pr, ui=ui, s=s, c=c, i=i, a=a, cwe=cwe, vendor="syn",
                   vendor_cve_count=vendor_count, exploitdb_before_t0=expl, n_references=rng.integers(1, 30, n),
                   epss_t0=np.clip(1 / (1 + np.exp(-z)) * rng.lognormal(0, .6, n) * 3, 0, 1),
                   kev_date_added=pd.NaT, h=h, cvss_version="3.1", collection_date=COLLECTION)
    df.loc[df.sample(frac=.15, random_state=1).index, "epss_t0"] = np.nan
    df.loc[df.sample(frac=.03, random_state=2).index, "cvss_base"] = np.nan
    df = df[df["t0"] + pd.Timedelta(days=h) <= COLLECTION].reset_index(drop=True)
    t1, t2 = choose_cutoffs(df["t0"], df["label"], .6, .2)
    df["split"] = assign_split(df, t1, t2, h)
    return df.sort_values(["t0", "cve_id"]).reset_index(drop=True)
