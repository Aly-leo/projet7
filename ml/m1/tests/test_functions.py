"""Tests unitaires des fonctions (données SYNTHÉTIQUES ou minuscules, écrites à la main)."""
import numpy as np
import pandas as pd
import pytest

from m1.build_dataset import compute_t0, count_before, label_from_kev, parse_cvss, parse_cwe, parse_vendor
from m1.common import load_config
from m1.modeling import bootstrap, ece, feature_lists, precision_recall_at_k


def ts(*d):
    return pd.Series(pd.to_datetime(list(d)))


def test_t0_est_le_premier_jour_du_mois_suivant_publication_plus_30_jours():
    t0 = compute_t0(ts("2024-01-01", "2024-01-31", "2024-02-15", "2024-12-05"))
    # 01-01 + 30 j = 01-31 -> 02-01 ; 01-31 + 30 j = 03-01 -> 04-01 ; 02-15 + 30 j = 03-16 -> 04-01 ; 12-05 + 30 j = 01-04 -> 02-01
    assert [d.date().isoformat() for d in t0] == ["2024-02-01", "2024-04-01", "2024-04-01", "2025-02-01"]
    # t0 est toujours strictement postérieur à la publication + 30 jours
    pub = ts("2024-05-31", "2024-06-01", "2024-06-30")
    assert (compute_t0(pub) > pub + pd.Timedelta(days=30)).all()


def test_etiquette_intervalle_ouvert_a_gauche_ferme_a_droite():
    t0 = ts("2024-03-01", "2024-03-01", "2024-03-01", "2024-03-01")
    added = ts("2024-03-01", "2024-03-02", "2024-05-30", "2024-05-31")  # t0 exclu ; t0 + 90 j = 2024-05-30 inclus
    assert label_from_kev(t0, added, 90).tolist() == [0, 1, 1, 0]
    assert label_from_kev(t0, pd.Series([pd.NaT] * 4), 90).tolist() == [0, 0, 0, 0]


def test_compteur_historique_ignore_le_futur_et_le_cve_lui_meme():
    pubs = {"v": np.sort(pd.to_datetime(["2024-01-01", "2024-02-01", "2024-03-01", "2024-09-01"]).to_numpy())}
    group = pd.Series(["v", "v", "inconnu"])
    when = ts("2024-03-01", "2024-10-01", "2024-10-01")
    out = count_before(pubs, group, when)
    assert out[0] == 1  # publiés strictement avant le 1er mars : 2 ; moins le CVE lui-même
    assert out[1] == 3
    assert np.isnan(out[2])


def test_parse_cvss_priorite_v31_puis_v30_puis_v40():
    v31 = {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 5, "vectorString": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:C/C:L/I:L/A:L"}},
                             {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 9.8, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}],
           "cvssMetricV30": [{"cvssData": {"version": "3.0", "baseScore": 1, "vectorString": "CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:C/C:N/I:N/A:N"}}]}
    r = parse_cvss(v31)
    assert (r["cvss_base"], r["cvss_version"], r["av"], r["s"]) == (9.8, "3.1", "N", "U")
    assert parse_cvss({k: v for k, v in v31.items() if k == "cvssMetricV30"})["cvss_version"] == "3.0"
    v40 = {"cvssMetricV40": [{"cvssData": {"version": "4.0", "baseScore": 8.7, "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}}]}
    r4 = parse_cvss(v40)
    assert (r4["av"], r4["c"], r4["s"]) == ("N", "H", "UNK")  # pas de composante « S » en v4
    empty = parse_cvss({})
    assert np.isnan(empty["cvss_base"]) and empty["av"] == "UNK"


def test_parse_cwe_et_editeur():
    assert parse_cwe([{"source": "autre", "description": [{"value": "CWE-1"}]}, {"source": "nvd@nist.gov", "description": [{"value": "CWE-79"}]}]) == "CWE-79"
    assert parse_cwe([{"source": "autre", "description": [{"value": "CWE-1"}]}]) == "CWE-1"
    assert parse_cwe([{"source": "nvd@nist.gov", "description": [{"value": "NVD-CWE-noinfo"}]}]) == "NVD-CWE-noinfo"
    assert parse_cwe([]) == "UNK"
    cfg = [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:apache:struts:2.0:*:*", "vulnerable": True},
                                    {"criteria": "cpe:2.3:a:apache:http_server:2.4:*:*", "vulnerable": True},
                                    {"criteria": "cpe:2.3:o:linux:linux_kernel:5:*:*", "vulnerable": False}]}]}]
    assert parse_vendor(cfg) == "apache"
    assert parse_vendor([]) == "unknown"


def test_decoupage_chronologique_sans_chevauchement_et_avec_purge(syn_df):
    d = syn_df
    tr, va, te = (d[d.split == s] for s in ("train", "val", "test"))
    assert tr.t0.max() < va.t0.min() <= va.t0.max() < te.t0.min()
    # purge : aucune ligne d'entraînement dont la fenêtre d'étiquette déborde sur la validation
    assert (tr.t0 + pd.Timedelta(days=90) <= va.t0.min()).all()
    assert (va.t0 + pd.Timedelta(days=90) <= te.t0.min()).all()
    assert (d.split == "purged").sum() > 0


def test_repartition_des_positifs_proche_de_60_20_20(syn_df):
    d = syn_df
    pos = d.groupby("split")["label"].sum()
    kept = pos.drop("purged", errors="ignore").sum()
    assert 0.5 < pos["train"] / (kept + pos.get("purged", 0)) < 0.7


def test_metriques():
    y = np.array([1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
    s = np.array([.9, .1, .2, .8, .3, .1, .1, .2, .1, .05])
    assert precision_recall_at_k(y, s, 2) == (1.0, 1.0)
    assert ece(y, np.where(y == 1, 1.0, 0.0)) == pytest.approx(0.0, abs=1e-9)
    b = bootstrap(y.repeat(50), {"m1": s.repeat(50), "autre": np.zeros(500)}, {"pr_auc": lambda yy, ss: float((yy * ss).mean())}, 50)
    assert "m1_minus_autre" in b["paired_diff"]


def test_epss_n_est_jamais_une_variable():
    cfg = load_config()
    cat, num = feature_lists(cfg)
    assert "epss_t0" not in cat + num and "n_references" not in cat + num
    with pytest.raises(AssertionError):
        feature_lists({"features": {"categorical": ["epss_t0"], "numeric": []}})
