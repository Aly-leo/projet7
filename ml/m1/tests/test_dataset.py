"""Contrôles anti-fuite sur le jeu de données RÉEL (ignorés si le jeu n'a pas encore été construit)."""
import json

import numpy as np
import pandas as pd
import pytest

from m1.build_dataset import load_nvd
from m1.common import INTERIM, PROCESSED, RAW, load_config, read_json
from m1.modeling import apply_top_cwe, feature_lists, make_pipeline

DATA = PROCESSED / "m1_dataset.csv"
pytestmark = pytest.mark.skipif(not DATA.exists(), reason="jeu de données réel absent : lancer `python -m m1 dataset`")


@pytest.fixture(scope="module")
def df():
    return pd.read_csv(DATA, parse_dates=["published", "t0", "kev_date_added", "collection_date"])


def test_une_ligne_par_cve(df):
    assert df["cve_id"].is_unique


def test_aucun_cve_deja_dans_kev_avant_t0(df):
    assert not (df["kev_date_added"].notna() & (df["kev_date_added"] <= df["t0"])).any()


def test_etiquettes_mures(df):
    assert (df["t0"] + pd.to_timedelta(df["h"], unit="D") <= df["collection_date"]).all()


def test_cohorte_posterieure_au_lancement_de_kev(df):
    launch = pd.Timestamp(read_json(INTERIM / "kev_meta.json")["kev_launch_date"])
    assert (df["t0"] > launch).all()


def test_etiquette_recalculee_depuis_kev(df):
    meta = read_json(INTERIM / "kev_meta.json")
    kev = json.loads((RAW / "kev" / meta["file"]).read_text(encoding="utf-8"))["vulnerabilities"]
    added = pd.Series({v["cveID"].upper(): pd.Timestamp(v["dateAdded"]) for v in kev})
    a = df["cve_id"].map(added)
    expected = ((a > df["t0"]) & (a <= df["t0"] + pd.to_timedelta(df["h"], unit="D"))).astype(int)
    assert (expected == df["label"]).all()


def test_variables_historiques_ne_regardent_pas_le_futur(df):
    """Recalcul INDÉPENDANT de vendor_cve_count et exploitdb_before_t0 sur un échantillon."""
    nvd = load_nvd()
    nvd = nvd[nvd["vuln_status"].fillna("").str.lower() != "rejected"]
    sample = df.sample(min(400, len(df)), random_state=0)
    for _, r in sample[sample["vendor"] != "unknown"].head(150).iterrows():
        same = nvd[(nvd["vendor"] == r["vendor"]) & (nvd["published"] < r["t0"]) & (nvd["cve_id"] != r["cve_id"])]
        assert r["vendor_cve_count"] == len(same), r["cve_id"]
    exp = pd.read_parquet(INTERIM / "exploitdb_cve_dates.parquet").set_index("cve_id")["exploit_date"]
    d = sample["cve_id"].map(exp)
    assert ((d.notna() & (d < sample["t0"])).astype(int) == sample["exploitdb_before_t0"]).all()


def test_decoupages_sans_chevauchement_dans_le_temps(df):
    tr, va, te = (df[df.split == s] for s in ("train", "val", "test"))
    assert tr["t0"].max() < va["t0"].min() and va["t0"].max() < te["t0"].min()
    h = int(df["h"].iloc[0])
    assert (tr["t0"] + pd.Timedelta(days=h) <= va["t0"].min()).all()  # purge de l'entraînement
    assert (va["t0"] + pd.Timedelta(days=h) <= te["t0"].min()).all()  # purge de la validation


def test_assez_de_positifs_pour_evaluer(df):
    cfg = load_config()
    for s in ("val", "test"):
        assert df.loc[df.split == s, "label"].sum() >= cfg["min_positives_eval"], f"moins de {cfg['min_positives_eval']} positifs en {s}"


def test_permutation_des_etiquettes_ramene_la_pr_auc_pres_de_la_prevalence(df):
    """Si on mélange les étiquettes, un modèle ne doit rien apprendre : sinon fuite ou bug."""
    from sklearn.metrics import average_precision_score

    cfg = load_config()
    cat, num = feature_lists(cfg)
    tr, va = df[df.split == "train"], df[df.split == "val"]
    top = tr["cwe"].value_counts().head(cfg["cwe_top_n"]).index.tolist()
    tr, va = apply_top_cwe(tr, top), apply_top_cwe(va, top)
    rng = np.random.default_rng(0)
    prev = va.label.mean()
    aps = []
    for _ in range(3):
        y_perm = rng.permutation(tr.label.to_numpy())
        pipe = make_pipeline("logreg", {"C": 0.2}, cat, num, 0).fit(tr[cat + num], y_perm)
        aps.append(average_precision_score(va.label, pipe.predict_proba(va[cat + num])[:, 1]))
    assert np.mean(aps) < max(3 * prev, prev + 0.01), f"PR-AUC permutée {np.mean(aps):.4f} vs prévalence {prev:.4f}"
