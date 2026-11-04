"""Bon fonctionnement du code d'entraînement, d'évaluation, d'explication et du service, sur données SYNTHÉTIQUES."""
import json
import secrets

import pytest
from fastapi.testclient import TestClient

from m1.service.app import MAX_BATCH, create_app

TOKEN = secrets.token_hex(16)  # généré à chaque exécution : aucun secret en clair dans le dépôt


def test_artefacts_et_metriques(syn_model_dir):
    for f in ("model.joblib", "calibrator.joblib", "cwe_rates.csv", "metrics.json", "shap_top.csv", "environment.json", "data_manifest.json", "config.yaml"):
        assert (syn_model_dir / f).exists(), f
    m = json.loads((syn_model_dir / "metrics.json").read_text())
    assert m["test_m1_calibre"]["pr_auc"] > m["test_m1_calibre"]["prevalence"]
    assert "reference_cvss" in m and m["epss_coverage"] < 1


def test_le_test_n_est_evalue_qu_une_fois(syn_model_dir, monkeypatch, syn_df, tmp_path):
    import sys

    import m1.evaluate as evaluate

    data = tmp_path / "d.csv"
    syn_df.to_csv(data, index=False)
    monkeypatch.setattr(sys, "argv", ["evaluate", "--data", str(data), "--model-dir", str(syn_model_dir)])
    with pytest.raises(SystemExit):
        evaluate.main()


def test_epss_pas_dans_les_variables_du_modele(syn_model_dir):
    import joblib

    assert "epss_t0" not in joblib.load(syn_model_dir / "model.joblib")["features"]


@pytest.fixture(scope="module")
def client(syn_model_dir):
    return TestClient(create_app(syn_model_dir, token=TOKEN))


def post(client, items, token=TOKEN):
    return client.post("/m1/predict", json={"items": items}, headers={"X-M1-Token": token} if token else {})


def test_service_exige_un_jeton(client):
    assert client.get("/health").status_code == 200
    assert post(client, [{"cweId": "CWE-79"}], token=None).status_code == 401
    assert post(client, [{"cweId": "CWE-79"}], token="mauvais").status_code == 401
    assert client.get("/model-info").status_code == 401


def test_service_refuse_un_jeton_faible(syn_model_dir):
    with pytest.raises(RuntimeError):
        create_app(syn_model_dir, token="court")


def test_la_source_est_toujours_indiquee(client):
    r = post(client, [{"features": {"cvss_base": 9.8, "av": "N", "pr": "N", "cwe": "CWE-94", "exploitdb_before_t0": 1}},
                      {"cweId": "CWE-79"}, {"cweId": "CWE-99999"}, {"cveId": "CVE-2099-0001"}])
    assert r.status_code == 200
    p = r.json()["predictions"]
    assert [x["source"] for x in p] == ["m1", "cwe_rate", "prior", "prior"]
    assert p[0]["calibrated"] is True and p[1]["calibrated"] is False
    assert all(0 <= x["probability"] <= 1 and x["modelVersion"] for x in p)
    risky, benign = (post(client, [{"features": f}]).json()["predictions"][0]["probability"] for f in (
        {"cvss_base": 9.8, "av": "N", "pr": "N", "exploitdb_before_t0": 1}, {"cvss_base": 2.0, "av": "P", "pr": "H", "exploitdb_before_t0": 0}))
    assert risky > benign


def test_validation_stricte_et_limites(client):
    assert post(client, []).status_code == 422
    assert post(client, [{"cweId": "'; DROP TABLE"}]).status_code == 422
    assert post(client, [{"cveId": "pas-un-cve"}]).status_code == 422
    assert post(client, [{"features": {"cvss_base": 99}}]).status_code == 422
    assert post(client, [{"features": {"inconnu": 1}}]).status_code == 422
    assert post(client, [{"cweId": "CWE-79"}] * (MAX_BATCH + 1)).status_code == 422
    big = client.post("/m1/predict", content=b"x" * 300_000, headers={"X-M1-Token": TOKEN, "Content-Type": "application/json"})
    assert big.status_code == 413
    err = post(client, [{"cweId": 12}])  # type strict : un entier n'est pas une chaîne
    assert err.status_code == 422 and "detail" in err.json() and "Traceback" not in err.text
