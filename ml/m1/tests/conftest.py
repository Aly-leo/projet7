import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from synthetic import make_synthetic  # noqa: E402


@pytest.fixture(scope="session")
def syn_df():
    return make_synthetic()


@pytest.fixture(scope="session")
def syn_model_dir(tmp_path_factory, syn_df, monkeypatch_session):
    """Entraîne un petit modèle sur données SYNTHÉTIQUES (test du code de bout en bout, pas un résultat)."""
    import m1.evaluate as evaluate
    import m1.explain as explain
    import m1.train as train

    tmp = tmp_path_factory.mktemp("syn_model")
    data = tmp / "syn_dataset.csv"
    syn_df.to_csv(data, index=False)
    out = tmp / "model"
    monkeypatch_session.setattr(evaluate, "REPORTS", tmp / "reports")
    monkeypatch_session.setattr(explain, "REPORTS", tmp / "reports")
    monkeypatch_session.setattr(sys, "argv", ["train", "--data", str(data), "--out", str(out), "--quick"])
    train.main()
    monkeypatch_session.setattr(sys, "argv", ["evaluate", "--data", str(data), "--model-dir", str(out)])
    evaluate.main()
    monkeypatch_session.setattr(sys, "argv", ["explain", "--data", str(data), "--model-dir", str(out), "--sample", "3000"])
    explain.main()
    return out


@pytest.fixture(scope="session")
def monkeypatch_session():
    from _pytest.monkeypatch import MonkeyPatch

    mp = MonkeyPatch()
    yield mp
    mp.undo()
