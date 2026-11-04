# M1 : make collect | dataset | train | evaluate | explain | sensitivity | service | test
# Sans `make` (Windows) : python -m m1 <commande> (voir README.md).
PY ?= python
export PYTHONPATH := src

.PHONY: collect dataset train evaluate explain sensitivity service test lint

collect:
	$(PY) -m m1 collect-kev
	$(PY) -m m1 collect-exploitdb
	$(PY) -m m1 collect-nvd
	$(PY) -m m1.build_dataset --prepare-only
	$(PY) -m m1 collect-epss

# Reconstruit les jeux de données (h = 30, 90, 365) à partir des données brutes.
dataset:
	$(PY) -m m1.build_dataset --prepare-only
	$(PY) -m m1 collect-epss
	$(PY) -m m1 dataset --all-horizons

train:
	$(PY) -m m1 train

evaluate:
	$(PY) -m m1 evaluate
	$(PY) -m m1.explain

explain:
	$(PY) -m m1.explain

sensitivity:
	$(PY) -m m1.sensitivity

service:
	$(PY) -m m1 service

test:
	$(PY) -m pytest -q tests

lint:
	$(PY) -m ruff check src tests
