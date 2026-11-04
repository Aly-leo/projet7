"""Point d'entrée portable (sans make) : python -m m1 <commande> [options]."""
from __future__ import annotations

import importlib
import sys

COMMANDS = {
    "collect-kev": "m1.collect_kev",
    "collect-nvd": "m1.collect_nvd",
    "collect-epss": "m1.collect_epss",
    "collect-exploitdb": "m1.collect_exploitdb",
    "dataset": "m1.build_dataset",
    "train": "m1.train",
    "evaluate": "m1.evaluate",
    "service": "m1.service.app",
}

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("Commandes :", ", ".join(COMMANDS))
        raise SystemExit(2)
    mod = importlib.import_module(COMMANDS[sys.argv[1]])
    sys.argv = [COMMANDS[sys.argv[1]], *sys.argv[2:]]
    mod.main()
