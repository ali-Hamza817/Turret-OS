"""scripts/run_pipeline.py — orchestrate all pipeline stages end-to-end."""

from __future__ import annotations

import argparse
import subprocess
import sys

PIPELINE = [
    ("harvest",       ["python", "-m", "turret_harvest.cli",   "--config", "config/default.yaml"]),
    ("build_graph",   ["python", "-m", "turret_graph.cli",     "load"]),
    ("rules_eval",    ["python", "-m", "turret_detect.rules",  "--config", "config/espionage_rules.yaml"]),
    ("train_gnn",     ["python", "-m", "turret_detect.trainer","--epochs", "60"]),
    ("explain",       ["python", "-m", "turret_detect.explain"]),
    ("pack_evidence", ["python", "-m", "turret_evidence.cli",  "--out", "evidence_packs/"]),
    ("evaluate",      ["python", "scripts/run_experiments.py", "--out", "reports/"]),
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Run full TURRET OS pipeline")
    parser.add_argument("--from-stage", default=None, help="Start from this stage name")
    args = parser.parse_args()

    running = args.from_stage is None
    for name, cmd in PIPELINE:
        if args.from_stage and name == args.from_stage:
            running = True
        if not running:
            print(f"⏭️   Skipping {name}")
            continue
        print(f"\n{'='*60}\n== {name.upper()}\n{'='*60}")
        result = subprocess.run(cmd)
        if result.returncode != 0:
            print(f"❌  Stage '{name}' failed with code {result.returncode}")
            sys.exit(result.returncode)
        print(f"✅  {name} complete")


if __name__ == "__main__":
    main()
