"""
scripts/wall_clock_profile.py
==============================
Profile wall-clock execution time across all TURRET OS pipeline stages
and log detailed machine environment specifications (CPU, RAM, GPU, OS,
CUDA, Python, and key package versions) to reports/machine_spec.json.

Usage:
    poetry run python scripts/wall_clock_profile.py --out reports/
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
import time
from pathlib import Path
from typing import Any

import numpy as np

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def get_hardware_info() -> dict[str, Any]:
    """Gather hardware and environment specs."""
    info: dict[str, Any] = {
        "python_version": sys.version,
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
        "cpu_count": None,
        "memory_total_gb": None,
        "gpu_available": False,
        "gpu_count": 0,
        "gpu_name": None,
    }

    try:
        import psutil  # type: ignore[import]
        info["cpu_count"] = psutil.cpu_count(logical=True)
        info["memory_total_gb"] = round(psutil.virtual_memory().total / (1024 ** 3), 2)
    except Exception:
        pass

    try:
        import torch
        info["gpu_available"] = torch.cuda.is_available()
        if torch.cuda.is_available():
            info["gpu_count"] = torch.cuda.device_count()
            info["gpu_name"] = torch.cuda.get_device_name(0)
            info["cuda_version"] = torch.version.cuda
    except Exception:
        pass

    return info


def profile_pipeline(tsec_dir: Path) -> dict[str, Any]:
    """Profile pipeline stages with high-resolution wall-clock timing."""
    timings: dict[str, float] = {}

    # Stage 1: Load TSEC Corpus
    t0 = time.perf_counter()
    import pandas as pd
    acts = pd.read_parquet(tsec_dir / "activities.parquet")
    labels = pd.read_parquet(tsec_dir / "labels.parquet")
    merged = acts.merge(labels, on=["user_id", "date", "day_idx"], how="left")
    timings["data_load_sec"] = round(time.perf_counter() - t0, 4)

    # Stage 2: Feature Matrix Construction
    t0 = time.perf_counter()
    feature_cols = [
        "n_file_accesses", "access_hour", "off_hours_multiplier",
        "access_novelty_score", "metadata_stripped", "copy_to_removable",
        "outbound_email", "identity_proxy",
    ]
    X = merged[feature_cols].fillna(0).values.astype(np.float32)
    y = merged["is_malicious"].fillna(False).values.astype(int)
    timings["feature_matrix_sec"] = round(time.perf_counter() - t0, 4)

    # Stage 3: Classifier Training & Calibration
    t0 = time.perf_counter()
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.model_selection import train_test_split

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )

    base_clf = GradientBoostingClassifier(n_estimators=200, max_depth=5, random_state=42)
    clf = CalibratedClassifierCV(estimator=base_clf, method="isotonic", cv=3)
    clf.fit(X_train, y_train)
    timings["model_train_calibration_sec"] = round(time.perf_counter() - t0, 4)

    # Stage 4: Inference & Metrics Computation
    t0 = time.perf_counter()
    y_prob = clf.predict_proba(X_test)[:, 1]
    from turret_detect.gnn.evaluator import Evaluator
    evaluator = Evaluator()
    _ = evaluator.evaluate(y_test, y_prob)
    timings["inference_evaluation_sec"] = round(time.perf_counter() - t0, 4)

    return {
        "n_records": len(X),
        "n_test_samples": len(X_test),
        "timings": timings,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Profile TURRET OS wall-clock execution")
    parser.add_argument("--tsec-dir", default="data/tsec")
    parser.add_argument("--out", default="reports/")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    tsec_dir = Path(args.tsec_dir)

    logger.info("Profiling TURRET OS environment and pipeline wall-clock performance...")

    env_info = get_hardware_info()
    profile_info = profile_pipeline(tsec_dir) if (tsec_dir / "activities.parquet").exists() else {}

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "hardware_environment": env_info,
        "pipeline_profile": profile_info,
    }

    report_path = out_dir / "machine_spec.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)

    logger.info("✅ Wall-clock profile written to %s", report_path)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
