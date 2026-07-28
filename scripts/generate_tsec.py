"""
scripts/generate_tsec.py
=========================
TURRET OS TSEC Synthetic Corpus Generator.

Generates a seeded, deterministic synthetic dataset of user-day activity
records representing 5 adversarial insider profiles for D3 experiments.

Adversarial Profiles:
  1. MIRROR_USER        — Mimics legitimate user behaviour patterns
  2. BREATHING_COLLECTOR — Slow, low-volume data collection over months
  3. GHOST_AUTHOR        — Uses shared accounts; edits documents under others' names
  4. COMFORT_BREAKER     — Occasionally probes outside clearance/comfort zone
  5. CLEANER             — Strips metadata before exfiltration

Usage:
  python scripts/generate_tsec.py --seed 42 --users 500 --days 365 --out data/tsec/

Output:
  data/tsec/users.parquet         — User profiles with clearance levels
  data/tsec/activities.parquet    — User-day activity records
  data/tsec/labels.parquet        — Ground-truth labels (user_id, day, is_malicious, profile)
  data/tsec/README.md             — Dataset statistics
"""

from __future__ import annotations

import argparse
import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ── Profile definitions ────────────────────────────────────────────────────

PROFILES = {
    "MIRROR_USER": {
        "prevalence": 0.008,       # ~4 of 500 users
        "description": "Mimics normal user behaviour; low deviation scores",
        "clearance_violation_rate": 0.02,
        "off_hours_multiplier": 1.1,
        "novelty_score_mean": 1.5,   # just under 3σ threshold
        "metadata_strip_rate": 0.0,
        "removable_copy_rate": 0.05,
        "outbound_email_rate": 0.3,
    },
    "BREATHING_COLLECTOR": {
        "prevalence": 0.006,
        "description": "Slow, low-volume data collection over months",
        "clearance_violation_rate": 0.01,
        "off_hours_multiplier": 1.05,
        "novelty_score_mean": 2.0,
        "metadata_strip_rate": 0.0,
        "removable_copy_rate": 0.02,
        "outbound_email_rate": 0.1,
    },
    "GHOST_AUTHOR": {
        "prevalence": 0.004,
        "description": "Uses shared accounts; edits documents under other users names",
        "clearance_violation_rate": 0.05,
        "off_hours_multiplier": 1.3,
        "novelty_score_mean": 3.5,
        "metadata_strip_rate": 0.1,
        "removable_copy_rate": 0.0,
        "outbound_email_rate": 0.2,
        "identity_proxy_rate": 0.8,   # high mismatch rate
    },
    "COMFORT_BREAKER": {
        "prevalence": 0.010,
        "description": "Occasionally probes outside clearance/comfort zone",
        "clearance_violation_rate": 0.15,
        "off_hours_multiplier": 1.8,
        "novelty_score_mean": 4.0,
        "metadata_strip_rate": 0.0,
        "removable_copy_rate": 0.1,
        "outbound_email_rate": 0.2,
    },
    "CLEANER": {
        "prevalence": 0.004,
        "description": "Strips metadata before scheduled exfiltration",
        "clearance_violation_rate": 0.05,
        "off_hours_multiplier": 2.0,
        "novelty_score_mean": 5.0,
        "metadata_strip_rate": 0.9,   # core signature
        "removable_copy_rate": 0.6,
        "outbound_email_rate": 0.5,
        "badge_corr_rate": 0.7,        # copies near badge events
    },
}

CLEARANCE_LEVELS = ["open", "cui", "secret", "ts", "ts_sci"]
DEPARTMENTS = ["Engineering", "Finance", "HR", "Legal", "Research", "Operations", "IT"]


def _assign_profile(rng: np.random.Generator) -> str | None:
    """Assign an adversarial profile to a user based on prevalence rates."""
    roll = rng.random()
    cumulative = 0.0
    for profile, spec in PROFILES.items():
        cumulative += spec["prevalence"]
        if roll < cumulative:
            return profile
    return None  # Benign user


def generate_users(n_users: int, rng: np.random.Generator) -> pd.DataFrame:
    """Generate synthetic user profiles."""
    records = []
    for i in range(n_users):
        profile = _assign_profile(rng)
        clearance_idx = int(rng.integers(0, len(CLEARANCE_LEVELS)))
        records.append({
            "user_id": f"U{i:05d}",
            "department": rng.choice(DEPARTMENTS),
            "max_clearance": CLEARANCE_LEVELS[clearance_idx],
            "clearance_idx": clearance_idx,
            "hire_date": (datetime(2020, 1, 1) + timedelta(days=int(rng.integers(0, 1460)))).isoformat(),
            "adversarial_profile": profile,
            "is_malicious": profile is not None,
        })
    return pd.DataFrame(records)


def generate_activities(
    users_df: pd.DataFrame,
    n_days: int,
    rng: np.random.Generator,
    start_date: datetime | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Generate user-day activity records and ground-truth labels.
    Returns (activities_df, labels_df).
    """
    if start_date is None:
        start_date = datetime(2023, 1, 1, tzinfo=timezone.utc)

    activities = []
    labels = []

    for _, user in users_df.iterrows():
        profile_name = user["adversarial_profile"]
        profile = PROFILES.get(profile_name, {}) if profile_name else {}
        is_malicious = user["is_malicious"]

        for day in range(n_days):
            date = start_date + timedelta(days=day)
            is_weekend = date.weekday() >= 5

            # Skip ~80% of weekends for benign users
            if is_weekend and not is_malicious and rng.random() < 0.80:
                continue

            # Base activity levels
            n_file_accesses = int(rng.poisson(lam=20 if not is_weekend else 3))
            off_hours_mult = float(profile.get("off_hours_multiplier", 1.0)) if profile else 1.0
            access_hour = int(rng.integers(7, 19))  # default business hours
            if profile and rng.random() < 0.3:
                access_hour = int(rng.integers(0, 7)) if rng.random() < 0.5 else int(rng.integers(19, 24))

            novelty_mean = float(profile.get("novelty_score_mean", 1.0)) if profile else 1.0
            novelty_score = float(rng.normal(novelty_mean, 0.5))

            cv_rate = float(profile.get("clearance_violation_rate", 0.001)) if profile else 0.001
            metadata_strip = bool(profile and rng.random() < float(profile.get("metadata_strip_rate", 0.0)))
            removable_copy = bool(profile and rng.random() < float(profile.get("removable_copy_rate", 0.0)))
            outbound_email = bool(rng.random() < float(profile.get("outbound_email_rate", 0.05) if profile else 0.05))
            identity_proxy = bool(profile and rng.random() < float(profile.get("identity_proxy_rate", 0.0)))

            activities.append({
                "user_id": user["user_id"],
                "date": date.date().isoformat(),
                "day_idx": day,
                "n_file_accesses": n_file_accesses,
                "access_hour": access_hour,
                "off_hours_multiplier": off_hours_mult,
                "access_novelty_score": round(novelty_score, 4),
                "file_classifier": CLEARANCE_LEVELS[min(
                    user["clearance_idx"] + (1 if rng.random() < cv_rate else 0),
                    len(CLEARANCE_LEVELS) - 1
                )],
                "user_max_clearance": user["max_clearance"],
                "metadata_stripped": metadata_strip,
                "copy_to_removable": removable_copy,
                "outbound_email": outbound_email,
                "identity_proxy": identity_proxy,
                "followed_by_outbound": metadata_strip and outbound_email,
                "outbound_gap_minutes": int(rng.integers(5, 55)) if (metadata_strip and outbound_email) else 999,
                "badge_gap_minutes": int(rng.integers(5, 25)) if removable_copy else 999,
                "doc_author": f"User_{rng.integers(0, 50):03d}" if identity_proxy else user["user_id"],
                "session_user": user["user_id"],
            })

            # Label: is this a malicious day?
            malicious_day = is_malicious and (
                metadata_strip or removable_copy or identity_proxy
                or novelty_score > 3.0 or rng.random() < 0.05
            )
            labels.append({
                "user_id": user["user_id"],
                "date": date.date().isoformat(),
                "day_idx": day,
                "is_malicious": malicious_day,
                "adversarial_profile": profile_name,
            })

    return pd.DataFrame(activities), pd.DataFrame(labels)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate TSEC synthetic corpus")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--users", type=int, default=500)
    parser.add_argument("--days", type=int, default=365)
    parser.add_argument("--out", type=str, default="data/tsec/")
    args = parser.parse_args()

    rng = np.random.default_rng(args.seed)
    random.seed(args.seed)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Generating %d users × %d days (seed=%d)...", args.users, args.days, args.seed)

    users_df = generate_users(args.users, rng)
    activities_df, labels_df = generate_activities(users_df, args.days, rng)

    # Write Parquet
    users_df.to_parquet(out_dir / "users.parquet", index=False)
    activities_df.to_parquet(out_dir / "activities.parquet", index=False)
    labels_df.to_parquet(out_dir / "labels.parquet", index=False)

    # Write stats README
    malicious_users = int(users_df["is_malicious"].sum())
    malicious_days = int(labels_df["is_malicious"].sum())
    total_days = len(labels_df)
    positive_rate = malicious_days / total_days if total_days else 0

    profile_counts = users_df[users_df["is_malicious"]]["adversarial_profile"].value_counts().to_dict()

    stats = {
        "seed": args.seed,
        "n_users": args.users,
        "n_days": args.days,
        "n_malicious_users": malicious_users,
        "n_activity_records": len(activities_df),
        "n_label_records": total_days,
        "n_positive_labels": malicious_days,
        "positive_rate": round(positive_rate, 4),
        "profile_counts": profile_counts,
    }

    with open(out_dir / "dataset_stats.json", "w") as f:
        json.dump(stats, f, indent=2)

    logger.info("TSEC corpus written to %s", out_dir)
    logger.info("Stats: %d users, %d malicious (%.1f%%), %d activity records, positive_rate=%.4f",
                args.users, malicious_users, 100 * malicious_users / args.users,
                len(activities_df), positive_rate)
    for profile, count in profile_counts.items():
        logger.info("  %-25s : %d users", profile, count)


if __name__ == "__main__":
    main()
