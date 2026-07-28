"""
scripts/generate_d5_tenant.py
==============================
Generate Dataset D5: Internal Tenant 90-Day Lab Pilot Dataset.

Simulates a 90-day lab deployment across 35 users (engineering, HR, finance)
with 2 active insider threat scenarios tagged by security team analysts:
  Scenario 1: Identity-proxy author spoofing + slow data staging
  Scenario 2: Off-hours metadata-stripped exfiltration

Usage:
  poetry run python scripts/generate_d5_tenant.py --out data/d5_tenant/
"""

from __future__ import annotations

import argparse
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DEPARTMENTS = ["Engineering", "HR", "Finance", "Legal", "Operations"]
CLEARANCE_LEVELS = ["open", "cui", "secret", "ts", "ts_sci"]


def generate_d5_tenant(
    n_users: int = 35,
    n_days: int = 90,
    seed: int = 1337,
    out_dir: Path = Path("data/d5_tenant"),
) -> None:
    rng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    start_date = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Users
    users = []
    for i in range(n_users):
        is_insider = (i in (7, 22))  # User 7 and User 22 are tagged insiders
        users.append({
            "user_id": f"U_TENANT_{i:03d}",
            "department": rng.choice(DEPARTMENTS),
            "max_clearance": CLEARANCE_LEVELS[min(i % 5, 4)],
            "clearance_idx": min(i % 5, 4),
            "hire_date": "2024-03-15",
            "adversarial_profile": "GHOST_AUTHOR" if i == 7 else ("CLEANER" if i == 22 else None),
            "is_malicious": is_insider,
        })
    users_df = pd.DataFrame(users)

    # Activities & Labels
    activities = []
    labels = []

    for _, user in users_df.iterrows():
        is_insider = user["is_malicious"]
        profile = user["adversarial_profile"]

        for day in range(n_days):
            date = start_date + timedelta(days=day)
            is_weekend = date.weekday() >= 5
            if is_weekend and not is_insider and rng.random() < 0.85:
                continue

            # Base normal activity
            access_hour = int(rng.integers(8, 18))
            off_hours_mult = 1.0
            novelty = float(rng.normal(1.0, 0.4))
            metadata_strip = False
            removable_copy = False
            outbound_email = bool(rng.random() < 0.05)
            identity_proxy = False

            # Inject insider scenarios for days 45-75
            is_malicious_day = False
            if is_insider and 45 <= day <= 75:
                is_malicious_day = True
                if profile == "GHOST_AUTHOR":
                    identity_proxy = True
                    novelty = float(rng.normal(3.8, 0.5))
                    off_hours_mult = 1.6
                elif profile == "CLEANER":
                    metadata_strip = bool(rng.random() < 0.85)
                    removable_copy = bool(rng.random() < 0.70)
                    outbound_email = True
                    off_hours_mult = 2.2
                    access_hour = int(rng.integers(1, 6))

            activities.append({
                "user_id": user["user_id"],
                "date": date.date().isoformat(),
                "day_idx": day,
                "n_file_accesses": int(rng.poisson(25 if not is_weekend else 4)),
                "access_hour": access_hour,
                "off_hours_multiplier": off_hours_mult,
                "access_novelty_score": round(novelty, 4),
                "file_classifier": user["max_clearance"],
                "user_max_clearance": user["max_clearance"],
                "metadata_stripped": metadata_strip,
                "copy_to_removable": removable_copy,
                "outbound_email": outbound_email,
                "identity_proxy": identity_proxy,
                "followed_by_outbound": metadata_strip and outbound_email,
                "outbound_gap_minutes": 15 if (metadata_strip and outbound_email) else 999,
                "badge_gap_minutes": 10 if removable_copy else 999,
                "doc_author": "User_Spoofed" if identity_proxy else user["user_id"],
                "session_user": user["user_id"],
            })

            labels.append({
                "user_id": user["user_id"],
                "date": date.date().isoformat(),
                "day_idx": day,
                "is_malicious": is_malicious_day,
                "adversarial_profile": profile if is_malicious_day else None,
            })

    acts_df = pd.DataFrame(activities)
    labels_df = pd.DataFrame(labels)

    users_df.to_parquet(out_dir / "users.parquet", index=False)
    acts_df.to_parquet(out_dir / "activities.parquet", index=False)
    labels_df.to_parquet(out_dir / "labels.parquet", index=False)

    stats = {
        "dataset_id": "D5 Internal Tenant Pilot",
        "n_users": n_users,
        "n_days": n_days,
        "n_activity_records": len(acts_df),
        "n_malicious_users": 2,
        "n_malicious_days": int(labels_df["is_malicious"].sum()),
        "positive_rate": round(float(labels_df["is_malicious"].mean()), 4),
    }

    with open(out_dir / "dataset_stats.json", "w") as f:
        json.dump(stats, f, indent=2)

    logger.info("D5 Internal Tenant Pilot dataset generated: %d users, %d records -> %s",
                n_users, len(acts_df), out_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate D5 Internal Tenant Dataset")
    parser.add_argument("--out", default="data/d5_tenant")
    args = parser.parse_args()
    generate_d5_tenant(out_dir=Path(args.out))
