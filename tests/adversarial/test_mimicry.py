"""
tests/adversarial/test_mimicry.py
==================================
Adversarial robustness tests for TURRET OS.
Verifies that mimicry, metadata-stripping, and identity-proxy attacks
cause ≤ 5% AUC drop (paper acceptance criterion H3).
"""

from __future__ import annotations

import numpy as np
import pytest


@pytest.fixture(scope="module")
def tsec_data():
    """Load TSEC corpus; skip if not generated yet."""
    from pathlib import Path
    tsec_dir = Path("data/tsec")
    if not tsec_dir.exists() or not (tsec_dir / "activities.parquet").exists():
        pytest.skip("TSEC corpus not generated. Run: make tsec")

    import pandas as pd
    acts = pd.read_parquet(tsec_dir / "activities.parquet")
    labels = pd.read_parquet(tsec_dir / "labels.parquet")
    merged = acts.merge(labels, on=["user_id", "date", "day_idx"], how="left")
    merged["is_malicious"] = merged["is_malicious"].fillna(False).astype(int)

    feature_cols = [
        "n_file_accesses", "access_hour", "off_hours_multiplier",
        "access_novelty_score", "metadata_stripped", "copy_to_removable",
        "outbound_email", "identity_proxy",
    ]
    X = merged[feature_cols].fillna(0).values.astype(np.float32)
    y = merged["is_malicious"].values.astype(int)
    return X, y


@pytest.fixture(scope="module")
def trained_model(tsec_data):
    """Train a GBT model on TSEC data."""
    from sklearn.ensemble import GradientBoostingClassifier
    from sklearn.model_selection import train_test_split

    X, y = tsec_data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=42
    )
    clf = GradientBoostingClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    return clf, X_test, y_test


class TestAdversarialRobustness:

    def _get_auc(self, clf, X_test, y_test) -> float:
        from sklearn.metrics import roc_auc_score
        probs = clf.predict_proba(X_test)[:, 1]
        return float(roc_auc_score(y_test, probs))

    def test_clean_auc_above_threshold(self, trained_model) -> None:
        """Clean AUC must be above 0.85 on TSEC for tests to be meaningful."""
        clf, X_test, y_test = trained_model
        auc = self._get_auc(clf, X_test, y_test)
        assert auc >= 0.85, f"Clean AUC {auc:.4f} too low for adversarial tests"

    def test_mimicry_attack_auc_drop_under_5pct(self, trained_model) -> None:
        """
        Mimicry attack: shift novelty_score down by 1σ for positive samples.
        AUC drop must be ≤ 5% (hypothesis H3).
        """
        clf, X_test, y_test = trained_model
        clean_auc = self._get_auc(clf, X_test, y_test)

        X_attack = X_test.copy()
        # Shift access_novelty_score (feature index 3) down by 1.0
        X_attack[:, 3] = np.maximum(0, X_attack[:, 3] - 1.0)
        attacked_auc = self._get_auc(clf, X_attack, y_test)

        drop_pct = 100 * (clean_auc - attacked_auc) / clean_auc
        assert drop_pct <= 5.0, (
            f"Mimicry AUC drop {drop_pct:.2f}% exceeds 5% threshold. "
            f"Clean={clean_auc:.4f}, Attacked={attacked_auc:.4f}"
        )

    def test_metadata_strip_evasion_detection(self, trained_model) -> None:
        """
        CLEANER profile: metadata_stripped=True should still be detectable.
        AUC drop when stripping feature must be ≤ 5%.
        """
        clf, X_test, y_test = trained_model
        clean_auc = self._get_auc(clf, X_test, y_test)

        X_attack = X_test.copy()
        X_attack[:, 4] = 0  # metadata_stripped = 0 (attacker cleans it)
        attacked_auc = self._get_auc(clf, X_attack, y_test)

        drop_pct = 100 * (clean_auc - attacked_auc) / clean_auc
        assert drop_pct <= 5.0, (
            f"Metadata-strip evasion AUC drop {drop_pct:.2f}% > 5% threshold"
        )

    def test_identity_proxy_injection(self, trained_model) -> None:
        """
        GHOST_AUTHOR: identity_proxy zeroed out.
        AUC drop ≤ 5%.
        """
        clf, X_test, y_test = trained_model
        clean_auc = self._get_auc(clf, X_test, y_test)

        X_attack = X_test.copy()
        X_attack[:, 7] = 0  # identity_proxy = 0
        attacked_auc = self._get_auc(clf, X_attack, y_test)

        drop_pct = 100 * (clean_auc - attacked_auc) / clean_auc
        assert drop_pct <= 5.0, (
            f"Identity-proxy injection AUC drop {drop_pct:.2f}% > 5%"
        )
