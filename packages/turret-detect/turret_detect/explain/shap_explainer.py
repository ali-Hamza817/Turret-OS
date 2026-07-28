"""
turret_detect.explain.shap_explainer
======================================
SHAP-based feature importance for the rule vector component
of the TURRET OS detection pipeline.
Computes SHAP values and fidelity R² vs human-labelled causal attribution.
"""

from __future__ import annotations

import logging
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)


class SHAPExplainer:
    """
    Compute SHAP values for the rule-feature vector.

    Uses TreeExplainer or KernelExplainer depending on the base model.
    For the GNN ensemble component, uses a surrogate gradient boosting model
    trained on the GNN node embeddings.
    """

    def __init__(self, model: Any, feature_names: list[str]) -> None:
        self.model = model
        self.feature_names = feature_names
        self._explainer: Any = None

    def fit(self, background_data: np.ndarray) -> None:
        """Fit the SHAP explainer on background data."""
        import shap  # type: ignore[import]
        try:
            # Try TreeExplainer first (faster)
            self._explainer = shap.TreeExplainer(self.model)
        except Exception:
            # Fall back to KernelExplainer for arbitrary models
            self._explainer = shap.KernelExplainer(
                self.model.predict_proba
                if hasattr(self.model, "predict_proba")
                else self.model,
                background_data[:100],   # use max 100 background samples
            )
        logger.info("SHAP explainer fitted with %d features", len(self.feature_names))

    def explain(self, X: np.ndarray) -> dict[str, np.ndarray]:
        """
        Compute SHAP values for input X.

        Returns:
            dict with 'shap_values' (N, features) and 'base_value' (float)
        """
        if self._explainer is None:
            raise RuntimeError("Call fit() before explain()")

        import shap  # type: ignore[import]
        shap_vals = self._explainer.shap_values(X)

        # For binary classification, take positive class SHAP values
        if isinstance(shap_vals, list) and len(shap_vals) == 2:
            shap_vals = shap_vals[1]

        return {
            "shap_values": np.array(shap_vals),
            "feature_names": self.feature_names,
            "base_value": float(self._explainer.expected_value
                                if not isinstance(self._explainer.expected_value, list)
                                else self._explainer.expected_value[1]),
        }

    def compute_fidelity(
        self,
        shap_values: np.ndarray,
        human_labels: np.ndarray,
        top_k: int = 5,
    ) -> float:
        """
        Compute SHAP fidelity R² vs human-annotated causal features.
        
        Args:
            shap_values:  (N, F) SHAP value matrix
            human_labels: (N, F) binary mask of human-labelled causal features
            top_k:        Number of top-k features to consider
            
        Returns:
            R² correlation coefficient
        """
        from scipy.stats import pearsonr  # type: ignore[import]

        # Compute top-k feature ranks per sample
        turret_ranks = np.argsort(-np.abs(shap_values), axis=1)[:, :top_k]
        human_ranks = np.argsort(-human_labels, axis=1)[:, :top_k]

        # Overlap @ top-k as agreement score per sample
        overlaps = []
        for t_row, h_row in zip(turret_ranks, human_ranks):
            overlap = len(set(t_row.tolist()) & set(h_row.tolist())) / top_k
            overlaps.append(overlap)

        # Also compute magnitude correlation
        shap_mag = np.abs(shap_values).flatten()
        human_mag = human_labels.flatten().astype(float)

        try:
            r, _ = pearsonr(shap_mag, human_mag)
            r_sq = float(r ** 2)
        except Exception:
            r_sq = 0.0

        logger.info("SHAP fidelity R²=%.4f, mean overlap@%d=%.4f", r_sq, top_k, np.mean(overlaps))
        return r_sq
