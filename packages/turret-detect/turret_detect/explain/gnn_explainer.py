"""
turret_detect.explain.gnn_explainer
======================================
GNNExplainer-based subgraph explanation for the TurretGNN model.
Identifies the most important edges and features in the 4-hop ego-subgraph
for each alert.  Computes fidelity and sparsity metrics for the paper.
"""

from __future__ import annotations

import logging
from typing import Any

import torch
import numpy as np

logger = logging.getLogger(__name__)


class TurretGNNExplainer:
    """
    GNNExplainer wrapper for the TurretGNN model.
    Uses torch_geometric.explain.GNNExplainer to identify the
    minimal sufficient subgraph for each alert's prediction.
    """

    def __init__(self, model: Any, device: torch.device | None = None) -> None:
        self.model = model
        self.device = device or torch.device("cpu")

    def explain_node(
        self,
        node_idx: int,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        timestamps: torch.Tensor,
        epochs: int = 200,
    ) -> dict[str, Any]:
        """
        Explain the prediction for a single node (user-day alert).

        Returns:
            dict with edge_mask, node_feat_mask, fidelity_score, sparsity
        """
        try:
            from torch_geometric.explain import Explainer, GNNExplainer  # type: ignore[import]
        except ImportError:
            logger.warning("torch_geometric.explain not available; returning empty explanation")
            return {"edge_mask": [], "node_feat_mask": [], "fidelity_score": 0.0, "sparsity": 0.0}

        explainer = Explainer(
            model=self.model,
            algorithm=GNNExplainer(epochs=epochs),
            explanation_type="model",
            node_mask_type="attributes",
            edge_mask_type="object",
            model_config={
                "mode": "binary_classification",
                "task_level": "node",
                "return_type": "probs",
            },
        )

        self.model.eval()
        x = x.to(self.device)
        edge_index = edge_index.to(self.device)
        timestamps = timestamps.to(self.device)

        try:
            explanation = explainer(x, edge_index, index=node_idx, timestamps=timestamps)

            edge_mask = explanation.edge_mask.detach().cpu().numpy().tolist()
            node_mask = explanation.node_mask.detach().cpu().numpy().tolist() if explanation.node_mask is not None else []

            # Fidelity: prediction drop when top edges removed
            fidelity = self._compute_fidelity(
                explanation, node_idx, x, edge_index, timestamps
            )

            # Sparsity: fraction of edges with mask < 0.1
            edge_arr = np.array(edge_mask)
            sparsity = float(np.mean(edge_arr < 0.1)) if len(edge_arr) > 0 else 0.0

            return {
                "node_idx": node_idx,
                "edge_mask": edge_mask,
                "node_feat_mask": node_mask,
                "fidelity_score": fidelity,
                "sparsity": sparsity,
            }
        except Exception as exc:
            logger.warning("GNNExplainer failed for node %d: %s", node_idx, exc)
            return {"node_idx": node_idx, "edge_mask": [], "node_feat_mask": [], "fidelity_score": 0.0, "sparsity": 0.0}

    def _compute_fidelity(
        self,
        explanation: Any,
        node_idx: int,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        timestamps: torch.Tensor,
        top_k_fraction: float = 0.3,
    ) -> float:
        """
        Fidelity = |pred_full - pred_masked|.
        Mask out the top-k important edges and measure prediction drop.
        """
        try:
            with torch.no_grad():
                pred_full = self.model(x, edge_index, timestamps)[node_idx].item()

                edge_mask = explanation.edge_mask
                n_mask = max(1, int(len(edge_mask) * top_k_fraction))
                top_edges = torch.topk(edge_mask, n_mask).indices

                # Remove top edges
                keep = torch.ones(edge_index.size(1), dtype=torch.bool, device=self.device)
                keep[top_edges] = False
                masked_edge_index = edge_index[:, keep]

                if masked_edge_index.size(1) == 0:
                    return 0.0

                pred_masked = self.model(x, masked_edge_index, timestamps)[node_idx].item()
                return abs(pred_full - pred_masked)
        except Exception as exc:
            logger.debug("Fidelity computation failed: %s", exc)
            return 0.0
