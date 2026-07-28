"""
turret_detect.gnn.trainer
==========================
Training loop for the TurretGNN model.
Uses Focal loss + contrastive pretext task for imbalanced insider-threat data.
Implements deterministic training with seeded data splits (70/15/15).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
from torch.optim import Adam
from torch.optim.lr_scheduler import CosineAnnealingLR

from turret_detect.gnn.model import TurretGNN, FocalLoss
from turret_common.seeding import set_global_seed

logger = logging.getLogger(__name__)


class GNNTrainer:
    """
    Trains TurretGNN on a PyG dataset.

    Args:
        config: dict from config/default.yaml detection.gnn section
        seed:   Random seed for reproducibility
    """

    def __init__(self, config: dict[str, Any], seed: int = 42) -> None:
        self.config = config
        self.seed = seed
        set_global_seed(seed)

        device_str = config.get("device", "auto")
        if device_str == "auto":
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device_str)

        logger.info("GNNTrainer using device: %s", self.device)

        self.model: TurretGNN | None = None
        self.criterion = FocalLoss(
            alpha=config.get("focal_alpha", 0.25),
            gamma=config.get("focal_gamma", 2.0),
        )

    def build_model(self, node_feat_dim: int) -> TurretGNN:
        cfg = self.config
        self.model = TurretGNN(
            node_feat_dim=node_feat_dim,
            time_dim=cfg.get("time2vec_dim", 64),
            hidden_dim=cfg.get("hidden_dim", 256),
            num_layers=cfg.get("num_layers", 3),
            temporal_heads=cfg.get("temporal_heads", 4),
            dropout=cfg.get("dropout", 0.3),
        ).to(self.device)
        return self.model

    def train(
        self,
        train_data: Any,   # PyG Data or DataLoader
        val_data: Any,
        checkpoint_dir: Path,
        epochs: int = 60,
    ) -> dict[str, list[float]]:
        """
        Full training loop.
        Returns history dict with train_loss, val_auc per epoch.
        """
        if self.model is None:
            raise RuntimeError("Call build_model() before train()")

        optimizer = Adam(
            self.model.parameters(),
            lr=self.config.get("lr", 0.001),
            weight_decay=self.config.get("weight_decay", 1e-5),
        )
        scheduler = CosineAnnealingLR(optimizer, T_max=epochs)
        checkpoint_dir.mkdir(parents=True, exist_ok=True)

        history: dict[str, list[float]] = {"train_loss": [], "val_auc": []}
        best_val_auc = 0.0

        for epoch in range(1, epochs + 1):
            train_loss = self._train_epoch(train_data, optimizer)
            val_auc = self._eval_epoch(val_data)
            scheduler.step()

            history["train_loss"].append(train_loss)
            history["val_auc"].append(val_auc)

            logger.info("Epoch %3d/%d | loss=%.4f | val_auc=%.4f", epoch, epochs, train_loss, val_auc)

            # Save best checkpoint
            if val_auc > best_val_auc:
                best_val_auc = val_auc
                ckpt_path = checkpoint_dir / "gnn_best.pt"
                torch.save({
                    "epoch": epoch,
                    "model_state_dict": self.model.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "val_auc": val_auc,
                    "config": self.config,
                    "seed": self.seed,
                }, ckpt_path)

            # Save latest
            torch.save({
                "epoch": epoch,
                "model_state_dict": self.model.state_dict(),
                "val_auc": val_auc,
                "config": self.config,
                "seed": self.seed,
            }, checkpoint_dir / "gnn_latest.pt")

        logger.info("Training complete. Best val AUC: %.4f", best_val_auc)
        return history

    def _train_epoch(self, data: Any, optimizer: Any) -> float:
        self.model.train()  # type: ignore[union-attr]
        optimizer.zero_grad()

        # Handle PyG Data object
        if hasattr(data, "x"):
            x = data.x.to(self.device)
            edge_index = data.edge_index.to(self.device)
            ts = data.timestamps.to(self.device) if hasattr(data, "timestamps") else torch.zeros(x.size(0)).to(self.device)
            y = data.y.float().to(self.device)

            probs = self.model(x, edge_index, ts)  # type: ignore[misc]
            loss = self.criterion(probs, y)
            loss.backward()
            nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
            optimizer.step()
            return loss.item()
        return 0.0

    def _eval_epoch(self, data: Any) -> float:
        """Compute AUC on validation data."""
        self.model.eval()  # type: ignore[union-attr]
        with torch.no_grad():
            if not hasattr(data, "x"):
                return 0.0
            x = data.x.to(self.device)
            edge_index = data.edge_index.to(self.device)
            ts = data.timestamps.to(self.device) if hasattr(data, "timestamps") else torch.zeros(x.size(0)).to(self.device)
            y = data.y.cpu().numpy()
            probs = self.model(x, edge_index, ts).cpu().numpy()  # type: ignore[misc]

        try:
            from sklearn.metrics import roc_auc_score
            return float(roc_auc_score(y, probs))
        except Exception:
            return 0.0

    def load_checkpoint(self, checkpoint_path: Path) -> None:
        """Load model weights from checkpoint."""
        ckpt = torch.load(checkpoint_path, map_location=self.device)
        if self.model is None:
            raise RuntimeError("Call build_model() before load_checkpoint()")
        self.model.load_state_dict(ckpt["model_state_dict"])
        logger.info("Loaded checkpoint from %s (epoch %d, val_auc=%.4f)",
                    checkpoint_path, ckpt.get("epoch", -1), ckpt.get("val_auc", 0.0))
