"""
turret_detect.gnn.model
========================
GraphSAGE + Time2Vec + Temporal Attention model for insider threat detection.

Architecture:
  Input: node feature matrix + edge index + edge timestamps
  → Time2Vec encoding of timestamps
  → 3x GraphSAGE layers with residual connections
  → Temporal self-attention over node neighbourhood
  → MLP classifier head → binary alert score ∈ [0, 1]

Reference:
  Hamilton et al. (2017) "Inductive Representation Learning on Large Graphs"
  Kazemi et al. (2019) "Time2Vec: Learning a Vector Representation of Time"
"""

from __future__ import annotations

import math
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch_geometric.nn import SAGEConv  # type: ignore[import]


class Time2Vec(nn.Module):
    """
    Learnable time encoding.
    Encodes a scalar timestamp t as:
      [t·ω₀+b₀, sin(t·ω₁+b₁), ..., sin(t·ω_k+b_k)]
    """

    def __init__(self, out_dim: int) -> None:
        super().__init__()
        self.out_dim = out_dim
        # Linear component (index 0) + sinusoidal components (1..out_dim-1)
        self.W = nn.Parameter(torch.empty(out_dim))
        self.b = nn.Parameter(torch.empty(out_dim))
        nn.init.uniform_(self.W, -math.pi, math.pi)
        nn.init.uniform_(self.b, -math.pi, math.pi)

    def forward(self, t: Tensor) -> Tensor:
        """
        Args:
            t: (batch,) or (batch, 1) float tensor of timestamps
        Returns:
            (batch, out_dim) time encoding
        """
        if t.dim() == 1:
            t = t.unsqueeze(-1)  # (B, 1)
        t = t.float()
        out = t * self.W + self.b   # (B, out_dim)
        # First component is linear, rest are sinusoidal
        out[:, 1:] = torch.sin(out[:, 1:])
        return out


class TurretGNN(nn.Module):
    """
    GraphSAGE + Time2Vec + TemporalAttention insider threat detection model.

    Args:
        node_feat_dim:  Input node feature dimensionality.
        time_dim:       Time2Vec output dimension.
        hidden_dim:     GraphSAGE hidden dimension.
        num_layers:     Number of GraphSAGE layers.
        temporal_heads: Number of temporal attention heads.
        dropout:        Dropout probability.
    """

    def __init__(
        self,
        node_feat_dim: int,
        time_dim: int = 64,
        hidden_dim: int = 256,
        num_layers: int = 3,
        temporal_heads: int = 4,
        dropout: float = 0.3,
    ) -> None:
        super().__init__()

        self.time2vec = Time2Vec(time_dim)

        # Input projection
        in_dim = node_feat_dim + time_dim
        self.input_proj = nn.Linear(in_dim, hidden_dim)

        # GraphSAGE layers
        self.sage_layers = nn.ModuleList([
            SAGEConv(hidden_dim, hidden_dim) for _ in range(num_layers)
        ])

        # Batch normalisation per layer
        self.bns = nn.ModuleList([nn.BatchNorm1d(hidden_dim) for _ in range(num_layers)])

        # Temporal self-attention
        self.temporal_attn = nn.MultiheadAttention(
            embed_dim=hidden_dim,
            num_heads=temporal_heads,
            dropout=dropout,
            batch_first=True,
        )

        # Classifier MLP
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim // 2, 1),
        )

        self.dropout = nn.Dropout(dropout)
        self._init_weights()

    def _init_weights(self) -> None:
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.xavier_uniform_(m.weight)
                if m.bias is not None:
                    nn.init.zeros_(m.bias)

    def forward(
        self,
        x: Tensor,          # (N, node_feat_dim) node features
        edge_index: Tensor, # (2, E) edge connectivity
        timestamps: Tensor, # (N,) per-node timestamps
    ) -> Tensor:
        """
        Forward pass.

        Returns:
            (N,) float tensor of alert probabilities ∈ [0, 1]
        """
        # Time2Vec encoding
        t_enc = self.time2vec(timestamps)          # (N, time_dim)
        h = torch.cat([x.float(), t_enc], dim=-1)  # (N, node_feat_dim + time_dim)
        h = self.input_proj(h)                      # (N, hidden_dim)
        h = F.relu(h)

        # GraphSAGE layers with residual + BN
        for sage, bn in zip(self.sage_layers, self.bns):
            residual = h
            h = sage(h, edge_index)
            h = bn(h)
            h = F.relu(h)
            h = self.dropout(h)
            h = h + residual   # residual connection

        # Temporal attention (treat all nodes as a sequence for global context)
        h_seq = h.unsqueeze(0)           # (1, N, hidden_dim)
        h_attn, _ = self.temporal_attn(h_seq, h_seq, h_seq)
        h = h + h_attn.squeeze(0)        # residual

        # Classification
        logits = self.classifier(h).squeeze(-1)  # (N,)
        return torch.sigmoid(logits)


class FocalLoss(nn.Module):
    """
    Focal loss for highly imbalanced insider threat datasets.
    FL(p_t) = -α_t * (1 - p_t)^γ * log(p_t)
    """

    def __init__(self, alpha: float = 0.25, gamma: float = 2.0) -> None:
        super().__init__()
        self.alpha = alpha
        self.gamma = gamma

    def forward(self, probs: Tensor, targets: Tensor) -> Tensor:
        targets = targets.float()
        bce = F.binary_cross_entropy(probs, targets, reduction="none")
        p_t = probs * targets + (1 - probs) * (1 - targets)
        alpha_t = self.alpha * targets + (1 - self.alpha) * (1 - targets)
        focal_weight = (1 - p_t) ** self.gamma
        loss = alpha_t * focal_weight * bce
        return loss.mean()
