"""
turret_common.seeding
=====================
Global seed setting for full reproducibility across PyTorch, NumPy,
random, and Python's built-in hash seed.

Call set_global_seed(seed) once at the start of every training or
evaluation run to guarantee identical outputs across runs.
"""

from __future__ import annotations

import os
import random


def set_global_seed(seed: int) -> None:
    """
    Set all random seeds for full determinism.
    Must be called before any data loading or model initialisation.
    """
    random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)

    try:
        import numpy as np
        np.random.seed(seed)
    except ImportError:
        pass

    try:
        import torch
        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        # For full determinism on CUDA (may impact performance)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    except ImportError:
        pass
