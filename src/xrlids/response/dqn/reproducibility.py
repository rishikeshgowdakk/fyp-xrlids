"""Reproducibility Utilities and Environment Provenance (SPEC-P2-AUTONOMOUS-RESPONSE-001).

Implements deterministic seeding and environment provenance capture.
"""

from __future__ import annotations

import os
import random
import sys
from typing import Any
import numpy as np
import torch

from xrlids.utils.env import git_commit


def set_seed(seed: int = 42) -> None:
    """Set random seeds across Python, NumPy, and PyTorch for deterministic execution."""
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


def capture_provenance(seed: int = 42, git_sha: str | None = None) -> dict[str, Any]:
    """Capture comprehensive runtime software and hardware environment metadata."""
    effective_git = git_sha or git_commit()
    return {
        "random_seed": seed,
        "git_commit": effective_git,
        "python_version": sys.version.split()[0],
        "platform": sys.platform,
        "torch_version": torch.__version__,
        "numpy_version": np.__version__,
        "cuda_available": torch.cuda.is_available(),
    }
