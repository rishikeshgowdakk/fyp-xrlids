"""Deterministic seeding.

Every stochastic stage in Phase 1 must call :func:`set_global_seeds` and record the seed
in the experiment metadata. GPU nondeterminism is documented rather than hidden.
"""

from __future__ import annotations

import os
import random

import numpy as np


def set_global_seeds(seed: int, *, deterministic_torch: bool = True) -> int:
    """Seed Python, NumPy and (if installed) PyTorch.

    Parameters
    ----------
    seed:
        The seed value. It is recorded verbatim in experiment metadata.
    deterministic_torch:
        When True, request deterministic PyTorch algorithms. This can raise if an
        operation has no deterministic implementation; callers that hit that should
        document the source of nondeterminism rather than disable seeding.

    Returns
    -------
    int
        The seed, so callers can pass it straight into metadata.
    """
    if seed is None:
        raise ValueError("seed must be an explicit integer; None is not reproducible")

    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)

    try:  # torch is an optional heavy dependency for non-LSTM work
        import torch

        torch.manual_seed(seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
        if deterministic_torch:
            torch.use_deterministic_algorithms(True, warn_only=True)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False
    except ImportError:
        pass

    return seed
