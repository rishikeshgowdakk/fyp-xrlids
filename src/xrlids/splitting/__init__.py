"""Leakage-safe dataset splitting."""

from xrlids.splitting.leakage import audit_split_leakage
from xrlids.splitting.splitter import SplitConfig, SplitConfigurationError, SplitResult, build_splits

__all__ = [
    "audit_split_leakage",
    "SplitConfig",
    "SplitConfigurationError",
    "SplitResult",
    "build_splits",
]
