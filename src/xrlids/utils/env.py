"""Environment fingerprinting for reproducibility metadata.

Every experiment records the software environment and Git commit so a result can be
reconstructed against the exact code and libraries that produced it.
"""

from __future__ import annotations

import importlib.metadata as md
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any

# Packages whose versions materially affect results.
_TRACKED = (
    "numpy",
    "pandas",
    "scikit-learn",
    "scipy",
    "torch",
    "shap",
    "matplotlib",
    "PyYAML",
)


def git_commit(repo_root: str | Path = ".") -> str | None:
    """Return the current Git commit SHA, or None if unavailable.

    Never raises: a missing Git binary or an uncommitted tree must not break a pipeline,
    but the absence is recorded (as None) rather than faked.
    """
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        )
        return out.stdout.strip() or None
    except Exception:
        return None


def _pkg_versions() -> dict[str, str]:
    versions: dict[str, str] = {}
    for name in _TRACKED:
        try:
            versions[name] = md.version(name)
        except md.PackageNotFoundError:
            versions[name] = "not-installed"
    return versions


def environment_fingerprint(repo_root: str | Path = ".") -> dict[str, Any]:
    """Return a JSON-serialisable description of the execution environment."""
    try:
        import torch

        cuda = torch.cuda.is_available()
        cuda_version = torch.version.cuda if cuda else None
    except Exception:
        cuda = False
        cuda_version = None

    return {
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor_count": None,
        "cuda_available": cuda,
        "cuda_version": cuda_version,
        "git_commit": git_commit(repo_root),
        "packages": _pkg_versions(),
    }
