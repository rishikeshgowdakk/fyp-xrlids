"""Hashing helpers used for checksums and schema identity.

These hashes are the backbone of traceability: dataset checksums, feature-schema hashes
and preprocessor hashes all flow into experiment metadata.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Iterable, Mapping, Sequence

_CHUNK = 1 << 20  # 1 MiB


def sha256_bytes(data: bytes) -> str:
    """Return the hex SHA256 of a byte string."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str | Path, *, chunk_size: int = _CHUNK) -> str:
    """Return the hex SHA256 of a file, streamed so large datasets are safe."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def feature_schema_hash(features: Sequence[str] | Iterable[str]) -> str:
    """Hash an *ordered* feature schema.

    Order is significant: the model was trained on a specific column order, and a
    reordered vector is a different input even if the set of names is identical.
    """
    names = list(features)
    if len(names) != len(set(names)):
        dupes = sorted({n for n in names if names.count(n) > 1})
        raise ValueError(f"feature schema contains duplicate names: {dupes}")
    payload = "\n".join(names).encode("utf-8")
    return sha256_bytes(payload)


def dict_hash(obj: Mapping) -> str:
    """Stable hash of a JSON-serialisable mapping (sorted keys, no whitespace drift)."""
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_bytes(payload.encode("utf-8"))
