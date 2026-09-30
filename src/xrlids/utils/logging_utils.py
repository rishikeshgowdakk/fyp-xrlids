"""Logging configuration.

Pipeline stages log experiment id, dataset, config, paths, row counts, class
distribution, elapsed time, warnings and errors. A single helper keeps the format
consistent so logs are greppable and machine-parseable.
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

_CONFIGURED = False
_FORMAT = "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s"


def configure_logging(level: int | str = logging.INFO) -> None:
    """Configure the root logger exactly once."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(_FORMAT))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a logger, configuring the root logger on first use."""
    configure_logging()
    return logging.getLogger(name)


def log_event(logger: logging.Logger, event: str, **fields: Any) -> None:
    """Log a structured key=value event.

    Values are JSON-encoded so heterogeneous payloads (dicts, lists, floats) remain
    parseable without ad-hoc formatting.
    """
    rendered = " ".join(f"{k}={json.dumps(v, default=str)}" for k, v in sorted(fields.items()))
    logger.info("%s %s", event, rendered)
