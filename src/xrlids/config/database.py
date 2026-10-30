"""PostgreSQL Database Configuration Re-export for Backward Compatibility.

All canonical implementation resides in `xrlids.events.database`.
"""

from __future__ import annotations

from xrlids.events.database import DatabaseConfig, load_database_config_from_env

__all__ = ["DatabaseConfig", "load_database_config_from_env"]
