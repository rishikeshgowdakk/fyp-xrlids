"""PostgreSQL Persistent Storage Re-export for Backward Compatibility.

All canonical implementation resides in `xrlids.events.postgres`.
"""

from __future__ import annotations

from xrlids.events.postgres import (
    CREATE_INDEXES_SQL,
    CREATE_TABLE_SQL,
    INSERT_EVENT_SQL,
    PostgresEventStore,
)

__all__ = [
    "CREATE_TABLE_SQL",
    "CREATE_INDEXES_SQL",
    "INSERT_EVENT_SQL",
    "PostgresEventStore",
]
