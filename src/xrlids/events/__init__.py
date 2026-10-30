"""Unified Security Event Schema, Event Management, and Persistence for XRL-IDARS.

Defines standardized JSON-serializable security events connecting perception,
explainability, source tracking, rules, and autonomous response.
"""

from xrlids.events.database import DatabaseConfig, load_database_config_from_env
from xrlids.events.manager import EventManager
from xrlids.events.postgres import PostgresEventStore
from xrlids.events.schema import SecurityEvent

__all__ = [
    "SecurityEvent",
    "EventManager",
    "DatabaseConfig",
    "load_database_config_from_env",
    "PostgresEventStore",
]
