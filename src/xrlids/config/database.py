"""PostgreSQL Database Configuration for XRL-IDARS.

Strictly adheres to security and environment conventions:
- Zero hardcoded passwords or credentials.
- All configuration loaded dynamically from environment variables.
- Explicit storage mode selection: 'auto', 'postgres', 'memory_jsonl', 'disabled'.
- Parameterized connection strings and connection dictionary generation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from typing import Any


@dataclass(frozen=True)
class DatabaseConfig:
    """PostgreSQL and Event Persistence Configuration."""

    host: str = "localhost"
    port: int = 5432
    database: str = "xrlids"
    user: str = "xrlids_user"
    password: str = ""  # NEVER hardcode; populated strictly from environment
    sslmode: str = "prefer"
    connect_timeout: int = 5  # seconds
    storage_mode: str = "auto"  # 'auto', 'postgres', 'memory_jsonl', 'disabled'
    jsonl_export: bool = True
    async_queue_size: int = 10000
    async_batch_size: int = 100
    async_flush_interval_s: float = 0.5

    @property
    def is_postgres_enabled(self) -> bool:
        """Evaluate if PostgreSQL persistence is configured to be attempted."""
        return self.storage_mode.lower() in ("auto", "postgres")

    @property
    def is_postgres_strictly_required(self) -> bool:
        """Evaluate if failure to connect to PostgreSQL must raise an error."""
        return self.storage_mode.lower() == "postgres"

    def to_connection_params(self) -> dict[str, Any]:
        """Generate kwargs dictionary suitable for psycopg.connect()."""
        params: dict[str, Any] = {
            "host": self.host,
            "port": self.port,
            "dbname": self.database,
            "user": self.user,
            "sslmode": self.sslmode,
            "connect_timeout": self.connect_timeout,
        }
        if self.password:
            params["password"] = self.password
        return params

    def to_safe_dict(self) -> dict[str, Any]:
        """Return configuration dictionary with sensitive credentials masked."""
        data = asdict(self)
        if data.get("password"):
            data["password"] = "******"
        return data

    def get_dsn(self, mask_password: bool = True) -> str:
        """Generate standard PostgreSQL DSN URI string."""
        pw = "******" if mask_password and self.password else self.password
        auth = f"{self.user}:{pw}@" if self.password else f"{self.user}@"
        return f"postgresql://{auth}{self.host}:{self.port}/{self.database}?sslmode={self.sslmode}"


def load_database_config_from_env() -> DatabaseConfig:
    """Load configuration from environment variables with safe, reproducible defaults."""
    host = os.environ.get("POSTGRES_HOST", "localhost").strip()
    port_str = os.environ.get("POSTGRES_PORT", "5432").strip()
    try:
        port = int(port_str)
    except ValueError:
        port = 5432

    database = os.environ.get("POSTGRES_DB", "xrlids").strip()
    user = os.environ.get("POSTGRES_USER", "xrlids_user").strip()
    password = os.environ.get("POSTGRES_PASSWORD", "").strip()
    sslmode = os.environ.get("POSTGRES_SSLMODE", "prefer").strip()

    timeout_str = os.environ.get("POSTGRES_CONNECT_TIMEOUT", "5").strip()
    try:
        connect_timeout = max(1, int(timeout_str))
    except ValueError:
        connect_timeout = 5

    storage_mode = os.environ.get("XRLIDS_STORAGE_MODE", "auto").strip().lower()
    if storage_mode not in ("auto", "postgres", "memory_jsonl", "disabled"):
        storage_mode = "auto"

    jsonl_export_val = os.environ.get("XRLIDS_JSONL_EXPORT", "true").strip().lower()
    jsonl_export = jsonl_export_val not in ("false", "0", "no", "off")

    queue_size_str = os.environ.get("XRLIDS_ASYNC_QUEUE_SIZE", "10000").strip()
    try:
        queue_size = max(100, int(queue_size_str))
    except ValueError:
        queue_size = 10000

    batch_size_str = os.environ.get("XRLIDS_ASYNC_BATCH_SIZE", "100").strip()
    try:
        batch_size = max(1, int(batch_size_str))
    except ValueError:
        batch_size = 100

    flush_interval_str = os.environ.get("XRLIDS_ASYNC_FLUSH_INTERVAL_S", "0.5").strip()
    try:
        flush_interval_s = max(0.05, float(flush_interval_str))
    except ValueError:
        flush_interval_s = 0.5

    return DatabaseConfig(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        sslmode=sslmode,
        connect_timeout=connect_timeout,
        storage_mode=storage_mode,
        jsonl_export=jsonl_export,
        async_queue_size=queue_size,
        async_batch_size=batch_size,
        async_flush_interval_s=flush_interval_s,
    )
