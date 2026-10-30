# XRL-IDARS — PostgreSQL Setup & Deployment Guide

This guide details how to configure, provision, and verify PostgreSQL event persistence for XRL-IDARS.

---

## 1. Environment Configuration

All database credentials and operating flags are supplied through environment variables. Zero credentials are hardcoded into the source repository.

### Environment Variables Reference

| Variable | Description | Default Value | Notes |
| :--- | :--- | :--- | :--- |
| `POSTGRES_HOST` | Database server host or IP | `localhost` | Container name `postgres` when in Docker |
| `POSTGRES_PORT` | Database server TCP port | `5432` | Standard PostgreSQL port |
| `POSTGRES_DB` | Target database name | `xrlids` | Standard XRL-IDARS event database |
| `POSTGRES_USER` | Database role username | `xrlids_user` | Non-root application user |
| `POSTGRES_PASSWORD` | Database role password | *(empty)* | Load securely from secret manager / env |
| `POSTGRES_SSLMODE` | SSL negotiation mode | `prefer` | `disable` for local dev, `require` for prod |
| `POSTGRES_CONNECT_TIMEOUT` | Connection attempt timeout | `5` (seconds) | Protects from hung TCP connections |
| `XRLIDS_STORAGE_MODE` | Persistence strategy | `auto` | Options: `auto`, `postgres`, `memory` |
| `XRLIDS_ASYNC_QUEUE_SIZE` | Persistence worker queue capacity | `10000` | Bounded FIFO queue limit |
| `XRLIDS_ASYNC_BATCH_SIZE` | Max batch size per transaction | `100` | Grouped insert size |
| `XRLIDS_ASYNC_FLUSH_INTERVAL` | Queue flush interval | `0.5` (seconds) | Max latency before batch write |

---

## 2. Setup Method 1: Docker Compose (Recommended for Containerized Environments)

A production-ready `docker-compose.yml` service is included in the project root.

### Step 1: Create local environment configuration
Copy the provided `.env.example` file and configure secure credentials:
```bash
cp .env.example .env
# Edit .env with your desired password
```

### Step 2: Launch PostgreSQL container
```bash
docker compose up -d postgres
```

### Step 3: Verify PostgreSQL container health
```bash
docker compose ps
```
PostgreSQL will report `healthy` once the `pg_isready` healthcheck probe completes.

### Step 4: Run XRL-IDARS with PostgreSQL
```bash
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=xrlids
export POSTGRES_USER=xrlids_user
export POSTGRES_PASSWORD=your_password
export XRLIDS_STORAGE_MODE=postgres

# Launch Streamlit dashboard
streamlit run dashboard/streamlit_app.py
```

---

## 3. Setup Method 2: Local Native PostgreSQL (Linux / Debian / Ubuntu / Fedora)

For developers running PostgreSQL directly on the host operating system without Docker.

### Step 1: Install PostgreSQL
On Debian/Ubuntu:
```bash
sudo apt update
sudo apt install -y postgresql postgresql-contrib
sudo systemctl enable --now postgresql
```

### Step 2: Create User and Database
```bash
sudo -u postgres psql -c "CREATE USER xrlids_user WITH PASSWORD 'change_me_to_strong_password';"
sudo -u postgres psql -c "CREATE DATABASE xrlids OWNER xrlids_user;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE xrlids TO xrlids_user;"
```

### Step 3: Export Environment Variables
```bash
export POSTGRES_HOST=localhost
export POSTGRES_PORT=5432
export POSTGRES_DB=xrlids
export POSTGRES_USER=xrlids_user
export POSTGRES_PASSWORD=change_me_to_strong_password
export XRLIDS_STORAGE_MODE=auto
```

### Step 4: Schema Auto-Initialization & Verification
The schema is automatically created on first startup by `PostgresEventStore.init_schema()`. You can also verify connectivity manually:
```bash
python -c "
from xrlids.events.postgres import PostgresEventStore
store = PostgresEventStore()
healthy, msg, details = store.health_check()
print(f'Healthy: {healthy} | {msg} | Latency: {details[\"latency_ms\"]}ms')
store.init_schema()
"
```

---

## 4. Verification & Health Monitoring

### Storage Health Indicator
In the XRL-IDARS Streamlit dashboard, navigate to **Detection & Security Events** (Page 4).
The top status banner will display:
```
🟢 Storage Backend: PostgreSQL Connected | Mode: auto | Persisted: 142 | Pending Queue: 0 | Failed Writes: 0 | Last Persistence: 2026-10-31 01:50:12 UTC
```

If PostgreSQL becomes unreachable, the banner automatically transitions to:
```
⚪ Storage Backend: In-Memory Ring Buffer + JSONL Audit File | PostgreSQL: Disconnected | Mode: memory | Local Buffer: 50 events
```
