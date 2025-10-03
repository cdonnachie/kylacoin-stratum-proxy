# Data Directory

This directory contains the SQLite database for mining statistics when `ENABLE_DATABASE=true`.

## Database File

- `mining.db` - SQLite database containing:
  - Block finds (chain, height, hash, worker, timestamp)
  - Connection events (worker connect/disconnect)
  - Share statistics (aggregated per minute)

## Size Expectations

- **Fresh install**: ~20 KB (empty database with schema)
- **After 1 month** (active solo mining): ~1-5 MB
- **After 1 year**: ~10-50 MB

The database is designed to be lightweight with minimal storage requirements.

## Backup

To backup your statistics:

```bash
# Copy the database file
cp data/mining.db data/mining_backup_$(date +%Y%m%d).db
```

## Reset

To start fresh (WARNING: deletes all history):

```bash
# Stop the proxy
docker-compose down

# Remove database
rm data/mining.db

# Restart proxy
docker-compose up -d
```

## Access

The database can be queried directly using SQLite tools:

```bash
# Using sqlite3 command line
sqlite3 data/mining.db "SELECT * FROM blocks ORDER BY timestamp DESC LIMIT 10;"

# Or use a GUI tool like DB Browser for SQLite
```

## Schema

See `kcn_proxy/db/schema.py` for complete table definitions.
