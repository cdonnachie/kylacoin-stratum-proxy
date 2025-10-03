# Quick Start: Enable Web Dashboard

Follow these steps to enable the web dashboard on your mining proxy.

## Step 1: Update Configuration

Edit your `.env` file and set:

```bash
ENABLE_DASHBOARD=true
DASHBOARD_PORT=8080
ENABLE_DATABASE=true
```

## Step 2: Rebuild and Restart (Docker)

```bash
docker-compose down
docker-compose build
docker-compose up -d
```

## Step 3: Access Dashboard

Open your browser to: **http://localhost:8080**

Or from another machine: **http://YOUR_SERVER_IP:8080**

## What You'll See

- **Live hashrate** of all connected miners
- **Active miner count** and details
- **Recent blocks found** (KCN and LCN)
- **24-hour statistics** (blocks, shares, acceptance rate)
- **Auto-refreshing** every 5 seconds

## Troubleshooting

### Dashboard Won't Load

1. Check logs:

```bash
docker-compose logs stratum-proxy | grep -i dashboard
```

Should see: `Starting web dashboard on port 8080`

2. Verify port mapping in `docker-compose.yml`:

```yaml
ports:
  - "8080:8080"
```

### No Statistics Showing

Make sure database is enabled:

```bash
ENABLE_DATABASE=true
```

Then rebuild:

```bash
docker-compose down && docker-compose build && docker-compose up -d
```

## Performance Impact

The dashboard and database have **minimal impact**:

- CPU: <1% overhead
- RAM: ~10MB additional
- Disk: ~1MB per month of statistics

## Disabling the Dashboard

To return to minimal mode, set in `.env`:

```bash
ENABLE_DASHBOARD=false
ENABLE_DATABASE=false
```

Then restart:

```bash
docker-compose restart stratum-proxy
```

---

For complete documentation, see [DASHBOARD.md](DASHBOARD.md)
