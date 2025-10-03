# Web Dashboard Setup Guide

The KCN-LCN Stratum Proxy includes an optional web dashboard for monitoring your solo mining operations in real-time.

## Features

- **Live Miner Monitoring**: View connected miners, their hashrates, and uptime
- **Block History**: See recent blocks found on both KCN and LCN chains
- **Statistics**: Track 24-hour performance, acceptance rates, and total shares
- **Lightweight**: Minimal performance impact, optimized for speed
- **Auto-Refresh**: Updates every 5 seconds automatically

## Configuration

### Enable Dashboard

The dashboard is **disabled by default** to keep the proxy as lean as possible. Enable it by setting environment variables:

#### Using Docker Compose (.env file)

Add to your `.env` file:

```bash
# Web Dashboard Settings
ENABLE_DASHBOARD=true
DASHBOARD_PORT=8080

# Database Settings (optional, recommended with dashboard)
ENABLE_DATABASE=true
```

#### Using Command Line

```bash
export ENABLE_DASHBOARD=true
export DASHBOARD_PORT=8080
export ENABLE_DATABASE=true
```

### Configuration Options

| Variable           | Default | Description                           |
| ------------------ | ------- | ------------------------------------- |
| `ENABLE_DASHBOARD` | `false` | Enable the web dashboard              |
| `DASHBOARD_PORT`   | `8080`  | Port for the web interface            |
| `ENABLE_DATABASE`  | `false` | Enable SQLite database for statistics |

## Usage

### Docker Setup

1. **Update your .env file**:

```bash
ENABLE_DASHBOARD=true
DASHBOARD_PORT=8080
ENABLE_DATABASE=true
```

2. **Rebuild and restart containers**:

```bash
docker-compose down
docker-compose build
docker-compose up -d
```

3. **Access the dashboard**:
   - Open your browser to: `http://localhost:8080`
   - Or from another machine: `http://YOUR_SERVER_IP:8080`

### Standalone Setup

1. **Install dependencies**:

```bash
pip install -r requirements.txt
```

2. **Set environment variables**:

```bash
export ENABLE_DASHBOARD=true
export DASHBOARD_PORT=8080
export ENABLE_DATABASE=true
```

3. **Run the proxy**:

```bash
python -m kcn_proxy.run
```

4. **Access the dashboard**:
   - Open your browser to: `http://localhost:8080`

## Dashboard Features

### Overview Stats

The dashboard displays:

- **Total Hashrate**: Combined hashrate of all connected miners
- **Active Miners**: Number of currently connected miners
- **KCN Blocks (24h)**: Blocks found on KylaCoin in last 24 hours
- **LCN Blocks (24h)**: Blocks found on LynCoin in last 24 hours
- **Acceptance Rate**: Percentage of accepted shares vs rejected
- **Total Shares**: Total shares submitted in last 24 hours

### Active Miners Table

For each connected miner:

- Worker name/address
- Mining software (e.g., SRBMiner-MULTI)
- Current hashrate (MH/s or GH/s)
- Connection uptime

### Recent Blocks Table

Last 20 blocks found showing:

- Chain (KCN or LCN)
- Block height
- Block hash (abbreviated)
- Worker who found it
- Status (Accepted/Rejected)
- Time ago

## Database

When `ENABLE_DATABASE=true`, the proxy stores:

### Stored Data

- **Blocks Found**: Complete history with timestamps, chain, height, worker, etc.
- **Connection Events**: Miner connect/disconnect history
- **Share Statistics**: Aggregated per-minute stats (not individual shares)

### Database Location

- **Docker**: `./data/mining.db` (mounted volume)
- **Standalone**: `./data/mining.db` (in project directory)

### Performance Impact

The database is designed for minimal impact:

- Writes only on block finds and connections (rare events)
- Share stats aggregated by minute, not individual shares
- Uses async SQLite operations
- Typical overhead: <1% CPU, <10MB RAM

## Disabling the Dashboard

To run the proxy without the dashboard (minimal mode):

```bash
# In .env file or environment
ENABLE_DASHBOARD=false
ENABLE_DATABASE=false
```

This removes all dashboard and database overhead, keeping the proxy as lean as possible.

## Troubleshooting

### Dashboard Not Loading

1. **Check if enabled**:

```bash
docker-compose logs stratum-proxy | grep -i dashboard
```

Should see: `Starting web dashboard on port 8080`

2. **Check port mapping** in `docker-compose.yml`:

```yaml
ports:
  - "8080:8080"
```

3. **Check firewall**: Ensure port 8080 is open if accessing remotely

### No Statistics Showing

1. **Verify database is enabled**:

```bash
docker-compose logs stratum-proxy | grep -i database
```

Should see: `Initializing database...`

2. **Check database file exists**:

```bash
ls -la ./data/mining.db
```

3. **Verify miners are connected**:

```bash
docker-compose logs stratum-proxy | grep -i connected
```

### Performance Issues

If you experience performance problems:

1. **Disable database** if you only want real-time monitoring:

```bash
ENABLE_DATABASE=false
```

2. **Reduce refresh rate**: Edit `kcn_proxy/web/static/index.html`:

```javascript
// Change from 5000 (5 seconds) to 10000 (10 seconds)
setInterval(updateAll, 10000);
```

## API Endpoints

The dashboard also exposes a REST API:

| Endpoint              | Method | Description                   |
| --------------------- | ------ | ----------------------------- |
| `/`                   | GET    | Dashboard HTML page           |
| `/api/miners`         | GET    | Get active miners JSON        |
| `/api/blocks`         | GET    | Get recent blocks JSON        |
| `/api/blocks/{chain}` | GET    | Get blocks for specific chain |
| `/api/stats`          | GET    | Get summary statistics        |
| `/api/health`         | GET    | Health check endpoint         |

### Example API Usage

```bash
# Get current miners
curl http://localhost:8080/api/miners

# Get recent blocks
curl http://localhost:8080/api/blocks?limit=10

# Get KCN blocks only
curl http://localhost:8080/api/blocks/KCN

# Get statistics
curl http://localhost:8080/api/stats?hours=24
```

## Security Considerations

### Local Network Only

By default, the dashboard binds to `0.0.0.0` (all interfaces). For production:

1. **Use a reverse proxy** (nginx, Caddy) with authentication
2. **Firewall the port** to specific IP addresses
3. **Use VPN** for remote access

### No Authentication

The dashboard has **no built-in authentication**. It's designed for:

- Local network use
- Behind a firewall
- Solo mining setups

**Do NOT expose to the public internet without a reverse proxy with authentication.**

## Examples

### Minimal Setup (No Dashboard)

```bash
# .env file
ENABLE_DASHBOARD=false
ENABLE_DATABASE=false
```

### Dashboard Only (No Database)

```bash
# .env file
ENABLE_DASHBOARD=true
ENABLE_DATABASE=false
# Real-time monitoring only, no history
```

### Full Setup (Dashboard + Database)

```bash
# .env file
ENABLE_DASHBOARD=true
DASHBOARD_PORT=8080
ENABLE_DATABASE=true
# Complete monitoring with historical data
```

### Custom Port

```bash
# .env file
ENABLE_DASHBOARD=true
DASHBOARD_PORT=3000  # Use port 3000 instead
```

Then update docker-compose.yml port mapping:

```yaml
ports:
  - "3000:3000"
```

## Screenshots

The dashboard shows:

- Beautiful gradient purple background
- Clean, modern card-based layout
- Responsive design (works on mobile)
- Live updating indicators
- Color-coded chains (green for KCN, orange for LCN)
- Status badges (green for accepted, red for rejected)

## Support

If you encounter issues:

1. Check the logs: `docker-compose logs stratum-proxy`
2. Verify environment variables: `docker-compose config`
3. Check database file permissions: `ls -la ./data/`
4. Review browser console for errors (F12)

---

**Recommendation for Solo Mining**: Enable both dashboard and database for the best monitoring experience. The performance impact is negligible and the insights are valuable!
