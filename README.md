# Kylacoin-Lyncoin Stratum Proxy

A stratum mining proxy for Kylacoin with optional Lyncoin merged mining (AuxPoW).

## Features

- ✅ **Merged Mining (AuxPoW)**: Mine both KylaCoin and LynCoin simultaneously
- ✅ **ZMQ Support**: Instant new block notifications for both chains
- ✅ **Parallel Block Submission**: Submit to both chains simultaneously for optimal speed
- ✅ **Notifications**: Discord and Telegram alerts for blocks found and miner connections
- ✅ **Web Dashboard** _(optional)_: Real-time monitoring of miners, hashrates, and blocks
- ✅ **SQLite Database** _(optional)_: Historical statistics and block history
- ✅ **Docker Ready**: Complete docker-compose setup with health checks
- ✅ **Flexible Difficulty**: Configurable share difficulty for any hashrate

## Quick Start

Choose your setup method:

### Option 1: Docker Compose (Recommended)

**Prerequisites:** Docker and Docker Compose installed

1. **Place Linux binaries**:

   ```bash
   # Copy Linux x86_64 binaries (NOT Windows/macOS)
   binaries/kylacoin/kylacoind
   binaries/kylacoin/kylacoin-cli
   binaries/lyncoin/lyncoind
   binaries/lyncoin/lyncoin-cli
   ```

2. **Configure environment**:

   ```bash
   cp .env.example .env
   # Edit .env - set passwords and optionally LCN_WALLET_ADDRESS for merged mining
   ```

3. **Start services**:

   ```bash
   docker-compose up -d
   docker-compose logs -f stratum-proxy  # Watch logs
   ```

4. **Connect miner**:
   - Server: `localhost:54321`
   - Username: Your Kylacoin address
   - Password: anything

### Option 2: Native Python (Your Own Nodes)

**Prerequisites:** Python 3.8+, running kylacoind and lyncoind nodes

1. **Configure blockchain nodes**:

   - Copy `config/kylacoin.conf` to your Kylacoin data directory
   - Copy `config/lyncoin.conf` to your Lyncoin data directory (optional, for merged mining)
   - Edit both files with secure passwords
   - Start both daemons

2. **Install Python dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure proxy**:

   ```bash
   cp .env.example .env
   # Edit .env to match your node RPC settings
   ```

4. **Run proxy**:

   ```bash
   python -m kcn_proxy.run
   ```

5. **Connect miner**: Same as Docker method above

## Configuration

### Essential Environment Variables

| Variable                        | Description                        | Default            |
| ------------------------------- | ---------------------------------- | ------------------ |
| `KCN_RPC_PORT`                  | Kylacoin RPC port                  | 5110               |
| `KCN_RPC_USER` / `KCN_RPC_PASS` | Kylacoin RPC credentials           | -                  |
| `LCN_RPC_PORT`                  | Lyncoin RPC port                   | 5053               |
| `LCN_RPC_USER` / `LCN_RPC_PASS` | Lyncoin RPC credentials            | -                  |
| `LCN_WALLET_ADDRESS`            | Lyncoin address for merged mining  | (blank = KCN only) |
| `STRATUM_PORT`                  | Port for miners to connect         | 54321              |
| `SHARE_DIFFICULTY_DIVISOR`      | Share difficulty (higher = easier) | 1000.0             |
| `USE_EASIER_TARGET`             | Use LCN target if easier           | true               |
| `ENABLE_ZMQ`                    | Enable ZMQ block notifications     | true               |
| `DISCORD_WEBHOOK_URL`           | Discord webhook for notifications  | (blank = disabled) |
| `TELEGRAM_BOT_TOKEN`            | Telegram bot token                 | (blank = disabled) |
| `TELEGRAM_CHAT_ID`              | Telegram chat ID                   | (blank = disabled) |
| `ENABLE_DASHBOARD`              | Enable web dashboard               | false              |
| `DASHBOARD_PORT`                | Web dashboard port                 | 8080               |
| `ENABLE_DATABASE`               | Enable statistics database         | false              |

See [NOTIFICATIONS.md](NOTIFICATIONS.md) for notification setup and [DASHBOARD.md](DASHBOARD.md) for dashboard configuration.

### Share Difficulty

`SHARE_DIFFICULTY_DIVISOR` controls how often miners submit shares:

- **Higher** (e.g., 2000): Easier shares, more frequent, better for home mining
- **Lower** (e.g., 500): Harder shares, less traffic, better for pools
- **Default (1000)**: Good balance

## Merged Mining (AuxPoW)

When `LCN_WALLET_ADDRESS` is set, the proxy enables merged mining. Here's how it works:

### How It Works

Both Kylacoin (KCN) and Lyncoin (LCN) use the **same Flex PoW hash** for difficulty validation:

```
Block Header (80 bytes)
    ↓
Flex PoW hash → Compare with both KCN and LCN targets
    ↓
    ├─→ Meets KCN target? → Submit to KCN → Earn KCN
    └─→ Meets LCN target? → Submit AuxPoW to LCN → Earn LCN

Example at typical difficulties (KCN: 0.008, LCN: 0.007):
  Flex PoW: 0x00000065...

  Compare: 0x00000065... < 0x0000007e... (KCN target) → ✗ No
  Compare: 0x00000065... < 0x00000080... (LCN target) → ✓ Yes!

  Result: Submit to LCN only, earn LCN rewards
```

### AuxPoW Structure

When submitting to LCN, the proxy creates an AuxPoW proof containing:

- Parent (KCN) coinbase transaction
- Parent block hash (SHA3d) - for block identification
- Merkle proofs
- Parent block header (80 bytes)

**Important**: While SHA3d is used for the block hash in the AuxPoW structure (what appears on block explorers), both chains validate difficulty using the **Flex PoW hash**.

### Block Finding Scenarios

At typical difficulties (KCN: ~0.008, LCN: ~0.007):

1. **LCN only**: Flex PoW meets LCN target → Submit AuxPoW → Earn LCN (most common, easier target)
2. **KCN only**: Flex PoW meets KCN target → Submit block → Earn KCN (less common, harder target)
3. **Both chains**: Flex PoW meets BOTH targets → Submit to both → Double rewards! (rare)

**Why LCN blocks are more common:**

- LCN typically has an easier target (~0.007 vs ~0.008)
- Both chains check the same Flex PoW hash
- The easier target means more shares qualify for LCN
- **Result**: You'll find more LCN blocks than KCN blocks

**Note:** The proxy automatically uses whichever target is easier when `USE_EASIER_TARGET=true`.

## Monitoring

**Block submissions** are logged to `./submit_history/`:

- `KCN_<height>_<job>_<time>.txt` - Kylacoin blocks
- `LCN_<height>_<job>_<time>.txt` - Lyncoin AuxPoW blocks

**Check logs:**

```bash
# Docker
docker-compose logs -f stratum-proxy

# Native
# Watch console output
```

## Troubleshooting

**"Coinbase parts not ready"**: Nodes still syncing, wait for full sync

**"LCN aux job is stale"**: Normal when LCN finds blocks, proxy auto-refreshes

**Miner can't connect**: Check firewall, verify STRATUM_PORT is correct

**Binary format error**: Must use Linux ELF x86_64 binaries for Docker

**Low hashrate**: Increase `SHARE_DIFFICULTY_DIVISOR` for more frequent feedback

## Advanced

### ZMQ Block Notifications

The proxy uses ZMQ for instant block notifications instead of polling:

- **KCN**: Port 28332
- **LCN**: Port 28433

Both conf files include ZMQ settings. Disable with `ENABLE_ZMQ=false` if needed.

### Job IDs

Job IDs are Unix timestamps (e.g., `66fb8a10`), updated:

- On new blocks (via ZMQ)
- Every 30 seconds (nTime rolls)
- When LCN creates new template

### Project Structure

```
kcn_proxy/
├── consensus/    # Block/transaction building
├── rpc/          # RPC client implementations
├── state/        # Template state management
├── stratum/      # Stratum protocol server
├── utils/        # Hashing and encoding
└── zmq/          # ZMQ block listeners
```

## License

MIT License - See LICENSE file

A Docker Compose setup for running a stratum proxy that enables mining Kylacoin (parent chain) and Lyncoin (auxiliary chain) simultaneously using AuxPoW.

## Quick Start

1. **Place the Linux binaries**:

   - Copy **Linux x86_64** `kylacoind` and `kylacoin-cli` to `binaries/kylacoin/`
   - Copy **Linux x86_64** `lyncoind` and `lyncoin-cli` to `binaries/lyncoin/`

   ⚠️ **Important**: Use Linux binaries only (not Windows .exe or macOS binaries)

2. **Update the environment file**:

   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

3. **Configure wallet addresses** (optional):
   Edit the `.env` file and set:

   - `LCN_WALLET_ADDRESS`: Your Lyncoin address for dual-chain mining (leave blank for Kylacoin-only mining)
   - Update RPC credentials for security

4. **Start the services**:

   ```bash
   docker compose up -d
   ```

5. **Check logs**:

   ```bash
   docker compose logs -f stratum-proxy
   ```

6. **Connect your miner**:
   - Point your miner to `localhost:54321`
   - Use your Kylacoin address as username
   - Any password

## Configuration

### Environment Variables

| Variable                   | Description                                            | Default                   |
| -------------------------- | ------------------------------------------------------ | ------------------------- |
| `KCN_RPC_USER`             | Kylacoin RPC username                                  | kylacoin_user             |
| `KCN_RPC_PASS`             | Kylacoin RPC password                                  | -                         |
| `KCN_RPC_PORT`             | Kylacoin RPC port                                      | 5110                      |
| `KCN_P2P_PORT`             | Kylacoin P2P port                                      | 5111                      |
| `LCN_RPC_USER`             | Lyncoin RPC username                                   | lyncoin_user              |
| `LCN_RPC_PASS`             | Lyncoin RPC password                                   | -                         |
| `LCN_RPC_PORT`             | Lyncoin RPC port                                       | 5053                      |
| `LCN_P2P_PORT`             | Lyncoin P2P port                                       | 5054                      |
| `LCN_WALLET_ADDRESS`       | Lyncoin wallet address (blank = primary-only mode)     | (blank - disables AuxPoW) |
| `STRATUM_PORT`             | Stratum proxy port                                     | 54321                     |
| `PROXY_SIGNATURE`          | Custom coinbase signature                              | /kcn-lcn-stratum-proxy/   |
| `USE_EASIER_TARGET`        | Enable easier target selection                         | true                      |
| `SHARE_DIFFICULTY_DIVISOR` | Share difficulty divisor (higher = easier/more shares) | 1000.0                    |
| `TESTNET`                  | Use testnet                                            | false                     |
| `VERBOSE`                  | Enable verbose logging                                 | true                      |
| `SHOW_JOBS`                | Show job updates in logs                               | true                      |

## Binary Setup

This setup uses local binaries instead of pre-built Docker images, giving you complete control over the cryptocurrency node versions.

### Required Binaries

Place the following files in their respective directories:

**Kylacoin** (`binaries/kylacoin/`):

- `kylacoind` - The main daemon
- `kylacoin-cli` - CLI client

**Lyncoin** (`binaries/lyncoin/`):

- `lyncoind` - The main daemon
- `lyncoin-cli` - CLI client

### Binary Requirements

⚠️ **Critical**: Only Linux binaries work with Docker containers!

- **Platform**: Linux x86_64 ELF binaries (NOT Windows .exe or macOS binaries)
- **Base System**: Ubuntu 24.04 compatible
- **glibc Version**: 2.36+ support (Ubuntu 24.04 provides glibc 2.39)
- **Executable permissions**: Set automatically by Docker
- **Dependencies**: Must be included or statically linked

### Getting Binaries

1. **Download releases** from official repositories
2. **Build from source** for your specific needs
3. **Extract from existing installations**

### Verification

Check if binaries are correct format:

```bash
file binaries/kylacoin/kylacoind
file binaries/lyncoin/lyncoind
```

**Expected Output:**

```
binaries/kylacoin/kylacoind: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
binaries/lyncoin/lyncoind: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, stripped
```

❌ **Wrong formats** (will NOT work):

- Windows: `PE32+ executable (console) x86-64, for MS Windows`
- macOS: `Mach-O 64-bit executable x86_64`

### Services

- **kylacoin**: Kylacoin daemon (parent chain)
  - RPC: `localhost:5110`
  - P2P: `localhost:5111`
- **lyncoin**: Lyncoin daemon (auxiliary chain)
  - RPC: `localhost:5053`
  - P2P: `localhost:5054`
- **stratum-proxy**: Mining proxy
  - Stratum: `localhost:54321`

## Customization

### Proxy Signature

The proxy includes a customizable signature in coinbase transactions to identify your mining setup. This appears in the blockchain and helps identify blocks found by your proxy.

**Configuration Options:**

1. **Environment Variable** (recommended for Docker):

   ```bash
   # In .env file
   PROXY_SIGNATURE=/your-pool-name/
   ```

2. **Command Line Argument**:
   ```bash
   python kcn-lcn-stratum-proxy.py --proxy-signature="/my-custom-signature/" [other args...]
   ```

**Guidelines:**

- Keep it short (max 32 bytes recommended)
- Use forward slashes or other characters to make it recognizable
- Examples: `/MyPool/`, `/Solo-Miner-2025/`, `/KCN-LCN-Proxy/`

**Default:** `/kcn-lcn-stratum-proxy/`

## Usage

### Native Python Execution (Without Docker)

If you prefer to run the proxy directly with Python instead of using Docker:

#### Prerequisites

1. **Python 3.8+** installed on your system
2. **Kylacoin and Lyncoin nodes** running separately (either locally or remotely)
3. **Python dependencies** installed

#### Setup Steps

1. **Install Python dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

2. **Configure your blockchain nodes** (optional):

   For convenience, you can use the provided configuration templates:

   - **Kylacoin**: Copy `kylacoin.conf` to your Kylacoin data directory
   - **Lyncoin**: Copy `lyncoin.conf` to your Lyncoin data directory

   **Data directory locations:**

   - Windows: `%APPDATA%\Kylacoin\` and `%APPDATA%\Lyncoin\`
   - Linux: `~/.kylacoin/` and `~/.lyncoin/`
   - macOS: `~/Library/Application Support/Kylacoin/` and `~/Library/Application Support/Lyncoin/`

3. **Ensure your nodes are running**:

   - Kylacoin node accessible via RPC (default: `localhost:5110`)
   - Lyncoin node accessible via RPC (default: `localhost:5053`)

4. **Run the proxy**:

   **For localhost testing only:**

   ```bash
   python kcn-lcn-stratum-proxy.py \
     --ip=127.0.0.1 \
     --port=54321 \
     --rpcuser=your_kcn_rpc_user \
     --rpcpass=your_kcn_rpc_password \
     --rpcip=127.0.0.1 \
     --rpcport=5110 \
     --aux-rpcuser=your_lcn_rpc_user \
     --aux-rpcpass=your_lcn_rpc_password \
     --aux-rpcip=127.0.0.1 \
     --aux-rpcport=5053 \
     --aux-address=your_lyncoin_address \
     --use-easier-target \
     --verbose
   ```

   **For HiveOS rigs or remote miners:**

   ```bash
   python kcn-lcn-stratum-proxy.py \
     --ip=0.0.0.0 \
     --port=54321 \
     --rpcuser=your_kcn_rpc_user \
     --rpcpass=your_kcn_rpc_password \
     --aux-address=your_lyncoin_address \
     --use-easier-target \
     --verbose
   ```

#### Example with Environment Variables

You can also use environment variables (create a `.env` file or export them):

```bash
# Set environment variables
export KCN_RPC_USER=your_kcn_user
export KCN_RPC_PASS=your_kcn_password
export LCN_RPC_USER=your_lcn_user
export LCN_RPC_PASS=your_lcn_password
export LCN_WALLET_ADDRESS=your_lyncoin_address
export PROXY_SIGNATURE=/my-custom-proxy/

# Run with minimal arguments (reads from environment)
python kcn-lcn-stratum-proxy.py \
  --rpcuser=$KCN_RPC_USER \
  --rpcpass=$KCN_RPC_PASS \
  --aux-rpcuser=$LCN_RPC_USER \
  --aux-rpcpass=$LCN_RPC_PASS \
  --aux-address=$LCN_WALLET_ADDRESS \
  --use-easier-target \
  --verbose
```

#### Network Binding Options

The `--ip` parameter controls which network interface the proxy binds to:

| IP Address      | Use Case                | Security | Description                                             |
| --------------- | ----------------------- | -------- | ------------------------------------------------------- |
| `127.0.0.1`     | **Testing/Development** | High     | Localhost only - miners must run on same machine        |
| `0.0.0.0`       | **Production Mining**   | Medium   | All interfaces - HiveOS rigs, remote miners can connect |
| `192.168.1.100` | **Specific Network**    | Medium   | Bind to specific IP - only that network interface       |

**Security Considerations:**

- `127.0.0.1`: Safest, only local access
- `0.0.0.0`: Requires firewall rules to restrict access
- Specific IP: Good compromise between accessibility and security

#### Available Options

Run `python kcn-lcn-stratum-proxy.py --help` to see all available options:

- `--ip`: IP address to bind proxy server on (default: 127.0.0.1)
- `--port`: Stratum port (default: 54321)
- `--rpcip/--rpcport`: Kylacoin RPC connection
- `--aux-rpcip/--aux-rpcport`: Lyncoin RPC connection
- `--proxy-signature`: Custom coinbase signature
- `--use-easier-target`: Enable easier target selection
- `--testnet`: Use testnet mode
- `--verbose`: Enable debug logging
- `--jobs`: Show job updates

### Docker Compose Usage

For a complete containerized setup:

#### Start All Services

```bash
docker compose up -d
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f stratum-proxy
docker compose logs -f kylacoin
docker compose logs -f lyncoin
```

### Stop Services

```bash
docker compose down
```

### Update Configuration

```bash
# Edit environment
nano .env

# Restart services
docker compose down && docker compose up -d
```

### Choosing Between Native Python vs Docker

| Aspect               | Native Python                        | Docker Compose                    |
| -------------------- | ------------------------------------ | --------------------------------- |
| **Setup Complexity** | Medium - requires manual node setup  | Easy - everything automated       |
| **Resource Usage**   | Lower - no container overhead        | Higher - container isolation      |
| **Development**      | Easier debugging and development     | More isolated but harder to debug |
| **Dependencies**     | Manual Python dependency management  | Fully contained environment       |
| **Node Management**  | Manual - you manage nodes separately | Automatic - nodes included        |
| **Platform**         | Any OS with Python support           | Any OS with Docker support        |
| **Customization**    | Full control over all components     | Limited to configuration files    |
| **Production**       | Requires more system administration  | Better for deployment and scaling |

**Choose Native Python if:**

- You're developing or debugging the proxy
- You already have Kylacoin/Lyncoin nodes running
- You want minimal resource usage
- You need fine-grained control

**Choose Docker Compose if:**

- You want a complete, easy setup
- You're deploying to production
- You prefer isolated environments
- You don't want to manage nodes manually

### Mining

Connect your miner to the stratum proxy:

- **Host**: Your server IP
- **Port**: 54321 (or your configured STRATUM_PORT)
- **Username**: Your Kylacoin address (e.g., `KYourKylacoinAddress.worker1`)
- **Password**: Any value

The first address that connects becomes the payout address for Kylacoin rewards. If `LCN_WALLET_ADDRESS` is configured, Lyncoin rewards go to that address. If `LCN_WALLET_ADDRESS` is blank, only Kylacoin will be mined (primary-only mode).

#### Sample Miner Commands

**SRBMiner-MULTI (Recommended for Flex algorithm):**

```bash
# For localhost testing
SRBMiner-MULTI.exe --algorithm flex --pool localhost:54321 --wallet kc1qcyahs89p6lmjtecdnf7lxv9sv2aa9z9s8yrcs9

# For remote server
SRBMiner-MULTI.exe --algorithm flex --pool 192.168.1.100:54321 --wallet kc1qcyahs89p6lmjtecdnf7lxv9sv2aa9z9s8yrcs9.worker1
```

**HiveOS Configuration:**

```bash
# Miner: SRBMiner-MULTI
# Algorithm: flex
# Pool: stratum+tcp://YOUR_SERVER_IP:54321
# Wallet: kc1qcyahs89p6lmjtecdnf7lxv9sv2aa9z9s8yrcs9.%WORKER_NAME%
# Password: x
```

**Note**: Replace `kc1qcyahs89p6lmjtecdnf7lxv9sv2aa9z9s8yrcs9` with your actual Kylacoin address.

### Configuration Files

The Docker containers automatically generate configuration files (`kylacoin.conf` and `lyncoin.conf`) from your `.env` file settings. This ensures that CLI tools work properly and all settings are consistent.

**Generated configuration includes:**

- RPC credentials and port settings
- Network and connection parameters
- Optimized settings for proxy operation

### RPC Command Line Access

You can interact with the blockchain nodes using RPC commands for monitoring, debugging, and management. Here are examples for both Docker and native setups:

#### Docker Container RPC Commands

**Kylacoin Commands:**

```bash
# Get mining information
docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getmininginfo

# Get blockchain info
docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getblockchaininfo

# Get wallet info
docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getwalletinfo

# Generate new address
docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getnewaddress

# Get network connections
docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getconnectioncount

# Alternative: Switch to kylacoin user first
docker compose exec -it kylacoin /bin/bash
su - kylacoin
kylacoin-cli getmininginfo
```

**Lyncoin Commands:**

```bash
# Get mining information
docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getmininginfo

# Get blockchain info
docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getblockchaininfo

# Get wallet info
docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getwalletinfo

# Generate new address
docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getnewaddress

# Get AuxPoW information
docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getauxblock

# Alternative: Switch to lyncoin user first
docker compose exec -it lyncoin /bin/bash
su - lyncoin
lyncoin-cli getmininginfo
```

#### Native Installation RPC Commands

**Kylacoin Commands:**

```bash
# Using configuration file (recommended)
kylacoin-cli getmininginfo

# Using explicit RPC parameters
kylacoin-cli -rpcuser=kylacoin_user -rpcpassword=kylacoin_password -rpcport=5110 getmininginfo
```

**Lyncoin Commands:**

```bash
# Using configuration file (recommended)
lyncoin-cli getmininginfo

# Using explicit RPC parameters
lyncoin-cli -rpcuser=lyncoin_user -rpcpassword=lyncoin_password -rpcport=5053 getmininginfo
```

#### Useful RPC Commands for Mining

**Monitor Mining Status:**

```bash
# Check if mining is active
getmininginfo

# Get current block height
getblockcount

# Get network hash rate
getnetworkhashps

# Check wallet balance
getbalance

# List recent transactions
listtransactions
```

**Debug Network Issues:**

```bash
# Check peer connections
getconnectioncount
getpeerinfo

# Check sync status
getblockchaininfo

# Verify daemon is responsive
uptime
```

**AuxPoW Specific (Lyncoin):**

```bash
# Get auxiliary block for mining
getauxblock

# Submit auxiliary proof of work
getauxblock <hash> <auxpow>
```

#### Troubleshooting RPC Access

If you encounter RPC authentication errors:

1. **Verify credentials match your `.env` file**
2. **For Docker**: Use the `-datadir` parameter or switch to the correct user
3. **For native**: Ensure the configuration file exists in the expected location
4. **Check the daemon is running**: Look for the process in `docker compose ps` or system processes

### Wallet Setup

**Important**: Before generating addresses, you must first create and load wallets for both nodes.

1. **Create Kylacoin Wallet**:

   ```bash
   # Create a new wallet named "default"
   docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" createwallet "default"

   # Load the wallet and set it to load on startup
   docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" loadwallet "default" true
   ```

2. **Create Lyncoin Wallet** (optional, for dual-chain mining):

   ```bash
   # Create a new wallet named "default"
   docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" createwallet "default"

   # Load the wallet and set it to load on startup
   docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" loadwallet "default" true
   ```

3. **Generate Kylacoin Address**:

   ```bash
   docker compose exec -it kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getnewaddress
   ```

4. **Generate Lyncoin Address** (optional, for dual-chain mining):

   ```bash
   docker compose exec -it lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getnewaddress
   ```

5. **Update .env file** with your addresses (optional - leave `LCN_WALLET_ADDRESS` blank for Kylacoin-only mining)

### CLI Testing

Test that CLI tools are working correctly:

```bash
# Linux/macOS
./test-cli.sh

# Windows
test-cli.bat

# Or manually test individual commands
docker compose exec kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getblockchaininfo
docker compose exec lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getblockchaininfo
```

### Monitoring

Check blockchain sync status:

```bash
# Kylacoin
docker compose exec kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getblockchaininfo

# Lyncoin
docker compose exec lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getblockchaininfo
```

Check mining info:

```bash
# Kylacoin
docker compose exec kylacoin kylacoin-cli -datadir="/home/kylacoin/.kylacoin" getmininginfo

# Lyncoin
docker compose exec lyncoin lyncoin-cli -datadir="/home/lyncoin/.lyncoin" getmininginfo
```

## Troubleshooting

### Services Won't Start

- Check Docker logs: `docker compose logs [service-name]`
- Verify `.env` file configuration
- Ensure ports aren't already in use

### Proxy Connection Issues

- Verify both daemons are synced
- Check RPC connectivity
- Review proxy logs for errors

### Mining Issues

- Ensure miner is pointing to correct host:port
- Verify wallet address format
- Check proxy logs for submission details

## Security Notes

- Change default RPC passwords in `.env`
- Consider using firewall rules for RPC ports
- Keep wallet backups secure
- Monitor for unauthorized access

## File Structure

```
kylacoin-stratum-proxy/
├── docker-compose.yml       # Main compose file
├── .env.example             # Example environment configuration
├── .gitignore               # Git ignore rules
├── Dockerfile               # Proxy container build
├── Dockerfile.kylacoin      # Kylacoin daemon container
├── Dockerfile.lyncoin       # Lyncoin daemon container
├── entrypoint.sh            # Docker entrypoint script
├── requirements.txt         # Python dependencies
├── setup.sh / setup.bat     # Setup scripts for different platforms
├── health-check.sh          # Health check scripts
├── binaries/                # Cryptocurrency binaries directory
│   ├── kylacoin/           # Kylacoin binaries
│   └── lyncoin/            # Lyncoin binaries
├── config/                  # Configuration templates directory
│   ├── kylacoin.conf       # Kylacoin daemon config template
│   └── lyncoin.conf        # Lyncoin daemon config template
├── kcn_proxy/               # Proxy application package
│   ├── consensus/          # Block/transaction building
│   ├── rpc/                # RPC client implementations
│   ├── state/              # Template state management
│   ├── stratum/            # Stratum protocol server
│   ├── utils/              # Hashing and encoding
│   └── zmq/                # ZMQ block listeners
└── submit_history/          # Block submission logs
```
