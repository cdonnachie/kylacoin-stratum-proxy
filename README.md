# Kylacoin-Lyncoin AuxPoW Stratum Proxy

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

| Variable             | Description                                        | Default                   |
| -------------------- | -------------------------------------------------- | ------------------------- |
| `KCN_RPC_USER`       | Kylacoin RPC username                              | kylacoin_user             |
| `KCN_RPC_PASS`       | Kylacoin RPC password                              | -                         |
| `KCN_RPC_PORT`       | Kylacoin RPC port                                  | 5110                      |
| `KCN_P2P_PORT`       | Kylacoin P2P port                                  | 5111                      |
| `LCN_RPC_USER`       | Lyncoin RPC username                               | lyncoin_user              |
| `LCN_RPC_PASS`       | Lyncoin RPC password                               | -                         |
| `LCN_RPC_PORT`       | Lyncoin RPC port                                   | 5053                      |
| `LCN_P2P_PORT`       | Lyncoin P2P port                                   | 5054                      |
| `LCN_WALLET_ADDRESS` | Lyncoin wallet address (blank = primary-only mode) | (blank - disables AuxPoW) |
| `STRATUM_PORT`       | Stratum proxy port                                 | 54321                     |
| `PROXY_SIGNATURE`    | Custom coinbase signature                          | /kcn-lcn-stratum-proxy/   |
| `USE_EASIER_TARGET`  | Enable easier target selection                     | true                      |
| `TESTNET`            | Use testnet                                        | false                     |
| `VERBOSE`            | Enable verbose logging                             | true                      |
| `SHOW_JOBS`          | Show job updates in logs                           | true                      |

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
├── .env                     # Environment variables
├── .env.example             # Example environment configuration
├── .gitignore               # Git ignore rules
├── Dockerfile               # Proxy container build
├── Dockerfile.kylacoin      # Kylacoin daemon container
├── Dockerfile.lyncoin       # Lyncoin daemon container
├── kylacoin.conf            # Kylacoin daemon config
├── lyncoin.conf             # Lyncoin daemon config
├── kcn-lcn-stratum-proxy.py # Proxy application
├── entrypoint.sh            # Docker entrypoint script
├── requirements.txt         # Python dependencies
├── setup.sh / setup.bat     # Setup scripts for different platforms
├── health-check.sh          # Health check scripts
├── binaries/                # Cryptocurrency binaries directory
│   ├── kylacoin/           # Kylacoin binaries
│   └── lyncoin/            # Lyncoin binaries
└── submit_history/          # Block submission logs
```
