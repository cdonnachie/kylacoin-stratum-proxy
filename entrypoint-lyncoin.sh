#!/bin/bash
set -e

# Ensure the data directory exists and has correct permissions
mkdir -p /home/lyncoin/.lyncoin
chown -R lyncoin:lyncoin /home/lyncoin/.lyncoin

# Create lyncoin.conf from environment variables
cat > /home/lyncoin/.lyncoin/lyncoin.conf << EOF
# Generated from environment variables
rpcuser=${LCN_RPC_USER}
rpcpassword=${LCN_RPC_PASS}
rpcport=${LCN_RPC_PORT:-5053}
rpcallowip=0.0.0.0/0
rpcbind=0.0.0.0:${LCN_RPC_PORT:-5053}
server=1
listen=1
daemon=0
printtoconsole=1

# P2P port
port=${LCN_P2P_PORT:-5054}

# ZMQ Configuration for block notifications
zmqpubhashblock=tcp://0.0.0.0:${LCN_ZMQ_PORT:-28433}
zmqpubrawblock=tcp://0.0.0.0:${LCN_ZMQ_RAW_PORT:-28434}

# Additional settings for better operation
maxconnections=50
timeout=30000
EOF

# Fix ownership of the config file
chown lyncoin:lyncoin /home/lyncoin/.lyncoin/lyncoin.conf

echo "Generated lyncoin.conf with RPC settings"

# Switch to lyncoin user and start lyncoind with the configuration file
exec su lyncoin -c "lyncoind $*"