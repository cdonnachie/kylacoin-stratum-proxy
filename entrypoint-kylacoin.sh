#!/bin/bash
set -e

# Ensure the data directory exists and has correct permissions
mkdir -p /home/kylacoin/.kylacoin
chown -R kylacoin:kylacoin /home/kylacoin/.kylacoin

# Create kylacoin.conf from environment variables
cat > /home/kylacoin/.kylacoin/kylacoin.conf << EOF
# Generated from environment variables
rpcuser=${KCN_RPC_USER}
rpcpassword=${KCN_RPC_PASS}
rpcport=${KCN_RPC_PORT:-5110}
rpcallowip=0.0.0.0/0
rpcbind=0.0.0.0:${KCN_RPC_PORT:-5110}
server=1
listen=1
daemon=0
printtoconsole=1
bind=0.0.0.0:${KCN_P2P_PORT:-5111}

# P2P port
port=${KCN_P2P_PORT:-5111}

# Additional settings for better operation
maxconnections=50
timeout=30000
EOF

# Fix ownership of the config file
chown kylacoin:kylacoin /home/kylacoin/.kylacoin/kylacoin.conf

echo "Generated kylacoin.conf with RPC settings"

# Switch to kylacoin user and start kylacoind with the configuration file
exec su kylacoin -c "kylacoind $*"