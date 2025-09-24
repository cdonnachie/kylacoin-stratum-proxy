#!/bin/bash

# Health check script for kylacoin
# This runs as root but switches to kylacoin user to run the CLI command
# Explicitly specify connection details to ensure we use the right port

if su kylacoin -c "kylacoin-cli -rpcconnect=127.0.0.1 -rpcport=${KCN_RPC_PORT:-5110} getblockchaininfo" > /dev/null 2>&1; then
    exit 0
else
    exit 1
fi