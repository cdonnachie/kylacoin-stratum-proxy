#!/bin/bash

# Health check script for lyncoin
# This runs as root but switches to lyncoin user to run the CLI command
# Explicitly specify connection details to ensure we use the right port

if su lyncoin -c "lyncoin-cli -rpcconnect=127.0.0.1 -rpcport=${LCN_RPC_PORT:-5053} getblockchaininfo" > /dev/null 2>&1; then
    exit 0
else
    exit 1
fi