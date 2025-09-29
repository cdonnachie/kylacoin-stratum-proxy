#!/bin/bash

# Docker entrypoint script for stratum proxy
# Handles conditional argument passing based on environment variables

ARGS=(
    "python" "-m" "kcn_proxy.main"
    "--ip=0.0.0.0"
    "--port=${STRATUM_PORT:-54321}"
    "--rpcip=kylacoin"
    "--rpcport=${KCN_RPC_PORT:-5110}"
    "--rpcuser=${KCN_RPC_USER}"
    "--rpcpass=${KCN_RPC_PASS}"
    "--aux-rpcip=lyncoin"
    "--aux-rpcport=${LCN_RPC_PORT:-19332}"
    "--aux-rpcuser=${LCN_RPC_USER}"
    "--aux-rpcpass=${LCN_RPC_PASS}"
    "--aux-address=${LCN_WALLET_ADDRESS}"
)

# Add conditional arguments
if [ -n "${PROXY_SIGNATURE}" ]; then
    ARGS+=("--proxy-signature=${PROXY_SIGNATURE}")
fi

# Add conditional flags only if they are explicitly set to "true"
if [ "${TESTNET,,}" = "true" ]; then
    ARGS+=("--testnet")
fi

if [ "${VERBOSE,,}" = "true" ]; then
    ARGS+=("--verbose")
fi

if [ "${SHOW_JOBS,,}" = "true" ]; then
    ARGS+=("--jobs")
fi

if [ "${USE_EASIER_TARGET,,}" = "true" ]; then
    ARGS+=("--use-easier-target")
fi

if [ "${DEBUG_SHARES,,}" = "true" ]; then
    ARGS+=("--debug-shares")
fi

echo "Starting with arguments: ${ARGS[@]}"
exec "${ARGS[@]}"