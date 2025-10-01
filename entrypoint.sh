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

# ZMQ arguments
if [ "${ENABLE_ZMQ,,}" = "true" ]; then
    ARGS+=("--enable-zmq")
    if [ -n "${KCN_ZMQ_ENDPOINT}" ]; then
        ARGS+=("--kcn-zmq-endpoint=${KCN_ZMQ_ENDPOINT}")
    fi
    if [ -n "${LCN_ZMQ_ENDPOINT}" ]; then
        ARGS+=("--lcn-zmq-endpoint=${LCN_ZMQ_ENDPOINT}")
    fi
elif [ "${ENABLE_ZMQ,,}" = "false" ]; then
    ARGS+=("--disable-zmq")
fi

echo "Starting with arguments: ${ARGS[@]}"
exec "${ARGS[@]}"