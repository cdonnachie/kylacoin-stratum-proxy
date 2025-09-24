#!/bin/bash

echo "Testing CLI connectivity to blockchain nodes..."
echo

echo "Testing Kylacoin CLI connection..."
docker compose exec kylacoin kylacoin-cli getblockchaininfo | head -5
echo

echo "Testing Lyncoin CLI connection..."  
docker compose exec lyncoin lyncoin-cli getblockchaininfo | head -5
echo

echo "Testing wallet generation..."
echo "Kylacoin new address:"
docker compose exec kylacoin kylacoin-cli getnewaddress
echo

echo "Lyncoin new address:"
docker compose exec lyncoin lyncoin-cli getnewaddress
echo

echo "CLI tests complete!"