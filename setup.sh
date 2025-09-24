#!/bin/bash

# Kylacoin-Lyncoin AuxPoW Proxy Setup Script

set -e

echo "🚀 Setting up Kylacoin-Lyncoin AuxPoW Proxy..."

# Check if Docker and Docker Compose are installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    exit 1
fi

# Function to generate random password
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating .env file..."
    
    # Generate secure passwords
    KCN_PASS=$(generate_password)
    LCN_PASS=$(generate_password)
    
    cat > .env << EOF
# Kylacoin Configuration
KCN_RPC_USER=kylacoin_user
KCN_RPC_PASS=${KCN_PASS}
KCN_RPC_PORT=9766
KCN_P2P_PORT=9765

# Lyncoin Configuration
LCN_RPC_USER=lyncoin_user
LCN_RPC_PASS=${LCN_PASS}
LCN_RPC_PORT=19332
LCN_P2P_PORT=19333

# Wallet Addresses (UPDATE THESE WITH YOUR ACTUAL ADDRESSES)
# Kylacoin address (optional - first miner connection sets this)
# KCN_WALLET_ADDRESS=KYourKylacoinAddressHere
LCN_WALLET_ADDRESS=lc1q44hvy3fg7rka5k9c0waqdu8yw3q4cca6fnxlff

# Stratum Proxy Configuration
STRATUM_PORT=54321
TESTNET=false
VERBOSE=true
SHOW_JOBS=true
EOF

    echo "✅ .env file created with random passwords"
    echo "⚠️  Please update the wallet addresses in .env file"
else
    echo "✅ .env file already exists"
fi

# Update config files with passwords from .env
source .env

# Update kylacoin.conf
sed -i "s/rpcuser=.*/rpcuser=${KCN_RPC_USER}/" kylacoin.conf
sed -i "s/rpcpassword=.*/rpcpassword=${KCN_RPC_PASS}/" kylacoin.conf

# Update lyncoin.conf
sed -i "s/rpcuser=.*/rpcuser=${LCN_RPC_USER}/" lyncoin.conf
sed -i "s/rpcpassword=.*/rpcpassword=${LCN_RPC_PASS}/" lyncoin.conf

echo "✅ Configuration files updated"

# Create submit_history directory
mkdir -p submit_history

# Check binaries
echo "🔍 Checking binaries..."
./check-binaries.sh

# Build and start services
echo "🔨 Building and starting services..."
docker-compose build --no-cache
docker-compose up -d

echo ""
echo "🎉 Setup complete!"
echo ""
echo "📊 Service Status:"
docker-compose ps

echo ""
echo "📝 Next Steps:"
echo "1. Wait for blockchain sync (check with: docker-compose logs -f kylacoin lyncoin)"
echo "2. Update wallet addresses in .env file"
echo "3. Restart proxy: docker-compose restart stratum-proxy"
echo "4. Connect your miner to localhost:${STRATUM_PORT}"
echo ""
echo "📖 Commands:"
echo "  View logs:     docker-compose logs -f"
echo "  Stop services: docker-compose down"
echo "  Restart:       docker-compose restart"
echo ""
echo "🔧 Monitoring:"
echo "  KCN status:   docker-compose exec kylacoin kylacoin-cli getblockchaininfo"
echo "  LCN status:    docker-compose exec lyncoin lyncoin-cli getblockchaininfo"
echo "  Proxy logs:    docker-compose logs -f stratum-proxy"