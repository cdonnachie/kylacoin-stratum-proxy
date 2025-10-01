#!/bin/bash

# Health check script for the mining setup

set -e

echo "🔍 Checking Kylacoin-Lyncoin AuxPoW Proxy Health..."
echo "================================================="

# Function to check service status
check_service() {
    local service=$1
    local status=$(docker-compose ps -q $service 2>/dev/null)
    
    if [ -z "$status" ]; then
        echo "❌ $service: Not running"
        return 1
    else
        local health=$(docker inspect --format='{{.State.Health.Status}}' $(docker-compose ps -q $service) 2>/dev/null || echo "no-health-check")
        if [ "$health" = "healthy" ]; then
            echo "✅ $service: Running and healthy"
        elif [ "$health" = "unhealthy" ]; then
            echo "⚠️  $service: Running but unhealthy"
        else
            echo "🟡 $service: Running (no health check)"
        fi
    fi
}

# Check Docker Compose services
echo "📋 Service Status:"
check_service "kylacoin"
check_service "lyncoin" 
check_service "stratum-proxy"

echo ""
echo "🔗 Network Connectivity:"

# Check if services can communicate
if docker-compose exec -T stratum-proxy python -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('kylacoin', 5110)); s.close(); print('✅ Proxy -> Kylacoin RPC: OK')" 2>/dev/null; then
    :
else
    echo "❌ Proxy -> Kylacoin RPC: Failed"
fi

if docker-compose exec -T stratum-proxy python -c "import socket; s=socket.socket(); s.settimeout(5); s.connect(('lyncoin', 5053); s.close(); print('✅ Proxy -> Lyncoin RPC: OK')" 2>/dev/null; then
    :
else
    echo "❌ Proxy -> Lyncoin RPC: Failed"
fi

echo ""
echo "⛓️  Blockchain Status:"

# Check Kylacoin sync status
KCN_INFO=$(docker-compose exec -T kylacoin kylacoin-cli getblockchaininfo 2>/dev/null || echo "error")
if [ "$KCN_INFO" != "error" ]; then
    KCN_BLOCKS=$(echo "$KCN_INFO" | grep -o '"blocks":[0-9]*' | cut -d: -f2)
    KCN_HEADERS=$(echo "$KCN_INFO" | grep -o '"headers":[0-9]*' | cut -d: -f2)
    if [ "$KCN_BLOCKS" = "$KCN_HEADERS" ]; then
        echo "✅ Kylacoin: Synced ($KCN_BLOCKS blocks)"
    else
        echo "🔄 Kylacoin: Syncing ($KCN_BLOCKS/$KCN_HEADERS blocks)"
    fi
else
    echo "❌ Kylacoin: RPC Error"
fi

# Check Lyncoin sync status  
LCN_INFO=$(docker-compose exec -T lyncoin lyncoin-cli getblockchaininfo 2>/dev/null || echo "error")
if [ "$LCN_INFO" != "error" ]; then
    LCN_BLOCKS=$(echo "$LCN_INFO" | grep -o '"blocks":[0-9]*' | cut -d: -f2)
    LCN_HEADERS=$(echo "$LCN_INFO" | grep -o '"headers":[0-9]*' | cut -d: -f2)
    if [ "$LCN_BLOCKS" = "$LCN_HEADERS" ]; then
        echo "✅ Lyncoin: Synced ($LCN_BLOCKS blocks)"
    else
        echo "🔄 Lyncoin: Syncing ($LCN_BLOCKS/$LCN_HEADERS blocks)"
    fi
else
    echo "❌ Lyncoin: RPC Error"
fi

echo ""
echo "🎯 Stratum Proxy:"

# Check if stratum port is accessible
if nc -z localhost 54321 2>/dev/null; then
    echo "✅ Stratum port 54321: Accessible"
else
    echo "❌ Stratum port 54321: Not accessible"
fi

echo ""
echo "📊 Recent Activity:"
echo "Last 5 proxy log entries:"
docker-compose logs --tail=5 stratum-proxy 2>/dev/null || echo "No recent logs available"

echo ""
echo "💡 Troubleshooting:"
echo "  Full logs:        docker-compose logs -f"
echo "  Restart all:      docker-compose restart" 
echo "  Rebuild proxy:    docker-compose up -d --build stratum-proxy"
echo "  Check config:     cat .env"