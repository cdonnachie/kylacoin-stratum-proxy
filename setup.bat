@echo off
REM Kylacoin-Lyncoin AuxPoW Proxy Setup Script for Windows

echo [*] Setting up Kylacoin-Lyncoin AuxPoW Proxy...

REM Check if Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker is not installed. Please install Docker Desktop first.
    pause
    exit /b 1
)

REM Check if Docker Compose is available
docker-compose --version >nul 2>&1
if errorlevel 1 (
    docker compose version >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Docker Compose is not available. Please install Docker Compose.
        pause
        exit /b 1
    )
)

REM Create .env file if it doesn't exist
if not exist .env (
    echo [*] Creating .env file...
    
    REM Generate random passwords (simplified for Windows)
    set KCN_PASS=kcn_%RANDOM%_%RANDOM%
    set LCN_PASS=lcn_%RANDOM%_%RANDOM%
    
    (
        echo # Kylacoin Configuration
        echo KCN_RPC_USER=kylacoin_user
        echo KCN_RPC_PASS=%KCN_PASS%
        echo KCN_RPC_PORT=9766
        echo KCN_P2P_PORT=9765
        echo.
        echo # Lyncoin Configuration
        echo LCN_RPC_USER=lyncoin_user
        echo LCN_RPC_PASS=%LCN_PASS%
        echo LCN_RPC_PORT=19332
        echo LCN_P2P_PORT=19333
        echo.
        echo # Wallet Addresses ^(UPDATE THESE WITH YOUR ACTUAL ADDRESSES^)
        echo # Kylacoin address ^(optional - first miner connection sets this^)
        echo # KCN_WALLET_ADDRESS=KYourKylacoinAddressHere
        echo LCN_WALLET_ADDRESS=lc1qc5ynszqthxghtq78vc8qn5reh7l0u9rymef953
        echo.
        echo # Stratum Proxy Configuration
        echo STRATUM_PORT=54321
        echo TESTNET=false
        echo VERBOSE=true
        echo SHOW_JOBS=true
    ) > .env
    
    echo [OK] .env file created with random passwords
    echo [NOTICE] Please update the wallet addresses in .env file
) else (
    echo [OK] .env file already exists
)

REM Create submit_history directory
if not exist submit_history mkdir submit_history

REM Check binaries
echo [*] Checking binaries...
call check-binaries.bat

REM Build and start services
echo [*] Building and starting services...
docker compose build --no-cache
docker compose up -d

echo.
echo [SUCCESS] Setup complete!
echo.
echo [*] Service Status:
docker compose ps

echo.
echo [*] Next Steps:
echo 1. Wait for blockchain sync (check with: docker compose logs -f kylacoin lyncoin)
echo 2. Update wallet addresses in .env file
echo 3. Restart proxy: docker compose restart stratum-proxy
echo 4. Connect your miner to localhost:54321
echo.
echo [*] Commands:
echo   View logs:     docker compose logs -f
echo   Stop services: docker compose down
echo   Restart:       docker compose restart
echo.
echo [*] Monitoring:
echo   KCN status:   docker compose exec kylacoin kylacoin-cli getblockchaininfo
echo   LCN status:   docker compose exec lyncoin lyncoin-cli getblockchaininfo
echo   Proxy logs:   docker compose logs -f stratum-proxy

pause