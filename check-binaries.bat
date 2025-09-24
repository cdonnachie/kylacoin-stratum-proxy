@echo off
REM Binary setup helper script for Kylacoin-Lyncoin AuxPoW Proxy

echo [*] Binary Setup Helper
echo ======================

echo [*] Checking Kylacoin binaries...

if exist "binaries\kylacoin\kylacoind" (
    echo [OK] Kylacoin Daemon: Found
) else (
    echo [!!] Kylacoin Daemon: Missing
    echo     Expected: binaries\kylacoin\kylacoind
)

if exist "binaries\kylacoin\kylacoin-cli" (
    echo [OK] Kylacoin CLI: Found
) else (
    echo [!!] Kylacoin CLI: Missing
    echo     Expected: binaries\kylacoin\kylacoin-cli
)

echo.
echo [*] Checking Lyncoin binaries...

if exist "binaries\lyncoin\lyncoind" (
    echo [OK] Lyncoin Daemon: Found
) else (
    echo [!!] Lyncoin Daemon: Missing
    echo     Expected: binaries\lyncoin\lyncoind
)

if exist "binaries\lyncoin\lyncoin-cli" (
    echo [OK] Lyncoin CLI: Found
) else (
    echo [!!] Lyncoin CLI: Missing
    echo     Expected: binaries\lyncoin\lyncoin-cli
)

echo.
echo [*] Directory structure:
echo binaries\
echo +-- kylacoin\
if exist "binaries\kylacoin" (
    for %%f in (binaries\kylacoin\*) do (
        echo ^|   +-- %%~nxf
    )
) else (
    echo ^|   +-- ^(directory missing^)
)

echo +-- lyncoin\
if exist "binaries\lyncoin" (
    for %%f in (binaries\lyncoin\*) do (
        echo     +-- %%~nxf
    )
) else (
    echo     +-- ^(directory missing^)
)

echo.

REM Count missing binaries
set missing=0
if not exist "binaries\kylacoin\kylacoind" set /a missing+=1
if not exist "binaries\kylacoin\kylacoin-cli" set /a missing+=1
if not exist "binaries\lyncoin\lyncoind" set /a missing+=1
if not exist "binaries\lyncoin\lyncoin-cli" set /a missing+=1

if %missing%==0 (
    echo [SUCCESS] All required binaries are present!
    echo.
    echo [*] Next steps:
    echo 1. Build Docker images: docker compose build
    echo 2. Start services: docker compose up -d
    echo 3. Check logs: docker compose logs -f
) else (
    echo [WARNING] Missing %missing% required binaries
    echo.
    echo [*] To fix:
    echo 1. Copy binaries to the correct directories ^(see README.md^)
    echo 2. Run this script again to verify
    echo 3. Build Docker images: docker compose build
)

echo.
echo [HELP] Documentation:
echo   Binary requirements: See binaries\README.md
echo   Kylacoin setup: See binaries\kylacoin\README.md
echo   Lyncoin setup: See binaries\lyncoin\README.md

pause