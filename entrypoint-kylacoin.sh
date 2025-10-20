#!/bin/bash
set -e

# Ensure file descriptors are clean: close FDs 3+ if they exist, send stdout to FD 1, stderr to FD 2
exec 2>&2

# Bootstrap configuration
ENABLE_BOOTSTRAP=${ENABLE_BOOTSTRAP:-true}
BOOTSTRAP_MAX_AGE_DAYS=${BOOTSTRAP_MAX_AGE_DAYS:-7}
BOOTSTRAP_FORCE=${BOOTSTRAP_FORCE:-false}
BOOTSTRAP_VERIFY_CHECKSUM=${BOOTSTRAP_VERIFY_CHECKSUM:-true}
BOOTSTRAP_BASE_URL="https://downloads.kylacoin.com/blockchain-snapshots"
DATA_DIR="/home/kylacoin/.kylacoin"

# Function to log with timestamp (explicitly to stderr)
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] KCN Bootstrap: $1" >&2
}

# Function to check if bootstrap is needed
needs_bootstrap() {
    # If bootstrap disabled, skip
    if [ "$ENABLE_BOOTSTRAP" != "true" ]; then
        log "Bootstrap disabled via ENABLE_BOOTSTRAP=false"
        return 1
    fi
    
    # If force enabled, always bootstrap
    if [ "$BOOTSTRAP_FORCE" = "true" ]; then
        log "Bootstrap forced via BOOTSTRAP_FORCE=true"
        return 0
    fi
    
    # Check if blockchain data exists
    if [ ! -d "$DATA_DIR/blocks" ] || [ ! -d "$DATA_DIR/chainstate" ]; then
        log "No existing blockchain data found"
        return 0
    fi
    
    # Check age of existing data
    local blocks_dir="$DATA_DIR/blocks"
    if [ -d "$blocks_dir" ]; then
        local last_modified=$(stat -c %Y "$blocks_dir" 2>/dev/null || echo 0)
        local current_time=$(date +%s)
        local age_days=$(( (current_time - last_modified) / 86400 ))
        
        if [ $age_days -gt $BOOTSTRAP_MAX_AGE_DAYS ]; then
            log "Blockchain data is $    days old (max: $BOOTSTRAP_MAX_AGE_DAYS)"
            return 0
        else
            log "Blockchain data is recent ($age_days days old), skipping bootstrap"
            return 1
        fi
    fi
    
    return 0
}

# Function to detect latest bootstrap file
get_latest_bootstrap() {
    log "Detecting latest bootstrap file..."
    
    # Try to fetch the directory listing and extract the latest file
    # Redirect log output to stderr to keep stdout clean for filename capture
    local latest_file=$(curl -s --max-time 30 "$BOOTSTRAP_BASE_URL/" 2>&1 | \
                       grep -oE 'kylacoin-[0-9]{4}-[0-9]{2}-[0-9]{2}\.tar\.gz' | \
                       sort -V | tail -1 | tr -d '\n' | tr -d '\r' | xargs)
    
    if [ -z "$latest_file" ]; then
        # Fallback: try common recent date patterns
        local today=$(date +'%Y-%m-%d')
        local yesterday=$(date -d 'yesterday' +'%Y-%m-%d' 2>/dev/null || date -v-1d +'%Y-%m-%d' 2>/dev/null)
        local two_days_ago=$(date -d '2 days ago' +'%Y-%m-%d' 2>/dev/null || date -v-2d +'%Y-%m-%d' 2>/dev/null)
        
        for date in "$today" "$yesterday" "$two_days_ago"; do
            local candidate="kylacoin-${date}.tar.gz"
            if curl -s --head "$BOOTSTRAP_BASE_URL/$candidate" 2>/dev/null | head -1 | grep -q "200\|OK"; then
                latest_file="$candidate"
                break
            fi
        done
    fi
    
    if [ -z "$latest_file" ]; then
        log "ERROR: Could not detect latest bootstrap file"
        return 1
    fi
    
    log "Latest bootstrap file: $latest_file"
    echo "$latest_file"
}

# Function to download and verify bootstrap
download_bootstrap() {
    local filename="$1"
    local temp_dir="/tmp/kcn_bootstrap_$$"
    
    # Sanitize filename: remove any control characters, newlines, etc.
    filename=$(echo "$filename" | tr -d '\n' | tr -d '\r' | xargs)
    
    if [ -z "$filename" ]; then
        log "ERROR: Invalid filename provided"
        return 1
    fi
    
    log "Creating temporary directory: $temp_dir"
    mkdir -p "$temp_dir"
    
    # Download bootstrap file - suppress all other output during download
    log "Downloading bootstrap: $filename (~1.5GB, this may take a while...)"
    local download_url="${BOOTSTRAP_BASE_URL}/${filename}"
    # Explicitly redirect curl stderr to /dev/null to prevent mixing with output
    if ! curl -L --progress-bar --max-time 1800 "$download_url" -o "$temp_dir/$filename" 2>/dev/null; then
        log "ERROR: Failed to download bootstrap file from $download_url"
        rm -rf "$temp_dir"
        return 1
    fi
    
    # Verify file exists and has reasonable size
    if [ ! -f "$temp_dir/$filename" ]; then
        log "ERROR: Downloaded file does not exist at $temp_dir/$filename"
        rm -rf "$temp_dir"
        return 1
    fi
    
    local filesize=$(stat -c%s "$temp_dir/$filename" 2>/dev/null || echo "unknown")
    log "Download complete: $filename ($filesize bytes)"
    
    # Download and verify checksum if enabled
    if [ "$BOOTSTRAP_VERIFY_CHECKSUM" = "true" ]; then
        local checksum_file="${filename%.*.*}-checksum.txt"
        log "Downloading checksum: $checksum_file"
        
        local checksum_url="${BOOTSTRAP_BASE_URL}/${checksum_file}"
        if curl -L --max-time 60 "$checksum_url" -o "$temp_dir/checksum.txt" 2>/dev/null; then
            log "Verifying file integrity..."
            # Extract sha256 hash: format is "sha256 <hash>"
            # Use explicit variable assignment without piping to avoid truncation
            local sha256_line=$(grep "^sha256 " "$temp_dir/checksum.txt")
            local sha256_hash="${sha256_line#sha256 }"
            # Strip all whitespace including newlines and carriage returns
            sha256_hash=$(echo "$sha256_hash" | tr -d '\n\r\t ' | head -c 64)
            
            log "Extracted hash: '$sha256_hash' (length: ${#sha256_hash})"
            
            if [ ${#sha256_hash} -ne 64 ]; then
                log "WARNING: Hash length is ${#sha256_hash}, expected 64"
            fi
            
            if [ -z "$sha256_hash" ]; then
                log "WARNING: Could not extract sha256 hash from checksum file"
                log "Checksum file content:"
                cat "$temp_dir/checksum.txt" >&2
            else
                # Create proper sha256sum format: hash  filename (two spaces)
                # Use printf to be explicit
                printf '%s  %s\n' "$sha256_hash" "$filename" > "$temp_dir/checksum_verify.txt"
                
                if (cd "$temp_dir" && sha256sum -c checksum_verify.txt >/dev/null 2>&1); then
                    log "✓ Checksum verification successful"
                else
                    log "WARNING: Checksum verification failed (continuing anyway)."
                fi
            fi
        else
            log "WARNING: Could not download checksum file, skipping verification"
        fi
    fi
    
    echo "$temp_dir/$filename"
}

# Function to extract bootstrap
extract_bootstrap() {
    local bootstrap_file="$1"
    local temp_dir=$(dirname "$bootstrap_file")
    local backup_dir="/tmp/kcn_backup_$$"
    
    # Backup existing data if it exists
    if [ -d "$DATA_DIR/blocks" ] || [ -d "$DATA_DIR/chainstate" ]; then
        log "Backing up existing blockchain data..."
        mkdir -p "$backup_dir"
        [ -d "$DATA_DIR/blocks" ] && mv "$DATA_DIR/blocks" "$backup_dir/" 2>/dev/null || true
        [ -d "$DATA_DIR/chainstate" ] && mv "$DATA_DIR/chainstate" "$backup_dir/" 2>/dev/null || true
        [ -d "$DATA_DIR/indexes" ] && mv "$DATA_DIR/indexes" "$backup_dir/" 2>/dev/null || true
    fi
    
    # Extract bootstrap
    log "Extracting bootstrap to $DATA_DIR..."
    local tar_output
    tar_output=$(tar -xzf "$bootstrap_file" -C "$DATA_DIR" 2>&1)
    if [ $? -ne 0 ]; then
        log "ERROR: Failed to extract bootstrap"
        log "Extract error: $tar_output"
        # Restore backup if extraction failed
        if [ -d "$backup_dir" ]; then
            log "Restoring backup..."
            [ -d "$backup_dir/blocks" ] && mv "$backup_dir/blocks" "$DATA_DIR/" 2>/dev/null || true
            [ -d "$backup_dir/chainstate" ] && mv "$backup_dir/chainstate" "$DATA_DIR/" 2>/dev/null || true
            [ -d "$backup_dir/indexes" ] && mv "$backup_dir/indexes" "$DATA_DIR/" 2>/dev/null || true
        fi
        rm -rf "$temp_dir" "$backup_dir"
        return 1
    fi
    
    # Fix ownership
    chown -R kylacoin:kylacoin "$DATA_DIR"
    
    # Cleanup
    log "Cleaning up temporary files..."
    rm -rf "$temp_dir" "$backup_dir"
    
    log "✓ Bootstrap extraction completed successfully"
    return 0
}

# Function to run bootstrap process
run_bootstrap() {
    if ! needs_bootstrap; then
        return 0
    fi
    
    log "Starting bootstrap process..."
    
    local latest_file
    if ! latest_file=$(get_latest_bootstrap); then
        log "ERROR: Could not determine latest bootstrap file"
        return 1
    fi
    
    local bootstrap_path
    if ! bootstrap_path=$(download_bootstrap "$latest_file"); then
        log "ERROR: Failed to download bootstrap"
        return 1
    fi
    
    if ! extract_bootstrap "$bootstrap_path"; then
        log "ERROR: Failed to extract bootstrap"
        return 1
    fi
    
    log "Bootstrap process completed successfully!"
    return 0
}

# Ensure the data directory exists and has correct permissions
mkdir -p /home/kylacoin/.kylacoin
chown -R kylacoin:kylacoin /home/kylacoin/.kylacoin

# Run bootstrap if needed
if ! run_bootstrap; then
    log "Bootstrap failed, but continuing with normal startup..."
fi

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

# ZMQ Configuration for block notifications
zmqpubhashblock=tcp://0.0.0.0:${KCN_ZMQ_PORT:-29332}
zmqpubrawblock=tcp://0.0.0.0:${KCN_ZMQ_RAW_PORT:-29333}

# Additional settings for better operation
maxconnections=50
timeout=30000
EOF

# Fix ownership of the config file
chown kylacoin:kylacoin /home/kylacoin/.kylacoin/kylacoin.conf

echo "Generated kylacoin.conf with RPC settings"

# Switch to kylacoin user and start kylacoind with the configuration file
exec su kylacoin -c "kylacoind $*"