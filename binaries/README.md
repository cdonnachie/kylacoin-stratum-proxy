# Cryptocurrency Binaries Directory

This directory contains the local binaries for both Kylacoin and Lyncoin that will be used in the Docker containers.

## Directory Structure:

```
binaries/
├── kylacoin/
│   ├── kylacoind      # Kylacoin daemon
│   ├── kylacoin-cli   # Kylacoin CLI
│   └── README.md
├── lyncoin/
│   ├── lyncoind       # Lyncoin daemon
│   ├── lyncoin-cli    # Lyncoin CLI
│   └── README.md
└── README.md          # This file
```

## Setup Instructions:

1. **Copy Kylacoin binaries** into `kylacoin/` directory:

   - `kylacoind`
   - `kylacoin-cli`

2. **Copy Lyncoin binaries** into `lyncoin/` directory:

   - `lyncoind`
   - `lyncoin-cli`

3. **Build the Docker images**:

   ```bash
   docker compose build kylacoin lyncoin
   ```

4. **Start the services**:
   ```bash
   docker compose up -d
   ```

## Binary Requirements:

### Kylacoin:

- Compatible with Ubuntu 24.04 Linux (glibc 2.39+)
- Statically linked or with required dependencies
- Executable permissions (will be set automatically)

### Lyncoin:

- Compatible with Ubuntu 24.04 Linux (glibc 2.39+)
- AuxPoW support enabled
- Executable permissions (will be set automatically)

## Troubleshooting:

### Missing binaries:

```bash
# Check if files exist
ls -la binaries/kylacoin/
ls -la binaries/lyncoin/

# Build specific service
docker compose build kylacoin
docker compose build lyncoin
```

### Permission issues:

The Dockerfile automatically sets execute permissions, but if you're having issues:

```bash
chmod +x binaries/kylacoin/*
chmod +x binaries/lyncoin/*
```

### Architecture mismatch:

Ensure your binaries are compiled for Linux x86_64:

```bash
file binaries/kylacoin/kylacoind
file binaries/lyncoin/lyncoind
```

Should show: `ELF 64-bit LSB executable, x86-64`
