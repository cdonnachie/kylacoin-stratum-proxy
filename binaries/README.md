# Cryptocurrency Binaries Directory

This directory contains the local binaries for both Kylacoin and Lyncoin that will be used in the Docker containers.

⚠️ **CRITICAL**: Only **Linux x86_64 ELF binaries** work with Docker containers! Do NOT use Windows .exe or macOS binaries.

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

1. **Copy Kylacoin binaries** (Linux x86_64 ELF format) into `kylacoin/` directory:

   - `kylacoind`
   - `kylacoin-cli`

2. **Copy Lyncoin binaries** (Linux x86_64 ELF format) into `lyncoin/` directory:

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

**Platform**: Linux x86_64 ELF executables ONLY

### Kylacoin:

- **Format**: Linux x86_64 ELF executable
- **Compatibility**: Ubuntu 24.04 Linux (glibc 2.39+)
- **Dependencies**: Statically linked or with required dependencies included
- **Permissions**: Executable permissions (set automatically by Docker)

### Lyncoin:

- **Format**: Linux x86_64 ELF executable
- **Compatibility**: Ubuntu 24.04 Linux (glibc 2.39+)
- **Features**: AuxPoW support enabled
- **Permissions**: Executable permissions (set automatically by Docker)

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

**Expected output:**

```
binaries/kylacoin/kylacoind: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0
binaries/lyncoin/lyncoind: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0
```

❌ **Wrong formats (will cause container failures):**

- Windows: `PE32+ executable (console) x86-64, for MS Windows`
- macOS: `Mach-O 64-bit executable x86_64`
