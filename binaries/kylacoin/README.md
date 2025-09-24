# Kylacoin Binaries

Place your Kylacoin daemon and CLI binaries in this directory.

## Required Files:

- `kylacoind` - The Kylacoin daemon executable
- `kylacoin-cli` - The Kylacoin CLI client

## Where to get them:

1. Download from the official Kylacoin releases
2. Build from source code
3. Extract from existing installation

## File permissions:

The Docker build process will automatically set execute permissions on these files.

## Example:

```
binaries/kylacoin/
├── kylacoind
└── kylacoin-cli
```

After placing the files here, run:

```bash
docker compose build kylacoin
```
