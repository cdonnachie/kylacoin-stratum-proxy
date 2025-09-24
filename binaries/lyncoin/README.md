# Lyncoin Binaries

Place your Lyncoin daemon and CLI binaries in this directory.

## Required Files:

- `lyncoind` - The Lyncoin daemon executable
- `lyncoin-cli` - The Lyncoin CLI client

## Where to get them:

1. Download from the official Lyncoin releases
2. Build from source code
3. Extract from existing installation

## File permissions:

The Docker build process will automatically set execute permissions on these files.

## Example:

```
binaries/lyncoin/
├── lyncoind
└── lyncoin-cli
```

After placing the files here, run:

```bash
docker compose build lyncoin
```
