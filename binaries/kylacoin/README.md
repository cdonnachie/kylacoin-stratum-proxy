# Kylacoin Binaries

Place your Kylacoin daemon and CLI binaries in this directory.

## Required Files:

- `kylacoind` - The Kylacoin daemon executable (**Linux x86_64 ELF binary**)
- `kylacoin-cli` - The Kylacoin CLI client (**Linux x86_64 ELF binary**)

⚠️ **Important**: Only Linux binaries work with Docker containers! Do NOT use Windows .exe or macOS binaries.

## Where to get them:

1. Download from the official Kylacoin releases
2. Build from source code
3. Extract from existing installation

## File permissions:

The Docker build process will automatically set execute permissions on these files.

## Verification:

Check if you have the correct binary format:

```bash
file kylacoind
file kylacoin-cli
```

**Expected output:**

```
kylacoind: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0
kylacoin-cli: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0
```

❌ **Wrong formats (will NOT work):**

- Windows: `PE32+ executable (console) x86-64, for MS Windows`
- macOS: `Mach-O 64-bit executable x86_64`

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
