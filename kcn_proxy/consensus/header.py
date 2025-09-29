def build_header80_le(
    version: int,
    prevhash_le: bytes,
    merkleroot_le: bytes,
    ntime_le: bytes,
    bits_le: bytes,
    nonce_le: bytes,
) -> bytes:
    return (
        version.to_bytes(4, "little")
        + prevhash_le
        + merkleroot_le
        + ntime_le
        + bits_le
        + nonce_le
    )
