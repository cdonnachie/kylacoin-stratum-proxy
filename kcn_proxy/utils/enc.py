from typing import Optional


def var_int(i: int) -> bytes:
    if i < 0:
        raise ValueError(f"var_int requires non-negative integer, got {i}")
    if i < 0xFD:
        return i.to_bytes(1, "little")
    if i <= 0xFFFF:
        return b"\xfd" + i.to_bytes(2, "little")
    if i <= 0xFFFFFFFF:
        return b"\xfe" + i.to_bytes(4, "little")
    return b"\xff" + i.to_bytes(8, "little")


def op_push(i: int) -> bytes:
    if i < 0x4C:
        return i.to_bytes(1, "little")
    elif i <= 0xFF:
        return b"\x4c" + i.to_bytes(1, "little")
    elif i <= 0xFFFF:
        return b"\x4d" + i.to_bytes(2, "little")
    else:
        return b"\x4e" + i.to_bytes(4, "little")


def bech32_decode(bech: str):
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    if not bech:
        return (None, None)
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    hrp = bech[:pos]
    data = bech[pos + 1 :]
    decoded = []
    for ch in data:
        if ch not in CHARSET:
            return (None, None)
        decoded.append(CHARSET.find(ch))
    if len(decoded) < 6:
        return (None, None)
    witver = decoded[0]
    if witver > 16:
        return (None, None)
    converted = []
    acc = 0
    bits = 0
    for v in decoded[1:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            converted.append((acc >> bits) & 255)
    if bits >= 5 or ((acc << (5 - bits)) & 31):
        return (None, None)
    return (hrp, bytes(converted))


def bech32_encode(hrp: str, data: bytes) -> str:
    """Encode bytes to bech32 address"""
    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

    def bech32_polymod(values):
        GEN = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
        chk = 1
        for value in values:
            top = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ value
            for i in range(5):
                chk ^= GEN[i] if ((top >> i) & 1) else 0
        return chk

    def bech32_hrp_expand(hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    def bech32_create_checksum(hrp, data):
        values = bech32_hrp_expand(hrp) + data
        polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    # Convert data to 5-bit values
    spec = [0]  # witness version 0
    acc = 0
    bits = 0
    for value in data:
        acc = (acc << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            spec.append((acc >> bits) & 31)

    if bits:
        spec.append((acc << (5 - bits)) & 31)

    # Create checksum
    checksum = bech32_create_checksum(hrp, spec)

    # Combine and encode
    combined = spec + checksum
    return hrp + "1" + "".join([CHARSET[d] for d in combined])
