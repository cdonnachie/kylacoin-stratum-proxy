from typing import Optional


def var_int(i: int) -> bytes:
    assert i >= 0
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
