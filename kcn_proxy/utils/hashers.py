import hashlib
from hashlib import sha256
import flexhash


def dsha256(b: bytes) -> bytes:
    return sha256(sha256(b).digest()).digest()


def sha3d(b: bytes) -> bytes:
    return hashlib.sha3_256(hashlib.sha3_256(b).digest()).digest()


def flex_pow(header80: bytes) -> bytes:
    h = flexhash.hash(header80)
    if not isinstance(h, (bytes, bytearray)) or len(h) != 32:
        raise ValueError("flexhash returned invalid digest")
    return bytes(h)
