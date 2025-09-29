POW_LIMIT = int(
    "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16
)  # kylacoin consensus powLimit
DIFF1_TARGET = int(
    "00000000ffff0000000000000000000000000000000000000000000000000000", 16
)


def bits_to_target(bits_hex: str) -> int:
    bits = int(bits_hex, 16)
    exp = bits >> 24
    mant = bits & 0xFFFFFF
    if exp <= 3:
        target_int = mant >> (8 * (3 - exp))
    else:
        target_int = mant << (8 * (exp - 3))
    return target_int


def normalize_be_hex(h: str) -> str:
    return h.lower().zfill(64)


def target_to_diff_kcn(target_int: int) -> float:
    if target_int == 0:
        return float("inf")
    return DIFF1_TARGET / target_int


def target_to_diff1(target_int: int) -> float:
    if target_int == 0:
        return float("inf")
    return DIFF1_TARGET / target_int
