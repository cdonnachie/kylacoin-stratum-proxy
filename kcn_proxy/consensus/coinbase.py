from typing import List, Tuple
from ..utils.enc import var_int, op_push
from ..utils.hashers import dsha256


def build_coinbase(
    pub_h160: bytes,
    height: int,
    arbitrary: bytes,
    miner_value: int,
    outputs_extra: List[Tuple[int, bytes]],
    witness_commitment: bytes,
):
    bytes_needed_sub_1 = 0
    while True:
        if height <= (2 ** (7 + (8 * bytes_needed_sub_1))) - 1:
            break
        bytes_needed_sub_1 += 1
    bip34_height = height.to_bytes(bytes_needed_sub_1 + 1, "little")
    coinbase_script = (
        op_push(len(bip34_height)) + bip34_height + op_push(len(arbitrary)) + arbitrary
    )
    coinbase_txin_start = (
        bytes(32) + b"\xff" * 4 + var_int(len(coinbase_script)) + coinbase_script
    )
    coinbase_txin_end = b"\xff" * 4

    vout_to_miner = b"\x76\xa9\x14" + pub_h160 + b"\x88\xac"
    outputs = [
        miner_value.to_bytes(8, "little") + op_push(len(vout_to_miner)) + vout_to_miner
    ]
    for sat, script in outputs_extra:
        outputs.append(sat.to_bytes(8, "little") + op_push(len(script)) + script)
    if witness_commitment:
        outputs.append(bytes(8) + op_push(len(witness_commitment)) + witness_commitment)

    num_outputs = len(outputs)
    coinbase_txin = coinbase_txin_start + coinbase_txin_end

    coinbase_wit = (
        int(8).to_bytes(4, "little")
        + b"\x00\x01"
        + b"\x01"
        + coinbase_txin
        + var_int(num_outputs)
        + b"".join(outputs)
        + b"\x01\x20"
        + bytes(32)
        + bytes(4)
    )
    coinbase_nowit_full = (
        int(8).to_bytes(4, "little")
        + b"\x01"
        + coinbase_txin
        + var_int(num_outputs)
        + b"".join(outputs)
        + bytes(4)
    )

    coinbase1 = (
        int(8).to_bytes(4, "little") + b"\x00\x01" + b"\x01" + coinbase_txin_start
    )
    coinbase2 = (
        coinbase_txin_end
        + var_int(num_outputs)
        + b"".join(outputs)
        + b"\x01\x20"
        + bytes(32)
        + bytes(4)
    )

    coinbase1_nowit = int(8).to_bytes(4, "little") + b"\x01" + coinbase_txin_start
    coinbase2_nowit = (
        coinbase_txin_end + var_int(num_outputs) + b"".join(outputs) + bytes(4)
    )

    coinbase_txid = dsha256(coinbase_nowit_full)
    return (
        coinbase_wit,
        coinbase_txid,
        coinbase1,
        coinbase2,
        coinbase1_nowit,
        coinbase2_nowit,
    )
