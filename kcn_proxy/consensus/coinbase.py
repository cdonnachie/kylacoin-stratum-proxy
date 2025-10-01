from typing import List, Tuple
import logging
from ..utils.enc import var_int, op_push
from ..utils.hashers import dsha256

logger = logging.getLogger(__name__)


def build_coinbase(
    pub_h160: bytes,
    height: int,
    arbitrary: bytes,
    miner_value: int,
    outputs_extra: List[Tuple[int, bytes]],
    witness_commitment: bytes,
    is_witness: bool = False,
):
    # Calculate height serialization (BIP34)
    bytes_needed_sub_1 = 0
    while True:
        if height <= (2 ** (7 + (8 * bytes_needed_sub_1))) - 1:
            break
        bytes_needed_sub_1 += 1
    bip34_height = height.to_bytes(bytes_needed_sub_1 + 1, "little")

    coinbase_script_without_extranonces = (
        op_push(len(bip34_height)) + bip34_height + op_push(len(arbitrary)) + arbitrary
    )

    extranonce_placeholder_size = 8
    total_script_length = (
        len(coinbase_script_without_extranonces) + extranonce_placeholder_size
    )

    coinbase_txin_start = (
        bytes(32)
        + b"\xff" * 4
        + var_int(total_script_length)
        + coinbase_script_without_extranonces
    )
    coinbase_txin_end = b"\xff" * 4

    # Build outputs - use P2PKH for all addresses for blockchain compatibility
    # TODO: Investigate proper witness transaction support for bech32 addresses
    # P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
    vout_to_miner = b"\x76\xa9\x14" + pub_h160 + b"\x88\xac"

    outputs = [
        miner_value.to_bytes(8, "little") + op_push(len(vout_to_miner)) + vout_to_miner
    ]

    # Add extra outputs (e.g., founder rewards)
    for sat, script in outputs_extra:
        outputs.append(sat.to_bytes(8, "little") + op_push(len(script)) + script)

    # Add witness commitment if present
    if witness_commitment:
        outputs.append(bytes(8) + op_push(len(witness_commitment)) + witness_commitment)

    num_outputs = len(outputs)
    coinbase_txin = coinbase_txin_start + coinbase_txin_end

    # Use version 8 for coinbase transactions (KCN/LCN standard)
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

    coinbase1 = int(8).to_bytes(4, "little") + b"\x00\x01\x01" + coinbase_txin_start
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
