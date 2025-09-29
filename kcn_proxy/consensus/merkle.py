from typing import List
from ..utils.hashers import dsha256


def merkle_root_from_txids_le(txids: List[bytes]) -> bytes:
    if not txids:
        return dsha256(b"")
    if len(txids) == 1:
        return txids[0]
    level = txids[:]
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        level = [dsha256(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


def merkle_branch_for_index0(txids: List[bytes]) -> List[bytes]:
    if len(txids) <= 1:
        return []
    branch = []
    idx = 0
    level = txids[:]
    while len(level) > 1:
        if len(level) & 1:
            level.append(level[-1])
        pair = idx ^ 1
        branch.append(level[pair])
        next_level = []
        for i in range(0, len(level), 2):
            next_level.append(dsha256(level[i] + level[i + 1]))
        level = next_level
        idx //= 2
    return branch


def fold_branch_index0(leaf_le: bytes, branch: List[bytes]) -> bytes:
    h = leaf_le
    for sib in branch:
        h = dsha256(h + sib)
    return h
