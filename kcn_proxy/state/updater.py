import time, os, base58
from copy import deepcopy
from aiohttp import ClientSession
from ..rpc import kcn as rpc_kcn
from ..consensus.merkle import merkle_root_from_txids_le, merkle_branch_for_index0
from ..consensus.coinbase import build_coinbase
from ..consensus.targets import (
    normalize_be_hex,
    bits_to_target,
    target_to_diff_kcn,
    target_to_diff1,
)
from ..consensus.auxpow import refresh_aux_job


async def update_once(state, settings, http: ClientSession):
    js = await rpc_kcn.getblocktemplate(http, settings.node_url)
    if js.get("error"):
        raise RuntimeError(js["error"])
    r = js["result"]
    version_int = r["version"]
    height_int = r["height"]
    bits_hex = r["bits"]
    prev_hash_hex = r["previousblockhash"]
    txs_list = r["transactions"]
    coinbase_sats_int = r["coinbasevalue"]
    witness_hex = r["default_witness_commitment"]
    target_hex = r["target"]

    await refresh_aux_job(
        state,
        http,
        settings.aux_url,
        settings.aux_address,
        force_update=(state.height != height_int),
    )

    ts = int(time.time())
    new_witness = witness_hex != state.current_commitment
    state.current_commitment = witness_hex

    state.bits = bits_hex
    state.version = version_int

    # Store prevHash with 8-word reversal applied
    # Convert hex to bytes, then split into 8 words (4 bytes each) and reverse word order
    prev_hash_bytes = bytes.fromhex(prev_hash_hex)[::-1]  # Original LE conversion
    prevhash_words_le = []
    prevhash_words_be = []
    for i in range(0, 32, 4):  # 32 bytes total, 4 bytes per word
        word = prev_hash_bytes[i : i + 4]
        prevhash_words_be.append(word)
        prevhash_words_le.append(word[::-1])

    # Reverse the order of words and store
    state.prevHash_be = b"".join(prevhash_words_be)
    state.prevHash_le = b"".join(prevhash_words_le)

    new_block = state.height == -1 or state.height != height_int
    if new_block:
        state.height = height_int

    final_target = target_hex
    state.kcn_original_target = target_hex
    state.target_source = "KCN"
    if settings.use_easier_target and state.aux_job and state.aux_job.target:
        if int(state.aux_job.target, 16) > int(final_target, 16):
            final_target = state.aux_job.target
            state.target_source = "LCN"
    state.target = final_target

    if (
        new_block
        or new_witness
        or (state.timestamp + 60 < ts if state.timestamp != -1 else True)
    ):
        mm_tag = b""
        if state.aux_root:
            mm_magic = bytes([0xFA, 0xBE, 0x6D, 0x6D])
            aux_root_le = state.aux_root[::-1]
            mm_tag = (
                mm_magic
                + aux_root_le
                + state.mm_tree_size.to_bytes(4, "little")
                + state.mm_nonce.to_bytes(4, "little")
            )
        proxy_sig = (settings.proxy_signature or "/kcn-lcn-stratum-proxy/").encode(
            "utf-8"
        )
        arbitrary = mm_tag + proxy_sig

        outputs_extra = []
        dev = r.get("coinbasedevreward")
        if dev and "scriptpubkey" in dev and dev.get("value", 0) > 0:
            outputs_extra.append((dev["value"], bytes.fromhex(dev["scriptpubkey"])))
        comm_addr = r.get("CommunityAutonomousAddress")
        comm_val = r.get("CommunityAutonomousValue", 0) or 0
        if comm_addr and comm_val > 0:
            try:
                spk = (
                    b"\x76\xa9\x14"
                    + base58.b58decode_check(comm_addr)[1:]
                    + b"\x88\xac"
                )
                outputs_extra.append((comm_val, spk))
            except Exception:
                state.logger.warning("Failed to parse community address")

        if not state.pub_h160:
            return False

        (
            coinbase_wit,
            coinbase_txid,
            coinbase1,
            coinbase2,
            coinbase1_nowit,
            coinbase2_nowit,
        ) = build_coinbase(
            pub_h160=state.pub_h160,
            height=state.height,
            arbitrary=arbitrary,
            miner_value=coinbase_sats_int,
            outputs_extra=outputs_extra,
            witness_commitment=bytes.fromhex(witness_hex),
        )
        state.coinbase_tx = coinbase_wit
        state.coinbase_txid = coinbase_txid
        state.coinbase1 = coinbase1
        state.coinbase2 = coinbase2
        state.coinbase1_nowit = coinbase1_nowit
        state.coinbase2_nowit = coinbase2_nowit

        incoming_txs = []
        txids = [state.coinbase_txid]
        for tx in txs_list:
            incoming_txs.append(tx["data"])
            txids.append(bytes.fromhex(tx["txid"])[::-1])
        state.externalTxs = incoming_txs

        merkle = merkle_root_from_txids_le(txids)
        state.coinbase_branch = merkle_branch_for_index0(txids)
        state.merkle_branches = [h.hex() for h in state.coinbase_branch]

        state.bits_le = bytes.fromhex(bits_hex)[::-1]
        state.timestamp = ts
        state.job_counter += 1

        # push difficulty + notify
        t_int = int(state.target, 16)
        difficulty = target_to_diff1(t_int)

        job_params = [
            hex(state.job_counter)[2:],
            state.prevHash_le.hex(),
            state.coinbase1_nowit.hex(),
            state.coinbase2_nowit.hex(),
            state.merkle_branches,
            version_int.to_bytes(4, "big").hex(),
            bits_hex,
            ts.to_bytes(4, "big").hex(),
            True,
        ]
        state.logger.info("Job_Params: %s", job_params)
        alive = set()
        for sess in list(state.all_sessions):
            try:
                setattr(sess, "_share_difficulty", difficulty)
                await sess.send_notification("mining.set_difficulty", (difficulty,))
                await sess.send_notification("mining.notify", job_params)
            except Exception as e:
                state.logger.debug("Dropping dead session %r: %s", sess, e)
                # best-effort cleanup of hashrate map
                try:
                    wid = getattr(sess, "_worker_id", None)
                    if wid:
                        from ..stratum.session import hashratedict

                        hashratedict.pop(wid, None)
                except Exception:
                    pass
            else:
                alive.add(sess)
        state.all_sessions = alive

        for sess in list(state.new_sessions):
            try:
                setattr(sess, "_share_difficulty", difficulty)
                await sess.send_notification("mining.set_difficulty", (difficulty,))
                await sess.send_notification("mining.notify", job_params)
                state.all_sessions.add(sess)
            except Exception as e:
                state.logger.debug("Failed initializing new session %r: %s", sess, e)
        state.new_sessions.clear()


async def state_updater_loop(state, settings):
    from aiohttp import ClientSession

    async with ClientSession() as http:
        while True:
            try:
                await update_once(state, settings, http)
            except Exception as e:
                state.logger.critical("State updater error: %s", e)
                import asyncio

                await asyncio.sleep(5)
            import asyncio

            await asyncio.sleep(0.1)
