from dataclasses import dataclass
from typing import Optional
from ..utils.hashers import dsha256
from .targets import bits_to_target, normalize_be_hex
import time, json, random

BACKOFF_INITIAL = 2
BACKOFF_MAX = 300
LOG_COALESCE = 10


@dataclass
class AuxJob:
    symbol: str
    url: str
    aux_hash: str
    target: Optional[str] = None
    chain_id: Optional[int] = None


def process_aux_target(target_hex: str) -> str:
    if not target_hex:
        return ""
    t = target_hex.lower().replace("0x", "").zfill(64)
    try:
        b = bytes.fromhex(t)
        be = b[::-1].hex()  # common LE->BE flip
        return normalize_be_hex(be)
    except Exception:
        return normalize_be_hex(t)


async def refresh_aux_job(
    state, session, aux_url: Optional[str], aux_address: str, force_update: bool = False
):
    if not aux_url or not aux_address or not aux_address.strip():
        state.aux_job = None
        state.aux_root = None
        state.mm_tree_size = 0
        state.aux_last_update = 0
        state.aux_backoff_secs = 0
        state.aux_next_try_at = 0
        state.aux_last_error = ""
        return

    now = int(time.time())

    if (
        not force_update
        and getattr(state, "aux_next_try_at", 0)
        and now < state.aux_next_try_at
    ):
        return

    if (
        not force_update
        and getattr(state, "aux_last_update", 0)
        and (now - state.aux_last_update) < 30
    ):
        return

    try:
        async with session.post(
            aux_url,
            data=json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": "0",
                    "method": "createauxblock",
                    "params": [aux_address],
                }
            ),
        ) as resp:
            js = await resp.json()
    except Exception as e:
        _record_aux_error(state, f"LCN RPC error: {e}")
        return

    if js.get("error"):
        err = js["error"]
        code = err.get("code")
        msg = str(err.get("message", "")).lower()
        if code == -10 or "download" in msg or "initial block download" in msg:
            _record_aux_error(state, f"LCN not ready (IBD): {err}")
            return
        _record_aux_error(state, f"LCN aux error: {err}")
        return

    # Success
    state.aux_backoff_secs = 0
    state.aux_next_try_at = 0
    state.aux_last_error = ""
    r = js["result"]

    bits_val = r.get("bits")
    if bits_val is not None:
        bits_hex = (
            f"{bits_val:08x}"
            if isinstance(bits_val, int)
            else str(bits_val).lstrip("0x")
        )
        t_int = bits_to_target(bits_hex)
        processed_target = normalize_be_hex(f"{t_int:x}")
    else:
        processed_target = process_aux_target(r.get("_target") or r.get("target") or "")

    state.aux_job = AuxJob(
        symbol="LCN",
        url=aux_url,
        aux_hash=r["hash"],
        target=processed_target,
        chain_id=r.get("chainid"),
    )
    state.aux_root = dsha256(bytes.fromhex(state.aux_job.aux_hash)[::-1])
    state.mm_tree_size = 1
    state.mm_nonce = now & 0xFFFFFFFF
    state.aux_last_update = now


def _record_aux_error(state, message: str):
    now = int(time.time())
    if (
        message != getattr(state, "aux_last_error", "")
        or (now - getattr(state, "aux_last_log_at", 0)) >= LOG_COALESCE
    ):
        state.logger.info(message)
        state.aux_last_error = message
        state.aux_last_log_at = now
    backoff = getattr(state, "aux_backoff_secs", 0)
    backoff = BACKOFF_INITIAL if backoff == 0 else min(backoff * 2, BACKOFF_MAX)
    jitter = int(backoff * 0.1)
    delay = backoff + (random.randint(-jitter, jitter) if jitter > 0 else 0)
    delay = max(1, delay)
    state.aux_backoff_secs = backoff
    state.aux_next_try_at = now + delay
    state.aux_job = None
    state.aux_root = None
    state.mm_tree_size = 0
