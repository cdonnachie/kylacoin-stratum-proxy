"""FastAPI web server for mining dashboard"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import time
import logging
import os
from ..stratum import vardiff as _vardiff_mod

logger = logging.getLogger("WebAPI")

app = FastAPI(title="KCN-LCN Solo Mining Dashboard")

# Mount static files directory to serve images and other static assets
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

# Store reference to state (will be set on startup)
state = None


def set_state(mining_state):
    """Set the global state reference"""
    global state
    state = mining_state


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the main dashboard HTML"""
    html_path = Path(__file__).parent / "static" / "index.html"
    if html_path.exists():
        return html_path.read_text()
    return "<h1>Dashboard HTML not found</h1>"


@app.get("/api/miners")
async def get_active_miners():
    """Get currently connected miners with live stats"""
    if not state:
        return JSONResponse({"miners": [], "total_hashrate_mhs": 0, "miner_count": 0})

    # Block-only mode: if SHARE_DIFFICULTY_DIVISOR <= 1.0, disable hashrate estimation
    try:
        divisor_val = float(os.getenv("SHARE_DIFFICULTY_DIVISOR", "1000"))
    except ValueError:
        divisor_val = 1000.0
    if divisor_val <= 1.0:
        miners_disabled = []
        now_ts = time.time()
        for session in state.all_sessions:
            worker = getattr(session, "_worker_name", "Unknown")
            miner_software = getattr(session, "_miner_software", "Unknown")
            start_time = getattr(session, "_connection_time", now_ts)
            uptime_seconds = int(now_ts - start_time)
            miners_disabled.append(
                {
                    "worker": worker,
                    "software": miner_software,
                    "assigned_difficulty": getattr(session, "_share_difficulty", None),
                    "hashrate_display": "—",
                    "hashrate_value": 0,
                    "hashrate_unit": "H/s",
                    "hashrate_instant_hs": 0,
                    "hashrate_ema_hs": 0,
                    "shares_in_window": 0,
                    "rel_error_est": 1.0,
                    "uptime_seconds": uptime_seconds,
                    "connected_at": int(start_time),
                    "hashrate_disabled": True,
                }
            )
        return JSONResponse(
            {
                "miners": miners_disabled,
                "hashrate_disabled": True,
                "total_hashrate_mhs": 0.0,
                "total_hashrate_display": "—",
                "total_instant_hs": 0.0,
                "total_ema_hs": 0.0,
                "total_instant_display": "—",
                "total_ema_display": "—",
                "total_rel_error_est": 1.0,
                "total_shares_in_window": 0,
                "miner_count": len(miners_disabled),
            }
        )

    miners = []
    current_time = time.time()
    total_instant_hs = 0.0
    total_ema_hs = 0.0
    total_shares = 0
    intervals_map = {}
    if _vardiff_mod.vardiff_manager is not None:
        try:
            intervals_map = await _vardiff_mod.vardiff_manager.all_intervals()
        except Exception:
            intervals_map = {}

    for session in state.all_sessions:
        worker = getattr(session, "_worker_name", "Unknown")
        miner_software = getattr(session, "_miner_software", "Unknown")
        assigned_diff = getattr(session, "_share_difficulty", None)

        # Get hashrate from share-based tracker with appropriate units
        from ..stratum.session import hashrate_tracker

        hashrate_display = hashrate_tracker.get_hashrate_display(worker)
        hashrate_mhs = hashrate_tracker.get_hashrate_mhs(
            worker
        )  # Keep for backward compatibility

        # Calculate connection duration
        start_time = getattr(session, "_connection_time", current_time)
        uptime_seconds = int(current_time - start_time)

        inst_hs = float(hashrate_display.get("instant", 0.0))
        ema_hs = float(hashrate_display.get("ema", inst_hs))
        shares_win = int(hashrate_display.get("shares", 0))
        total_instant_hs += inst_hs
        total_ema_hs += ema_hs
        total_shares += shares_win

        # Try VarDiff intervals first, fall back to hashrate tracker if not available
        iv = intervals_map.get(worker, {})

        # If VarDiff is disabled or worker not in VarDiff manager, use hashrate tracker intervals
        if not iv or not iv.get("blended_interval"):
            iv = hashrate_tracker.get_interval_data(worker)

        miners.append(
            {
                "worker": worker,
                "software": miner_software,
                "assigned_difficulty": assigned_diff,
                "hashrate_mhs": round(hashrate_mhs, 2),  # Legacy field
                "hashrate_display": hashrate_display[
                    "display"
                ],  # New formatted display (EMA biased)
                "hashrate_value": round(hashrate_display["value"], 2),
                "hashrate_unit": hashrate_display["unit"],
                "uptime_seconds": uptime_seconds,
                "connected_at": int(start_time),
                "hashrate_instant_hs": round(inst_hs, 2),
                "hashrate_ema_hs": round(ema_hs, 2),
                "shares_in_window": shares_win,
                "rel_error_est": round(hashrate_display.get("rel_error", 1.0), 4),
                "share_avg_interval": iv.get("avg_interval"),
                "share_ema_interval": iv.get("ema_interval"),
                "share_blended_interval": iv.get("blended_interval"),
                "target_interval": (
                    getattr(_vardiff_mod.vardiff_manager, "target", None)
                    if _vardiff_mod.vardiff_manager
                    else None
                ),
            }
        )
    # Calculate total hashrate in H/s for accurate aggregation
    total_hashrate_hs = 0
    for session in state.all_sessions:
        worker = getattr(session, "_worker_name", "Unknown")
        hashrate_display = hashrate_tracker.get_hashrate_display(worker)

        # Convert all to H/s for summation
        if hashrate_display["unit"] == "MH/s":
            total_hashrate_hs += hashrate_display["value"] * 1_000_000
        elif hashrate_display["unit"] == "KH/s":
            total_hashrate_hs += hashrate_display["value"] * 1_000
        else:  # H/s
            total_hashrate_hs += hashrate_display["value"]

    # Format total with appropriate unit
    if total_hashrate_hs >= 1_000_000:
        total_display = f"{total_hashrate_hs / 1_000_000:.2f} MH/s"
        total_mhs = total_hashrate_hs / 1_000_000
    elif total_hashrate_hs >= 1_000:
        total_display = f"{total_hashrate_hs / 1_000:.2f} KH/s"
        total_mhs = total_hashrate_hs / 1_000_000
    else:
        total_display = f"{total_hashrate_hs:.2f} H/s"
        total_mhs = total_hashrate_hs / 1_000_000

    # Helper to format dynamic units from raw H/s
    def _fmt(hs: float) -> tuple[str, float]:
        if hs >= 1_000_000_000:
            return f"{hs / 1_000_000_000:.2f} GH/s", hs / 1_000_000
        if hs >= 1_000_000:
            return f"{hs / 1_000_000:.2f} MH/s", hs / 1_000_000
        if hs >= 1_000:
            return f"{hs / 1_000:.2f} KH/s", hs / 1_000_000
        return f"{hs:.2f} H/s", hs / 1_000_000

    total_instant_display, total_instant_mhs = _fmt(total_instant_hs)
    total_ema_display, total_ema_mhs = _fmt(total_ema_hs)
    # Combined relative error (approx) using total accepted shares
    total_rel_error = 1 / (total_shares**0.5) if total_shares > 0 else 1.0

    return JSONResponse(
        {
            "miners": miners,
            "total_hashrate_mhs": round(total_mhs, 2),  # Legacy field
            "total_hashrate_display": total_display,  # Backward-compatible (EMA-like)
            "total_instant_hs": round(total_instant_hs, 2),
            "total_ema_hs": round(total_ema_hs, 2),
            "total_instant_display": total_instant_display,
            "total_ema_display": total_ema_display,
            "total_rel_error_est": round(total_rel_error, 4),
            "total_shares_in_window": total_shares,
            "miner_count": len(miners),
            "vardiff_enabled": _vardiff_mod.vardiff_manager is not None,
        }
    )


@app.get("/api/blocks")
async def get_blocks(limit: int = 100, offset: int = 0):
    """Get recent blocks found with pagination support (with in-memory fallback)"""
    try:
        from ..db.schema import get_recent_blocks

        result = await get_recent_blocks(limit, offset)
        return JSONResponse(
            {
                "blocks": result["blocks"],
                "total": result["total"],
                "source": "database",
            }
        )
    except Exception as e:
        # Fallback to in-memory tracker when database unavailable
        logger.warning(
            f"Database unavailable for blocks, using in-memory fallback: {e}"
        )
        from .block_tracker import get_block_tracker

        tracker = get_block_tracker()
        result = tracker.get_all_blocks(limit, offset)
        return JSONResponse(
            {
                "blocks": result["blocks"],
                "total": result["total"],
                "source": "memory",
            }
        )


@app.get("/api/blocks/{chain}")
async def get_chain_blocks(chain: str, limit: int = 10):
    """Get recent blocks for a specific chain (KCN or LCN) with in-memory fallback"""
    try:
        from ..db.schema import get_blocks_by_chain

        blocks = await get_blocks_by_chain(chain.upper(), limit)
        return JSONResponse(
            {"blocks": blocks, "chain": chain.upper(), "source": "database"}
        )
    except Exception as e:
        # Fallback to in-memory tracker when database unavailable
        logger.warning(
            f"Database unavailable for {chain} blocks, using in-memory fallback: {e}"
        )
        from .block_tracker import get_block_tracker

        tracker = get_block_tracker()
        blocks = tracker.get_blocks_by_chain(chain.upper(), limit)
        return JSONResponse(
            {"blocks": blocks, "chain": chain.upper(), "source": "memory"}
        )


@app.get("/api/best-shares")
async def get_best_shares():
    """Get best shares unified for merged mining"""
    try:
        from ..db.schema import get_unified_best_shares

        shares = await get_unified_best_shares(limit=10)

        return JSONResponse({"shares": shares})
    except Exception as e:
        logger.error(f"Error getting best shares: {e}")
        return JSONResponse({"shares": []})


@app.get("/api/best-shares/{chain}")
async def get_best_shares_by_chain(chain: str, limit: int = 10):
    """Get best shares for a specific chain"""
    try:
        from ..db.schema import get_best_shares

        shares = await get_best_shares(chain.upper(), limit=limit)
        return JSONResponse({"shares": shares, "chain": chain.upper()})
    except Exception as e:
        logger.error(f"Error getting best shares for {chain}: {e}")
        return JSONResponse({"shares": [], "chain": chain.upper()})


@app.get("/api/difficulty-history/{chain}")
async def get_difficulty_history(chain: str, hours: int = 24):
    """Get difficulty history for a specific chain over the last N hours"""
    try:
        from ..db.schema import get_difficulty_history

        history = await get_difficulty_history(chain.upper(), hours)
        return JSONResponse({"chain": chain.upper(), "hours": hours, "data": history})
    except Exception as e:
        logger.error(f"Error getting difficulty history for {chain}: {e}")
        return JSONResponse({"chain": chain.upper(), "hours": hours, "data": []})


@app.get("/api/hashrate-history")
async def get_hashrate_history(hours: int = 24):
    """Get hashrate history for the last N hours"""
    try:
        from ..db.schema import get_hashrate_history

        history = await get_hashrate_history(hours)
        return JSONResponse({"hours": hours, "data": history})
    except Exception as e:
        logger.error(f"Error getting hashrate history: {e}")
        return JSONResponse({"hours": hours, "data": []})


@app.get("/api/stats")
async def get_stats(hours: int = 24):
    """Get summary statistics"""
    from ..db.schema import get_stats_summary

    stats = await get_stats_summary(hours)

    # Add current difficulty and target info
    if state:
        kcn_difficulty = 0
        if state.kcn_original_target:
            try:
                from ..consensus.targets import target_to_diff1

                kcn_target_int = int(state.kcn_original_target, 16)
                kcn_difficulty = target_to_diff1(kcn_target_int)
            except Exception as e:
                logger.debug(f"Failed to compute KCN difficulty from target: {e}")

        if kcn_difficulty == 0:
            try:
                import aiohttp
                from ..config import Settings

                settings = Settings()

                async with aiohttp.ClientSession() as session:
                    payload = {
                        "jsonrpc": "1.0",
                        "id": "get_difficulty",
                        "method": "getblockchaininfo",
                        "params": [],
                    }
                    kcn_url = f"http://{settings.rpcuser}:{settings.rpcpass}@{settings.rpcip}:{settings.rpcport}"
                    async with session.post(
                        kcn_url,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=2),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "result" in data and data["result"]:
                                kcn_difficulty = data["result"].get("difficulty", 0)
            except Exception as e:
                logger.debug(f"Could not fetch KCN difficulty from daemon: {e}")

        stats["current_kcn_difficulty"] = kcn_difficulty

        if state.aux_job and getattr(state.aux_job, "target", None):
            try:
                from ..consensus.targets import target_to_diff1

                lcn_target_int = int(state.aux_job.target, 16)
                stats["current_lcn_difficulty"] = target_to_diff1(lcn_target_int)
            except Exception as e:
                logger.error("Failed to compute LCN difficulty: %s", e)
                stats["current_lcn_difficulty"] = 0
        else:
            stats["current_lcn_difficulty"] = 0
        stats["current_height_kcn"] = state.height
        stats["current_height_lcn"] = state.aux_job.height if state.aux_job else 0

        # Calculate Time-To-Find (TTF) estimates
        # Formula: TTF = (network_difficulty * 2^32) / hashrate_in_hs
        # Get total EMA hashrate from all miners
        from ..stratum.session import hashrate_tracker

        total_ema_hs = 0.0
        for session in state.all_sessions:
            worker = getattr(session, "_worker_name", "Unknown")
            hashrate_display = hashrate_tracker.get_hashrate_display(worker)
            ema_hs = float(hashrate_display.get("ema", 0.0))
            total_ema_hs += ema_hs

        # Calculate TTF for both chains (in seconds)
        stats["ttf_kcn_seconds"] = None
        stats["ttf_lcn_seconds"] = None

        if total_ema_hs > 0:
            kcn_diff = stats.get("current_kcn_difficulty", 0)
            lcn_diff = stats.get("current_lcn_difficulty", 0)

            if kcn_diff > 0:
                # TTF = (difficulty * 2^32) / hashrate
                stats["ttf_kcn_seconds"] = (kcn_diff * (2**32)) / total_ema_hs

            if lcn_diff > 0:
                stats["ttf_lcn_seconds"] = (lcn_diff * (2**32)) / total_ema_hs

    return JSONResponse(stats)


@app.get("/api/payouts")
async def get_payout_info():
    """Get payout address information"""
    import os

    payout_info = {
        "kcn_address": None,
        "lcn_address": None,
        "kcn_source": "not_set",
        "lcn_source": "not_set",
    }

    # Get LCN address from environment
    lcn_wallet = os.getenv("LCN_WALLET_ADDRESS", "")
    if lcn_wallet:
        payout_info["lcn_address"] = lcn_wallet
        payout_info["lcn_source"] = "env_config"

    # Get KCN address from first connected miner (if available)
    if state and hasattr(state, "pub_h160") and state.pub_h160:
        try:
            # Reconstruct the address from the stored pub_h160
            if getattr(state, "is_witness_address", False):
                # Bech32 address
                from ..utils.enc import bech32_encode

                hrp = "tkc" if getattr(state, "testnet", False) else "kc"
                kcn_address = bech32_encode(hrp, state.pub_h160)
            else:
                # Legacy address
                import base58

                version = 109 if getattr(state, "testnet", False) else 50
                kcn_address = base58.b58encode_check(
                    bytes([version]) + state.pub_h160
                ).decode()

            payout_info["kcn_address"] = kcn_address
            payout_info["kcn_source"] = "first_miner"
        except Exception as e:
            logger.debug("Failed to reconstruct KCN address: %s", e)
            # Fallback: show partial info
            payout_info["kcn_address"] = (
                f"Set by first miner (pub_h160: {state.pub_h160.hex()[:20]}...)"
            )
            payout_info["kcn_source"] = "first_miner"

    return JSONResponse(payout_info)


@app.get("/api/vardiff_state")
async def get_vardiff_state():
    """Inspect current VarDiff manager state (if enabled)."""
    manager = _vardiff_mod.vardiff_manager
    if manager is None:
        return JSONResponse({"enabled": False})
    try:
        return JSONResponse({"enabled": True, **manager.export_state()})
    except Exception as e:
        logger.error("Error exporting vardiff state: %s", e, exc_info=True)
        return JSONResponse(
            {"enabled": True, "error": "Failed to retrieve state"}, status_code=500
        )


@app.get("/favicon.ico")
async def favicon():
    """Serve a favicon (reuse kylacoin logo) to avoid 404 noise."""
    logo_path = static_dir / "kylacoin-logo.png"
    if logo_path.exists():
        return FileResponse(str(logo_path))
    # Fallback: 1x1 transparent GIF bytes
    from fastapi import Response

    transparent_gif = (
        b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00"
        b"\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00"
        b"\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
    )
    return Response(content=transparent_gif, media_type="image/gif")


@app.post("/api/flush_hashrate")
async def flush_hashrate():
    """Clear in-memory hashrate tracking (5m window + EMA) for a fresh start."""
    from ..stratum.session import hashrate_tracker

    cleared_workers = len(hashrate_tracker.worker_shares)
    hashrate_tracker.worker_shares.clear()
    hashrate_tracker.worker_ema.clear()
    return JSONResponse(
        {
            "status": "flushed",
            "cleared_workers": cleared_workers,
            "timestamp": int(time.time()),
        }
    )


@app.post("/api/clear_best_shares")
async def clear_best_shares():
    """Clear all best shares from database and start fresh tracking."""
    try:
        import aiosqlite
        from ..db.schema import DB_PATH

        async with aiosqlite.connect(DB_PATH) as db:
            # Delete all best shares
            await db.execute("DELETE FROM best_shares")
            deleted_count = db.total_changes
            await db.commit()

        return JSONResponse(
            {
                "status": "cleared",
                "deleted_count": deleted_count,
                "timestamp": int(time.time()),
            }
        )
    except Exception as e:
        logger.error("Error clearing best shares: %s", e)
        return JSONResponse(
            {"status": "error", "message": "Failed to clear shares"}, status_code=500
        )


@app.get("/api/lcn_hash_fix_status")
async def lcn_hash_fix_status():
    """Check if LCN hash fix has been completed or is needed."""
    try:
        import aiosqlite
        from ..db.schema import DB_PATH

        flag_file = Path("data/lcn_hashes_fixed.flag")
        flag_exists = flag_file.exists()

        # Count blocks with potentially incorrect hashes (all zeros pattern)
        bad_hash_count = 0
        if not flag_exists:
            try:
                async with aiosqlite.connect(DB_PATH) as db:
                    async with db.execute(
                        "SELECT COUNT(*) FROM blocks WHERE chain='LCN' AND accepted=1 AND block_hash LIKE '0000000000000000%'"
                    ) as cur:
                        row = await cur.fetchone()
                        if row:
                            bad_hash_count = row[0]
            except Exception as e:
                logger.debug("Failed to query bad hash count: %s", e)

        needs_fix = bad_hash_count > 0
        return JSONResponse(
            {
                "flag_exists": flag_exists,
                "needs_fix": needs_fix,
                "bad_hash_count": bad_hash_count,
                "show_button": needs_fix,  # Show button only if bad hashes detected
            }
        )
    except ImportError:
        return JSONResponse(
            {"error": "Database not enabled", "show_button": False}, status_code=503
        )
    except Exception as e:
        logger.error("Error checking LCN hash fix status: %s", e, exc_info=True)
        return JSONResponse(
            {"error": "Internal error", "show_button": False}, status_code=500
        )


@app.post("/api/fix_lcn_aux_hashes")
async def fix_lcn_aux_hashes(limit: int | None = None, dry_run: bool = False):
    """Fix historical LCN block rows that stored the parent (KCN) block hash.

    For each accepted LCN block we query getblockhash(height) on the LCN RPC endpoint (taken from
    an active session's aux_url) and update mismatched rows unless dry_run is true.
    """
    try:
        import aiosqlite
    except ImportError:
        return JSONResponse({"error": "Database not enabled"}, status_code=503)

    # Acquire LCN RPC URL from any active session
    lcn_url = None
    if state and state.all_sessions:
        for s in state.all_sessions:
            lcn_url = getattr(s, "_aux_url", None)
            if lcn_url:
                break
    if not lcn_url:
        return JSONResponse(
            {"error": "No active session with LCN RPC URL available"}, status_code=400
        )

    # Simple local RPC helper
    import json as _json, base64 as _b64
    from urllib.parse import urlparse
    import http.client

    def _rpc(method: str, params: list):
        u = urlparse(lcn_url)
        path = u.path or "/"
        auth_header = None
        if u.username:
            creds = f"{u.username}:{u.password or ''}".encode()
            auth_header = "Basic " + _b64.b64encode(creds).decode()
        body = _json.dumps(
            {"jsonrpc": "1.0", "id": "fix", "method": method, "params": params}
        )
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=10)
        headers = {"Content-Type": "text/plain"}
        if auth_header:
            headers["Authorization"] = auth_header
        conn.request("POST", path, body, headers)
        resp = conn.getresponse()
        data = resp.read()
        if resp.status != 200:
            raise RuntimeError(f"RPC {method} HTTP {resp.status}: {data[:120]!r}")
        js = _json.loads(data)
        if js.get("error"):
            raise RuntimeError(f"RPC {method} error: {js['error']}")
        return js["result"]

    from ..db.schema import DB_PATH

    checked = 0
    updated = 0
    diffs: list[tuple[int, str, str]] = []
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        query = "SELECT id, height, block_hash FROM blocks WHERE chain='LCN' AND accepted=1 ORDER BY height"
        async with db.execute(query) as cur:
            rows = await cur.fetchall()
        if limit:
            rows = rows[:limit]
        for r in rows:
            checked += 1
            height = r["height"]
            stored = r["block_hash"].lower()
            try:
                rpc_hash = _rpc("getblockhash", [height]).lower()
            except Exception as e:
                logger.debug("RPC error checking block %d: %s", height, e)
                diffs.append((height, stored, f"RPC_ERROR"))
                continue
            if stored != rpc_hash:
                diffs.append((height, stored, rpc_hash))
                if not dry_run:
                    await db.execute(
                        "UPDATE blocks SET block_hash=? WHERE id=?", (rpc_hash, r["id"])
                    )
                updated += 1
        if not dry_run and updated:
            await db.commit()

    # Create flag file on successful non-dry-run completion
    if not dry_run and checked > 0:
        flag_file = Path("data/lcn_hashes_fixed.flag")
        flag_file.parent.mkdir(parents=True, exist_ok=True)
        flag_file.write_text(
            f"LCN hash fix completed at {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n"
            f"Checked: {checked} blocks\n"
            f"Updated: {updated} blocks\n"
        )

    return JSONResponse(
        {
            "status": "ok",
            "checked": checked,
            "updated": updated,
            "dry_run": dry_run,
            "limit": limit,
            "diff_sample": diffs[:50],
        }
    )


@app.get("/api/shares")
async def get_share_stats(worker: str = None, minutes: int = 10):
    """Get recent share statistics for debugging hashrate calculation"""
    try:
        from ..db.schema import get_recent_share_stats

        stats = await get_recent_share_stats(worker=worker, minutes=minutes)

        # Calculate some summary info
        if stats:
            total_accepted = sum(s.get("shares_accepted", 0) for s in stats)
            total_rejected = sum(s.get("shares_rejected", 0) for s in stats)
            avg_difficulties = [
                s.get("avg_difficulty", 0) for s in stats if s.get("avg_difficulty")
            ]
            avg_difficulty = (
                sum(avg_difficulties) / len(avg_difficulties) if avg_difficulties else 0
            )

            summary = {
                "total_accepted": total_accepted,
                "total_rejected": total_rejected,
                "acceptance_rate": (
                    (total_accepted / (total_accepted + total_rejected) * 100)
                    if (total_accepted + total_rejected) > 0
                    else None
                ),
                "average_difficulty": avg_difficulty,
                "time_span_minutes": minutes,
            }
        else:
            summary = {
                "total_accepted": 0,
                "total_rejected": 0,
                "acceptance_rate": None,
                "average_difficulty": 0,
                "time_span_minutes": minutes,
            }

        return JSONResponse(
            {"stats": stats, "summary": summary, "worker_filter": worker}
        )

    except ImportError:
        return JSONResponse({"error": "Database not enabled"}, status_code=503)
    except Exception as e:
        logger.error("Error retrieving share stats: %s", e)
        return JSONResponse(
            {"error": "Failed to retrieve share statistics"}, status_code=500
        )


@app.post("/api/cleanup")
async def manual_cleanup():
    """Manually trigger database cleanup"""
    try:
        from ..db.schema import cleanup_old_data

        await cleanup_old_data()
        return JSONResponse(
            {"status": "cleanup completed", "timestamp": int(time.time())}
        )

    except ImportError:
        return JSONResponse({"error": "Database not enabled"}, status_code=503)
    except Exception as e:
        logger.error("Error during cleanup: %s", e)
        return JSONResponse({"error": "Failed to complete cleanup"}, status_code=500)


@app.get("/api/health")
async def health_check():
    """Simple health check endpoint"""
    return JSONResponse(
        {"status": "ok", "timestamp": int(time.time()), "database": "connected"}
    )


@app.get("/api/system/config")
async def get_system_config():
    """Get current system configuration and enabled features"""
    config_data = {
        "vardiff": {
            "enabled": _vardiff_mod.vardiff_manager is not None,
            "target_interval": float(os.getenv("VARDIFF_TARGET_INTERVAL", "15.0")),
            "min_difficulty": float(os.getenv("VARDIFF_MIN_DIFFICULTY", "0.00001")),
            "max_difficulty": float(os.getenv("VARDIFF_MAX_DIFFICULTY", "0.1")),
        },
        "zmq": {
            "enabled": os.getenv("ENABLE_ZMQ", "true").lower() == "true",
            "kcn_endpoint": os.getenv("KCN_ZMQ_ENDPOINT", "tcp://kylacoin:28332"),
            "lcn_endpoint": os.getenv("LCN_ZMQ_ENDPOINT", "tcp://lyncoin:28333"),
        },
        "notifications": {
            "discord": bool(os.getenv("DISCORD_WEBHOOK_URL", "").strip()),
            "telegram": bool(
                os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
                and os.getenv("TELEGRAM_CHAT_ID", "").strip()
            ),
        },
        "database": {
            "enabled": os.getenv("ENABLE_DATABASE", "false").lower() == "true",
        },
        "stratum": {
            "port": int(os.getenv("STRATUM_PORT", "54321")),
            "share_divisor": float(os.getenv("SHARE_DIFFICULTY_DIVISOR", "1000")),
        },
    }
    return JSONResponse(config_data)


@app.get("/api/daemon-status")
async def get_daemon_status():
    """Get blockchain daemon status for both KCN and LCN nodes"""
    import aiohttp
    import asyncio
    from ..config import Settings

    settings = Settings()

    async def get_blockchain_info(url: str, chain: str):
        """Get blockchain info from a node"""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "jsonrpc": "1.0",
                    "id": "daemon_status",
                    "method": "getblockchaininfo",
                    "params": [],
                }
                async with session.post(
                    url, json=payload, timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if "result" in data and data["result"]:
                            result = data["result"]
                            # Try to get network info for connections
                            net_payload = {
                                "jsonrpc": "1.0",
                                "id": "daemon_status",
                                "method": "getnetworkinfo",
                                "params": [],
                            }
                            try:
                                async with session.post(
                                    url,
                                    json=net_payload,
                                    timeout=aiohttp.ClientTimeout(total=3),
                                ) as net_resp:
                                    if net_resp.status == 200:
                                        net_data = await net_resp.json()
                                        net_result = net_data.get("result", {})
                                        connections = net_result.get("connections", 0)
                                        version = net_result.get(
                                            "subversion", "Unknown"
                                        ).strip("/")
                                    else:
                                        connections = "—"
                                        version = "—"
                            except:
                                connections = "—"
                                version = "—"

                            return {
                                "status": "Connected",
                                "sync": (
                                    f"{result.get('verificationprogress', 0) * 100:.1f}%"
                                    if result.get("verificationprogress")
                                    else "—"
                                ),
                                "connections": connections,
                                "version": version,
                                "blocks": result.get("blocks", 0),
                                "difficulty": result.get("difficulty", 0),
                                "chain": result.get("chain", "main"),
                                "synced": result.get("verificationprogress", 0)
                                >= 0.999,
                            }
                    return {
                        "status": "Error",
                        "sync": "—",
                        "connections": "—",
                        "version": "—",
                        "blocks": 0,
                        "difficulty": 0,
                        "chain": "—",
                        "synced": False,
                        "error": f"HTTP {resp.status}",
                    }
        except asyncio.TimeoutError:
            return {
                "status": "Timeout",
                "sync": "—",
                "connections": "—",
                "version": "—",
                "blocks": 0,
                "difficulty": 0,
                "chain": "—",
                "synced": False,
                "error": "Connection timeout",
            }
        except Exception as e:
            logger.error(f"Error getting {chain} blockchain info: {e}")
            return {
                "status": "Offline",
                "sync": "—",
                "connections": "—",
                "version": "—",
                "blocks": 0,
                "difficulty": 0,
                "chain": "—",
                "synced": False,
                "error": str(e),
            }

    # Build RPC URLs from settings
    kcn_url = f"http://{settings.rpcuser}:{settings.rpcpass}@{settings.rpcip}:{settings.rpcport}"
    lcn_url = f"http://{settings.aux_rpcuser}:{settings.aux_rpcpass}@{settings.aux_rpcip}:{settings.aux_rpcport}"

    # Get status from both nodes concurrently
    tasks = [get_blockchain_info(kcn_url, "KCN"), get_blockchain_info(lcn_url, "LCN")]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    response = {
        "kcn": (
            results[0]
            if len(results) > 0 and not isinstance(results[0], Exception)
            else {
                "status": "Error",
                "sync": "—",
                "connections": "—",
                "version": "—",
                "blocks": 0,
                "difficulty": 0,
                "chain": "—",
                "synced": False,
            }
        ),
        "lcn": (
            results[1]
            if len(results) > 1 and not isinstance(results[1], Exception)
            else {
                "status": "Error",
                "sync": "—",
                "connections": "—",
                "version": "—",
                "blocks": 0,
                "difficulty": 0,
                "chain": "—",
                "synced": False,
            }
        ),
    }

    return JSONResponse(response)


@app.get("/api/miners/connected")
async def get_connected_miners_paginated(page: int = 1, limit: int = 20):
    """Get connected miners with pagination"""
    try:
        from ..db.schema import get_connected_miners

        if page < 1:
            page = 1
        offset = (page - 1) * limit

        result = await get_connected_miners(offset=offset, limit=limit)
        return JSONResponse(
            {
                "miners": result["miners"],
                "total": result["total"],
                "page": page,
                "limit": limit,
                "pages": (result["total"] + limit - 1) // limit,
            }
        )
    except Exception as e:
        logger.error(f"Error getting connected miners: {e}")
        return JSONResponse(
            {"miners": [], "total": 0, "page": page, "limit": limit, "pages": 0}
        )


@app.get("/api/miners/disconnected")
async def get_disconnected_miners_paginated(
    hours: int = 24, page: int = 1, limit: int = 20
):
    """Get recently disconnected miners with pagination"""
    try:
        from ..db.schema import get_disconnected_miners

        if page < 1:
            page = 1
        offset = (page - 1) * limit

        result = await get_disconnected_miners(hours=hours, offset=offset, limit=limit)
        return JSONResponse(
            {
                "miners": result["miners"],
                "total": result["total"],
                "page": page,
                "limit": limit,
                "pages": (result["total"] + limit - 1) // limit,
                "hours": hours,
            }
        )
    except Exception as e:
        logger.error(f"Error getting disconnected miners: {e}")
        return JSONResponse(
            {
                "miners": [],
                "total": 0,
                "page": page,
                "limit": limit,
                "pages": 0,
                "hours": hours,
            }
        )


@app.post("/api/miners/{worker_name}/clear")
async def clear_miner_record(worker_name: str):
    """Delete a miner session record"""
    try:
        from ..db.schema import delete_miner_session

        await delete_miner_session(worker_name)
        return JSONResponse({"status": "success", "worker_name": worker_name})
    except Exception as e:
        logger.error("Error deleting miner record %s: %s", worker_name, e)
        return JSONResponse(
            {"status": "error", "message": "Failed to delete record"}, status_code=500
        )


@app.get("/api/earnings")
async def get_earnings_estimate():
    """Get estimated daily/weekly earnings based on current hashrate and difficulty"""
    try:
        from ..utils.earnings import EarningsCalculator
        from ..utils.price_tracker import get_price_tracker
        from ..consensus.targets import target_to_diff1
        from ..config import Settings
        import aiohttp

        if not state:
            return JSONResponse(
                {"status": "error", "message": "State not initialized"},
                status_code=500,
            )

        # Get current prices
        price_tracker = get_price_tracker()
        prices = await price_tracker.get_current_prices()

        # Calculate total hashrate from all connected miners
        total_hashrate_hs = 0.0
        from ..stratum.session import hashrate_tracker

        for session in state.all_sessions:
            worker = getattr(session, "_worker_name", "Unknown")
            hashrate_display = hashrate_tracker.get_hashrate_display(worker)
            ema_hs = float(hashrate_display.get("ema", 0.0))
            total_hashrate_hs += ema_hs

        # Get KCN difficulty from target or RPC
        kcn_difficulty = 0.0
        if state.kcn_original_target:
            try:
                kcn_target_int = int(state.kcn_original_target, 16)
                kcn_difficulty = target_to_diff1(kcn_target_int)
            except Exception as e:
                logger.debug(f"Failed to compute KCN difficulty from target: {e}")

        if kcn_difficulty == 0.0:
            try:
                settings = Settings()
                async with aiohttp.ClientSession() as session:
                    payload = {
                        "jsonrpc": "1.0",
                        "id": "get_difficulty",
                        "method": "getblockchaininfo",
                        "params": [],
                    }
                    kcn_url = f"http://{settings.rpcuser}:{settings.rpcpass}@{settings.rpcip}:{settings.rpcport}"
                    async with session.post(
                        kcn_url,
                        json=payload,
                        timeout=aiohttp.ClientTimeout(total=2),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if "result" in data and data["result"]:
                                kcn_difficulty = float(
                                    data["result"].get("difficulty", 0)
                                )
            except Exception as e:
                logger.debug(f"Could not fetch KCN difficulty from daemon: {e}")

        # Get LCN difficulty from aux target
        lcn_difficulty = 0.0
        if state.aux_job and getattr(state.aux_job, "target", None):
            try:
                lcn_target_int = int(state.aux_job.target, 16)
                lcn_difficulty = target_to_diff1(lcn_target_int)
            except Exception as e:
                logger.debug(f"Failed to compute LCN difficulty from target: {e}")

        # Ensure minimum difficulty of 1.0 to avoid division by zero
        # But only enforce this if difficulty is somehow zero/invalid
        if kcn_difficulty <= 0:
            kcn_difficulty = 1.0
        if lcn_difficulty <= 0:
            lcn_difficulty = 1.0

        # Get block rewards from daemon (via getblocktemplate)
        # KCN uses 12 decimal places, LCN uses 8 (like Bitcoin)
        # Block rewards are cached with 1-hour TTL to avoid excessive RPC calls
        price_tracker = get_price_tracker()
        block_rewards = await price_tracker.get_block_rewards()
        kcn_block_reward = block_rewards.get("kcn_block_reward", 1.0)
        lcn_block_reward = block_rewards.get("lcn_block_reward", 1.0)

        # Log calculation inputs
        logger.debug(
            f"Earnings calculation: hashrate={total_hashrate_hs}H/s, "
            f"kcn_diff={kcn_difficulty}, lcn_diff={lcn_difficulty}, "
            f"kcn_reward={kcn_block_reward}, lcn_reward={lcn_block_reward}, "
            f"kcn_price=${prices.get('kcn_price_usd')}, lcn_price=${prices.get('lcn_price_usd')}"
        )

        # Calculate earnings with actual block rewards
        earnings = EarningsCalculator.calculate_daily_earnings(
            hashrate_hs=total_hashrate_hs,
            kcn_difficulty=kcn_difficulty,
            lcn_difficulty=lcn_difficulty,
            kcn_price_btc=prices.get("kcn_price"),
            kcn_price_usd=prices.get("kcn_price_usd"),
            lcn_price_btc=prices.get("lcn_price"),
            lcn_price_usd=prices.get("lcn_price_usd"),
            kcn_block_reward=kcn_block_reward,
            lcn_block_reward=lcn_block_reward,
        )

        # Log results
        logger.debug(
            f"Earnings result: lcn_coins_per_day={earnings.get('lcn_coins_per_day')}, "
            f"lcn_usd_per_day={earnings.get('lcn_usd_per_day')}, "
            f"kcn_coins_per_day={earnings.get('kcn_coins_per_day')}, "
            f"kcn_usd_per_day={earnings.get('kcn_usd_per_day')}"
        )

        # Add price information and current metrics
        earnings["prices"] = {
            "kcn_price_btc": prices.get("kcn_price"),
            "kcn_price_usd": prices.get("kcn_price_usd"),
            "lcn_price_btc": prices.get("lcn_price"),
            "lcn_price_usd": prices.get("lcn_price_usd"),
            "price_timestamp": prices.get("timestamp"),
        }
        earnings["current_metrics"] = {
            "total_hashrate_hs": round(total_hashrate_hs, 2),
            "kcn_difficulty": kcn_difficulty,
            "lcn_difficulty": lcn_difficulty,
        }

        return JSONResponse(earnings)

    except Exception as e:
        logger.error("Error calculating earnings: %s", e, exc_info=True)
        return JSONResponse(
            {"status": "error", "message": "Failed to calculate earnings"},
            status_code=500,
        )
