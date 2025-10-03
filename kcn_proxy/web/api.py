"""FastAPI web server for mining dashboard"""

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import time
import logging
import os

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
        }
    )


@app.get("/api/blocks")
async def get_blocks(limit: int = 50):
    """Get recent blocks found"""
    from ..db.schema import get_recent_blocks

    blocks = await get_recent_blocks(limit)
    return JSONResponse({"blocks": blocks})


@app.get("/api/blocks/{chain}")
async def get_chain_blocks(chain: str, limit: int = 10):
    """Get recent blocks for a specific chain (KCN or LCN)"""
    from ..db.schema import get_blocks_by_chain

    blocks = await get_blocks_by_chain(chain.upper(), limit)
    return JSONResponse({"blocks": blocks, "chain": chain.upper()})


@app.get("/api/stats")
async def get_stats(hours: int = 24):
    """Get summary statistics"""
    from ..db.schema import get_stats_summary

    stats = await get_stats_summary(hours)

    # Add current difficulty and target info
    if state:
        stats["current_kcn_difficulty"] = state.advertised_diff or 0
        stats["current_lcn_difficulty"] = (
            float.fromhex(state.aux_job.target) if state.aux_job else 0
        )
        stats["current_height_kcn"] = state.height
        stats["current_height_lcn"] = state.aux_job.height if state.aux_job else 0

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
                    else 100
                ),
                "average_difficulty": avg_difficulty,
                "time_span_minutes": minutes,
            }
        else:
            summary = {
                "total_accepted": 0,
                "total_rejected": 0,
                "acceptance_rate": 100,
                "average_difficulty": 0,
                "time_span_minutes": minutes,
            }

        return JSONResponse(
            {"stats": stats, "summary": summary, "worker_filter": worker}
        )

    except ImportError:
        return JSONResponse({"error": "Database not enabled"}, status_code=503)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


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
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/health")
async def health_check():
    """Simple health check endpoint"""
    return JSONResponse(
        {"status": "ok", "timestamp": int(time.time()), "database": "connected"}
    )
