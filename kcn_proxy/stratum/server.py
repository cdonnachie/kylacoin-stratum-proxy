from aiorpcx import serve_rs
from functools import partial
from .session import StratumSession
from ..utils.notifications import NotificationManager
from . import vardiff as _vardiff_mod
from .vardiff import VarDiffManager


async def start_server(state, settings):
    import os, logging

    logger = logging.getLogger("Stratum-Proxy")
    # Early diagnostic for VarDiff configuration
    env_val = os.getenv("ENABLE_VARDIFF")
    logger.debug(
        "VarDiff config: settings.enable_vardiff=%s (ENV ENABLE_VARDIFF=%r)",
        settings.enable_vardiff,
        env_val,
    )
    if not settings.enable_vardiff:
        logger.debug(
            "VarDiff disabled. To enable set ENABLE_VARDIFF=true in your runtime environment (and restart)."
        )
    # Create notification manager
    notification_manager = NotificationManager(
        discord_webhook=settings.discord_webhook,
        telegram_bot_token=settings.telegram_bot_token,
        telegram_chat_id=settings.telegram_chat_id,
    )

    # Create global vardiff manager if enabled
    if settings.enable_vardiff:
        # Only initialize once
        if _vardiff_mod.vardiff_manager is None:
            _vardiff_mod.vardiff_manager = VarDiffManager(
                target_share_time=settings.vardiff_target_interval,
                min_difficulty=settings.vardiff_min_difficulty,
                max_difficulty=settings.vardiff_max_difficulty,
                retarget_shares=settings.vardiff_retarget_shares,
                retarget_time=settings.vardiff_retarget_time,
                down_step=settings.vardiff_down_step,
                up_step=settings.vardiff_up_step,
                ema_alpha=settings.vardiff_ema_alpha,
                inactivity_lower=settings.vardiff_inactivity_lower,
                inactivity_drop_factor=settings.vardiff_inactivity_drop_factor,
                inactivity_multiples=settings.vardiff_inactivity_multiples,
                state_path=settings.vardiff_state_path,
                warm_start_minutes=settings.vardiff_warm_start_minutes,
            )
            # Store headroom on manager for clamp usage
            _vardiff_mod.vardiff_manager.chain_headroom = (
                settings.vardiff_chain_headroom
            )

            # Force an initial tick so the (empty) state file is created promptly
            try:
                await _vardiff_mod.vardiff_manager.tick()
            except Exception:
                pass

            # Periodic tick task
            async def _vardiff_tick_loop():
                import asyncio

                while True:
                    try:
                        await asyncio.sleep(30)
                        await _vardiff_mod.vardiff_manager.tick()
                    except Exception:
                        pass

            import asyncio

            asyncio.create_task(_vardiff_tick_loop())

    factory = partial(
        StratumSession,
        state,
        settings.testnet,
        settings.node_url,
        settings.aux_url,
        settings.debug_shares,
        settings.share_difficulty_divisor,
        notification_manager,
    )
    server = await serve_rs(factory, settings.ip, settings.port, reuse_address=True)
    import logging

    logging.getLogger("Stratum-Proxy").info(
        "Serving on %s:%d", settings.ip, settings.port
    )
    if settings.testnet:
        logging.getLogger("Stratum-Proxy").info("Using testnet")
    await server.serve_forever()
