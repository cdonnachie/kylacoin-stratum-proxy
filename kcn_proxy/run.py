import asyncio
import time
from .config import Settings
from .logging_setup import setup_logging
from .state.template import TemplateState
from .state.updater import state_updater_loop, update_once
from .stratum.server import start_server
from .zmq.listener import DualZMQListener


def run_with_settings(settings: Settings):
    logger = setup_logging(settings.log_level)
    mode = (
        "KCN+LCN AuxPoW" if (settings.aux_url and settings.aux_address) else "KCN only"
    )
    logger.debug("Mode: %s", mode)
    if settings.aux_url and settings.aux_address:
        logger.debug("LCN address: %s", settings.aux_address)

    # Log ZMQ configuration
    # Log ZMQ configuration
    if settings.enable_zmq:
        logger.debug(
            "ZMQ enabled - KCN: %s, LCN: %s",
            settings.kcn_zmq_endpoint,
            settings.lcn_zmq_endpoint,
        )
    else:
        logger.info("ZMQ disabled - using polling only")

    state = TemplateState()

    async def main():
        from aiohttp import ClientSession

        # Initialize database if enabled
        if settings.enable_database:
            from .db.schema import init_database, cleanup_old_data

            logger.info("Initializing database...")
            await init_database()

            # Start periodic cleanup task (runs every 4 hours)
            async def periodic_cleanup():
                while True:
                    try:
                        await asyncio.sleep(4 * 3600)  # 4 hours
                        await cleanup_old_data()
                    except Exception as e:
                        logger.error("Periodic database cleanup failed: %s", e)

            asyncio.create_task(periodic_cleanup())

            # Start periodic snapshot task (runs every 60 seconds)
            async def periodic_snapshots():
                last_snapshot_time = time.time()
                while True:
                    try:
                        current_time = time.time()

                        # Record difficulty and hashrate snapshot every 60 seconds
                        if current_time - last_snapshot_time >= 60:
                            from .db.schema import (
                                record_difficulty_snapshot,
                                record_hashrate_snapshot,
                            )
                            from .consensus.targets import target_to_diff1

                            # Record difficulty snapshots for both chains
                            if state.kcn_original_target:
                                try:
                                    kcn_target_int = int(state.kcn_original_target, 16)
                                    kcn_diff = target_to_diff1(kcn_target_int)
                                    await record_difficulty_snapshot("KCN", kcn_diff)
                                except Exception as e:
                                    logger.debug(
                                        f"Failed to record KCN difficulty snapshot: {e}"
                                    )

                            if state.aux_job and state.aux_job.target:
                                try:
                                    lcn_target_int = int(state.aux_job.target, 16)
                                    lcn_diff = target_to_diff1(lcn_target_int)
                                    await record_difficulty_snapshot("LCN", lcn_diff)
                                except Exception as e:
                                    logger.debug(
                                        f"Failed to record LCN difficulty snapshot: {e}"
                                    )

                            # Record hashrate snapshot
                            try:
                                from .stratum.session import hashrate_tracker

                                if hashrate_tracker:
                                    # Calculate aggregate hashrate from all connected sessions
                                    total_hashrate_hs = 0.0
                                    if hasattr(state, "all_sessions"):
                                        for session in state.all_sessions:
                                            worker_name = getattr(
                                                session, "_worker_name", None
                                            )
                                            if worker_name:
                                                hashrate_info = hashrate_tracker.get_hashrate_display(
                                                    worker_name
                                                )
                                                instant_hs = float(
                                                    hashrate_info.get("instant", 0.0)
                                                )
                                                total_hashrate_hs += instant_hs

                                    # Always record hashrate snapshot (even if 0)
                                    logger.debug(
                                        f"Recording hashrate snapshot: {total_hashrate_hs} H/s"
                                    )
                                    await record_hashrate_snapshot(total_hashrate_hs)
                                else:
                                    logger.debug("hashrate_tracker not initialized")
                            except Exception as e:
                                logger.debug(f"Failed to record hashrate snapshot: {e}")

                            last_snapshot_time = current_time

                        await asyncio.sleep(10)  # Check every 10 seconds
                    except Exception as e:
                        logger.error(f"Periodic snapshot collection failed: {e}")
                        await asyncio.sleep(10)

            asyncio.create_task(periodic_snapshots())

        else:
            logger.debug("Database disabled - snapshots and cleanup skipped")

        # Start periodic price updates (runs regardless of database status)
        async def periodic_price_updates():
            from .utils.price_tracker import get_price_tracker

            while True:
                try:
                    await asyncio.sleep(60 * 60)  # Update every 1 hour
                    price_tracker = get_price_tracker()
                    prices = await price_tracker.get_current_prices()
                    logger.debug(f"Price update: KCN=${prices.get('kcn_price_usd')}")
                except Exception as e:
                    logger.debug(f"Periodic price update failed: {e}")

        asyncio.create_task(periodic_price_updates())

        # Start web dashboard if enabled
        dashboard_task = None
        if settings.enable_dashboard:
            import uvicorn
            from .web.api import app, set_state

            logger.info("Starting web dashboard on port %d", settings.dashboard_port)
            set_state(state)

            # Create uvicorn config
            config = uvicorn.Config(
                app, host="0.0.0.0", port=settings.dashboard_port, log_level="warning"
            )
            server = uvicorn.Server(config)
            dashboard_task = asyncio.create_task(server.serve())

        async with ClientSession() as http:
            # ZMQ callbacks
            async def on_kcn_block(block_hash: str):
                logger.debug("ZMQ: New KCN block %s, updating template", block_hash)
                try:
                    await update_once(state, settings, http, force_update=True)
                except Exception as e:
                    logger.error("Failed to update template on KCN block: %s", e)

            async def on_lcn_block(block_hash: str):
                logger.debug("ZMQ: New LCN block %s, refreshing aux job", block_hash)
                try:
                    from .consensus.auxpow import refresh_aux_job

                    await refresh_aux_job(
                        state,
                        http,
                        settings.aux_url,
                        settings.aux_address,
                        force_update=True,
                    )
                    # Update template with new aux job if successful
                    if state.aux_job:
                        await update_once(state, settings, http, force_update=False)
                except Exception as e:
                    logger.error("Failed to refresh aux job on LCN block: %s", e)

            # Create tasks
            tasks = []

            # Always start the state updater (now with reduced frequency when ZMQ is active)
            tasks.append(asyncio.create_task(state_updater_loop(state, settings)))

            # Start stratum server
            tasks.append(asyncio.create_task(start_server(state, settings)))

            # Start ZMQ listener if enabled
            if settings.enable_zmq:
                zmq_listener = DualZMQListener(
                    kcn_endpoint=settings.kcn_zmq_endpoint,
                    lcn_endpoint=(
                        settings.lcn_zmq_endpoint if settings.aux_url else None
                    ),
                    on_kcn_block=on_kcn_block,
                    on_lcn_block=on_lcn_block if settings.aux_url else None,
                )
                tasks.append(asyncio.create_task(zmq_listener.start()))

            # Add dashboard task if enabled
            if dashboard_task:
                tasks.append(dashboard_task)

            # Wait for any task to complete or fail
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

    asyncio.run(main())


def run_from_env():
    run_with_settings(Settings())
