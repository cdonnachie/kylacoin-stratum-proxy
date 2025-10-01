import asyncio
from .config import Settings
from .logging_setup import setup_logging
from .state.template import TemplateState
from .state.updater import state_updater_loop, update_once
from .stratum.server import start_server
from .zmq.listener import DualZMQListener


def run_with_settings(settings: Settings):
    logger = setup_logging(settings.verbose)
    mode = (
        "KCN+LCN AuxPoW" if (settings.aux_url and settings.aux_address) else "KCN only"
    )
    logger.info("Mode: %s", mode)
    if settings.aux_url and settings.aux_address:
        logger.info("LCN address: %s", settings.aux_address)

    # Log ZMQ configuration
    # Log ZMQ configuration
    if settings.enable_zmq:
        logger.info(
            "ZMQ enabled - KCN: %s, LCN: %s",
            settings.kcn_zmq_endpoint,
            settings.lcn_zmq_endpoint,
        )
    else:
        logger.info("ZMQ disabled - using polling only")

    state = TemplateState()

    async def main():
        from aiohttp import ClientSession

        async with ClientSession() as http:
            # ZMQ callbacks
            async def on_kcn_block(block_hash: str):
                logger.info("ZMQ: New KCN block %s, updating template", block_hash)
                try:
                    await update_once(state, settings, http, force_update=True)
                except Exception as e:
                    logger.error("Failed to update template on KCN block: %s", e)

            async def on_lcn_block(block_hash: str):
                logger.info("ZMQ: New LCN block %s, refreshing aux job", block_hash)
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

            # Wait for any task to complete or fail
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)

    asyncio.run(main())


def run_from_env():
    run_with_settings(Settings())
