import asyncio
from .config import Settings
from .logging_setup import setup_logging
from .state.template import TemplateState
from .state.updater import state_updater_loop
from .stratum.server import start_server


def run_with_settings(settings: Settings):
    logger = setup_logging(settings.verbose)
    mode = (
        "KCN+LCN AuxPoW" if (settings.aux_url and settings.aux_address) else "KCN only"
    )
    logger.info("Mode: %s", mode)
    if settings.aux_url and settings.aux_address:
        logger.info("LCN address: %s", settings.aux_address)
    state = TemplateState()

    async def main():
        t1 = asyncio.create_task(state_updater_loop(state, settings))
        t2 = asyncio.create_task(start_server(state, settings))
        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_EXCEPTION)

    asyncio.run(main())


def run_from_env():
    run_with_settings(Settings())
