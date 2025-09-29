from aiorpcx import serve_rs
from functools import partial
from .session import StratumSession


async def start_server(state, settings):
    factory = partial(
        StratumSession,
        state,
        settings.testnet,
        settings.verbose,
        settings.node_url,
        settings.aux_url,
        settings.debug_shares,
    )
    server = await serve_rs(factory, settings.ip, settings.port, reuse_address=True)
    import logging

    logging.getLogger("Stratum-Proxy").info(
        "Serving on %s:%d", settings.ip, settings.port
    )
    if settings.testnet:
        logging.getLogger("Stratum-Proxy").info("Using testnet")
    await server.serve_forever()
