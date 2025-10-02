from aiorpcx import serve_rs
from functools import partial
from .session import StratumSession
from ..utils.notifications import NotificationManager


async def start_server(state, settings):
    # Create notification manager
    notification_manager = NotificationManager(
        discord_webhook=settings.discord_webhook,
        telegram_bot_token=settings.telegram_bot_token,
        telegram_chat_id=settings.telegram_chat_id,
    )

    factory = partial(
        StratumSession,
        state,
        settings.testnet,
        settings.verbose,
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
