import coloredlogs, logging


def setup_logging(verbose: bool):
    level = "DEBUG" if verbose else "INFO"
    coloredlogs.install(level=level, milliseconds=True)
    logger = logging.getLogger("Stratum-Proxy")
    coloredlogs.install(logger=logger, level=level, milliseconds=True)

    # Reduce noise from database libraries while keeping application logs
    logging.getLogger("aiosqlite").setLevel(logging.INFO)  # Reduce aiosqlite debug spam
    logging.getLogger("sqlite3").setLevel(logging.INFO)  # Reduce sqlite debug spam

    return logger
