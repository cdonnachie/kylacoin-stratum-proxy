import coloredlogs, logging


def setup_logging(verbose: bool):
    level = "DEBUG" if verbose else "INFO"
    coloredlogs.install(level=level, milliseconds=True)
    logger = logging.getLogger("Stratum-Proxy")
    coloredlogs.install(logger=logger, level=level, milliseconds=True)
    return logger
