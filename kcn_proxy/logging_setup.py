import coloredlogs, logging


def setup_logging(log_level="INFO"):
    """
    Setup logging with specified level.

    Args:
        log_level: Log level as string ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
                  or boolean (True=DEBUG, False=INFO) for backwards compatibility

    Returns:
        Logger instance configured with coloredlogs
    """
    # Handle backwards compatibility: boolean input
    if isinstance(log_level, bool):
        log_level = "DEBUG" if log_level else "INFO"

    # Validate log level
    valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    log_level = log_level.upper()
    if log_level not in valid_levels:
        print(
            f"Invalid log level '{log_level}'. Using 'INFO'. Valid levels: {valid_levels}"
        )
        log_level = "INFO"

    # Convert string log level to logging constant
    level_const = getattr(logging, log_level)

    # Configure root logger first (affects all child loggers)
    root_logger = logging.getLogger()
    root_logger.setLevel(level_const)
    coloredlogs.install(level=log_level, milliseconds=True)

    # Get main application logger
    logger = logging.getLogger("Stratum-Proxy")
    logger.setLevel(level_const)

    # Reduce noise from database libraries - always at INFO to prevent spam
    logging.getLogger("aiosqlite").setLevel(logging.INFO)
    logging.getLogger("sqlite3").setLevel(logging.INFO)

    # Set asyncio to INFO to reduce noise from selector logs
    logging.getLogger("asyncio").setLevel(logging.INFO)

    return logger
