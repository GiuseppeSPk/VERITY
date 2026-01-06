"""Logging configuration for VERITY.

Provides structured logging with:
- JSON format for production
- Rich console format for development
- Configurable log levels
"""

import logging
import sys
from typing import Literal

from verity.config.settings import get_settings


def setup_logging(
    level: str | None = None,
    format_type: Literal["json", "console"] = "console",
) -> logging.Logger:
    """Configure application-wide logging.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR). Uses settings if None.
        format_type: 'json' for structured logs, 'console' for human-readable.

    Returns:
        Configured root logger for VERITY.
    """
    settings = get_settings()
    log_level = level or settings.log_level

    # Create VERITY logger
    logger = logging.getLogger("verity")
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Clear existing handlers
    logger.handlers.clear()

    # Create handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Choose format based on type
    if format_type == "json":
        formatter = logging.Formatter(
            '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
            '"logger": "%(name)s", "message": "%(message)s"}'
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Prevent propagation to root logger
    logger.propagate = False

    return logger


def get_logger(name: str) -> logging.Logger:
    """Get a child logger for a specific module.

    Args:
        name: Module name (will be prefixed with 'verity.')

    Returns:
        Logger instance
    """
    return logging.getLogger(f"verity.{name}")
