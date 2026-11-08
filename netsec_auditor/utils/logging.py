"""Structured logging for NetSec Auditor."""

from __future__ import annotations

import logging
import os
import sys
from typing import Any, cast

import structlog


def configure_logging(level: str = "INFO", json_output: bool = False) -> None:
    """Configure structured logging for the application."""

    timestamper = structlog.processors.TimeStamper(fmt="iso")

    renderer: Any
    if json_output:
        renderer = structlog.processors.JSONRenderer()
    else:
        # Logs go to stderr; color them only on a terminal and honour NO_COLOR.
        colors = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
        renderer = structlog.dev.ConsoleRenderer(colors=colors)

    processors: list[Any] = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        timestamper,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        renderer,
    ]

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    log_level = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=log_level,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance."""
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
