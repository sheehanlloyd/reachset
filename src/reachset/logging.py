"""Owns logging configuration. structlog everywhere, stdlib logging routed through it."""

import logging
import sys

import structlog


def configure_logging(level: str = "INFO") -> None:
    """Configure structlog for JSON output on stderr. Idempotent."""
    logging.basicConfig(stream=sys.stderr, level=level.upper(), format="%(message)s")
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            logging.getLevelNamesMapping()[level.upper()]
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Named logger; use one per module."""
    return structlog.get_logger(name)  # type: ignore[no-any-return]  # structlog stubs return Any
