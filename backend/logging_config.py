"""NetSentinel Structured Logging and Log Security Module.

Configures application-wide logging with request ID correlation, configurable verbosity,
and secret-scrubbing filters to prevent credentials, API keys, and sensitive tokens
from leaking into terminal or journald log streams.
"""

import logging
import re
import sys
from typing import Optional

try:
    from flask import g, has_request_context
except ImportError:
    has_request_context = lambda: False
    g = None


class SecretSanitizingFilter(logging.Filter):
    """Logging filter that scrubs suspected API keys, tokens, and passwords from log records."""

    PATTERNS = [
        # Match API keys, passwords, tokens, secrets in key-value pairs or headers
        (re.compile(r'(?i)(api[_-]?key|apikey|secret|password|token|bearer|x-apikey|key)(["\']?\s*[:=]\s*["\']?)([^"\'\s,;]+)'), r'\1\2[REDACTED]'),
        # Match 32+ character hex or alphanumeric strings that resemble external API keys
        (re.compile(r'\b([0-9a-fA-F]{32,64})\b'), r'[REDACTED_HASH]'),
        # Match basic auth patterns
        (re.compile(r'(?i)(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+'), r'\1[REDACTED]'),
        # Match bearer tokens
        (re.compile(r'(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9_\-\.]+'), r'\1[REDACTED]'),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern, repl in self.PATTERNS:
                # Do not redact short normal words or UUIDs unless matched by key
                msg = pattern.sub(repl, msg)
            record.msg = msg
        return True


class RequestContextFilter(logging.Filter):
    """Logging filter that injects the active HTTP request ID into the log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        req_id = "-"
        if has_request_context() and g and hasattr(g, "request_id"):
            req_id = g.request_id
        record.request_id = req_id
        return True


def setup_logging(log_level: Optional[str] = None) -> logging.Logger:
    """Initialize structured logging for NetSentinel with security filters.

    Args:
        log_level: Desired log level string (DEBUG, INFO, WARNING, ERROR, CRITICAL).
                   Defaults to INFO.

    Returns:
        Root logger configured for NetSentinel.
    """
    valid_levels = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }

    level_str = str(log_level or "INFO").strip().upper()
    level = valid_levels.get(level_str, logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Format: [ISO8601-like timestamp] [LEVEL] [LOGGER_NAME] [REQUEST_ID] Message
    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(name)s] [%(request_id)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Clean existing handlers to prevent duplicate lines
    if not root_logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(formatter)
        handler.addFilter(RequestContextFilter())
        handler.addFilter(SecretSanitizingFilter())
        root_logger.addHandler(handler)
    else:
        for handler in root_logger.handlers:
            handler.setFormatter(formatter)
            handler.addFilter(RequestContextFilter())
            handler.addFilter(SecretSanitizingFilter())

    # Set third-party loggers to a reasonable level to prevent noise
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    logging.getLogger("engineio").setLevel(logging.WARNING)
    logging.getLogger("socketio").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    logger = logging.getLogger("netsentinel")
    logger.setLevel(level)
    return logger
