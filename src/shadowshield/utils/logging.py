"""Structured logging + an append-only JSONL audit sink.

ShadowShield uses :mod:`structlog` so every security event is a structured
record (easy to ship to a SIEM) rather than an opaque string. The audit sink is
deliberately simple — newline-delimited JSON — so it works everywhere with no
infrastructure.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import structlog

from ..core.config import LoggingConfig

_CONFIGURED = False


def configure_logging(config: LoggingConfig) -> Any:
    """Configure structlog once and return a bound ShadowShield logger.

    Logs are written to **stderr** (never stdout) so ShadowShield can sit on a
    stdin/stdout model pipeline without corrupting it.
    """
    global _CONFIGURED
    if not _CONFIGURED:
        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.JSONRenderer(),
            ],
            wrapper_class=structlog.make_filtering_bound_logger(
                getattr(logging, config.level, logging.INFO)
            ),
            # stderr, not stdout — keep stdout clean for the host application.
            logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
            cache_logger_on_first_use=True,
        )
        _CONFIGURED = True
    return structlog.get_logger("shadowshield")


class AuditLog:
    """Append-only JSONL audit trail for scan decisions.

    Each call to :meth:`record` writes exactly one JSON object on its own line.
    When ``redact_payloads`` is set (the default), raw offending text is never
    written — only a short, truncated preview — so the audit log can't itself
    become a data-leak vector.
    """

    def __init__(self, config: LoggingConfig) -> None:
        self._config = config
        self._path = Path(config.audit_path) if config.audit_path else None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._logger = configure_logging(config)

    @property
    def redact(self) -> bool:
        return self._config.redact_payloads

    def record(self, event: dict[str, Any], *, notable: bool = True) -> None:
        """Emit a security event to structlog and (if configured) the JSONL file.

        ``notable`` events (a threat was found / the payload wasn't clean) are
        logged at INFO; clean scans are logged at DEBUG so the default INFO level
        stays quiet on normal traffic. The JSONL audit file, when configured,
        records **every** decision regardless — it's the complete trail.
        """
        if not self._config.enabled:
            return
        if notable:
            self._logger.info("shadowshield.scan", **event)
        else:
            self._logger.debug("shadowshield.scan", **event)
        if self._path is not None:
            try:
                with self._path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
            except OSError as exc:  # never let audit IO break the request path
                self._logger.warning("shadowshield.audit_write_failed", error=str(exc))
