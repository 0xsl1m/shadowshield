"""Shared HTTP-security helpers for the optional servers.

Both :mod:`shadowshield.server` (minimal API) and :mod:`shadowshield.control`
(full dashboard) are unauthenticated control planes by default. These helpers add
*opt-in* API-key/bearer auth and CORS so a deployment can lock the surface down
without each server reinventing it.

Nothing here imports FastAPI - the FastAPI-dependent bits (the auth dependency,
the CORS middleware) are built inside each app factory where FastAPI is already
imported lazily. This module stays import-safe even without the ``dashboard`` extra.

Configuration precedence: explicit arguments first, then environment:

- ``SHADOWSHIELD_API_KEY``     - comma-separated list of accepted keys.
- ``SHADOWSHIELD_CORS_ORIGINS`` - comma-separated list of allowed origins.

Keys are compared with :func:`hmac.compare_digest` (constant-time) at request time.
"""

from __future__ import annotations

import hmac
import os


def _split_csv(value: str | None) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()] if value else []


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it and it not in seen:
            seen.add(it)
            out.append(it)
    return out


def resolve_api_keys(explicit: list[str] | None = None) -> list[str]:
    """Accepted API keys: explicit args + ``SHADOWSHIELD_API_KEY`` (de-duplicated)."""
    keys = list(explicit or [])
    keys += _split_csv(os.environ.get("SHADOWSHIELD_API_KEY"))
    return _dedupe(keys)


def resolve_cors_origins(explicit: list[str] | None = None) -> list[str]:
    """Allowed CORS origins: explicit args + ``SHADOWSHIELD_CORS_ORIGINS``."""
    origins = list(explicit or [])
    origins += _split_csv(os.environ.get("SHADOWSHIELD_CORS_ORIGINS"))
    return _dedupe(origins)


def extract_key(x_api_key: str | None, authorization: str | None) -> str | None:
    """Pull a presented key from either the ``X-API-Key`` or ``Bearer`` header."""
    if x_api_key:
        return x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip() or None
    return None


def key_is_valid(supplied: str | None, keys: list[str]) -> bool:
    """Constant-time check that ``supplied`` matches one of ``keys``.

    Compares UTF-8 bytes so a non-ASCII supplied key yields a clean ``False`` rather than
    a ``TypeError`` from :func:`hmac.compare_digest` (which rejects non-ASCII ``str``).
    """
    if not supplied:
        return False
    supplied_b = supplied.encode("utf-8")
    return any(hmac.compare_digest(supplied_b, k.encode("utf-8")) for k in keys)


def is_loopback(host: str) -> bool:
    """True for hosts that are not reachable off-box (no auth warning needed)."""
    return host in {"127.0.0.1", "localhost", "::1", ""}
