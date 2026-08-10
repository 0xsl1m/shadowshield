"""Durable, authenticated policy replay-state encoding and file IO.

Extracted from the monolithic ``control`` module. Everything here is stdlib-only
and FastAPI-free: canonical JSON + HMAC-SHA256 envelopes, symlink-safe bounded
reads, exclusive same-directory temporary writes, and atomic replacement.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any

_MAX_POLICY_AGE_SECONDS = 86_400
_MAX_POLICY_FUTURE_SKEW_SECONDS = 300
_MAX_POLICY_STATE_BYTES = 262_144
_MIN_POLICY_STATE_KEY_BYTES = 32
_POLICY_STATE_SCHEMA_VERSION = 1
_POLICY_STATE_MAC_DOMAIN = b"shadowshield-policy-state-v1\0"
_LOWERCASE_HEX_DIGITS = frozenset("0123456789abcdef")
_POLICY_STATE_PAYLOAD_KEYS = frozenset(
    {
        "highest_version",
        "bundle_ids",
        "effective_config",
        "active_policy",
        "updated_at",
    }
)
_ACTIVE_POLICY_KEYS = frozenset({"bundle_id", "version", "issued_at", "applied_at"})
_FileRevision = tuple[int, int, int, int, int, int, int]


def _policy_state_mac_for_key(payload: dict[str, Any], key: bytes) -> str:
    signed = {
        "schema_version": _POLICY_STATE_SCHEMA_VERSION,
        "payload": payload,
    }
    canonical = json.dumps(
        signed,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hmac.new(
        key,
        _POLICY_STATE_MAC_DOMAIN + canonical,
        hashlib.sha256,
    ).hexdigest()


def _encode_policy_state(payload: dict[str, Any], key: bytes) -> bytes:
    envelope = {
        "schema_version": _POLICY_STATE_SCHEMA_VERSION,
        "payload": payload,
        "mac": _policy_state_mac_for_key(payload, key),
    }
    encoded = (
        json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > _MAX_POLICY_STATE_BYTES:
        raise ValueError(f"policy state exceeds {_MAX_POLICY_STATE_BYTES} byte limit")
    return encoded


def _file_revision(metadata: os.stat_result) -> _FileRevision:
    """Return the stable fields used to detect a replaced or rewritten file."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        # Windows reports incompatible creation/change-time values between
        # path and descriptor stat calls. POSIX ctime is stable across those
        # views and catches a same-size rewrite even if mtime is restored.
        0 if os.name == "nt" else metadata.st_ctime_ns,
        metadata.st_nlink,
        stat.S_IMODE(metadata.st_mode),
    )


def _normalize_operator_file_path(path: str | Path) -> Path:
    """Normalize an operator-selected file while preserving its chosen location.

    Only the parent is resolved so a final symbolic-link entry remains visible to
    the no-follow checks below instead of silently redirecting the state file.
    """

    candidate = Path(path)
    if not candidate.name:
        raise ValueError("policy state path must name a file")
    # Deployment configuration intentionally permits arbitrary locations. Resolve
    # traversal and parent links once so later operations use one stable location.
    # codeql[py/path-injection]
    return candidate.parent.resolve(strict=False) / candidate.name


def _lstat_policy_state(path: Path, *, missing_ok: bool = False) -> os.stat_result | None:
    """Inspect a configured state path without following its final component."""

    try:
        # This is an intentional local-operator path, not an HTTP/API value. The
        # no-follow and identity checks around every subsequent access are the
        # applicable validation when arbitrary deployment paths must be supported.
        # codeql[py/path-injection]
        metadata = path.lstat()
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("policy state path must not be a symbolic link")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("policy state path must be a regular file")
    return metadata


def _assert_file_revision(path: Path, expected: os.stat_result | None) -> None:
    """Fail if *path* appeared, disappeared, or changed since inspection."""

    current = _lstat_policy_state(path, missing_ok=True)
    if expected is None:
        if current is not None:
            raise RuntimeError("policy state path appeared during the operation")
        return
    if current is None or _file_revision(current) != _file_revision(expected):
        raise RuntimeError("policy state changed during the operation")


def _path_entry_exists(path: Path) -> bool:
    """Return whether any entry, including a broken symlink, occupies *path*."""

    try:
        # Backup destinations are also explicit local-operator paths.
        # codeql[py/path-injection]
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _read_policy_state(
    path: Path,
    *,
    missing_ok: bool = False,
    expected: os.stat_result | None = None,
) -> tuple[bytes, os.stat_result] | None:
    """Read a bounded, regular state file without following a final symlink."""

    before = _lstat_policy_state(path, missing_ok=missing_ok)
    if before is None:
        return None
    if expected is not None and _file_revision(before) != _file_revision(expected):
        raise RuntimeError("policy state changed during the operation")

    flags = os.O_RDONLY
    flags |= getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    file_descriptor = -1
    try:
        # The path is deliberately selected by the local operator. O_NOFOLLOW
        # (where available), lstat/fstat identity checks, and a regular-file
        # requirement prevent a configured link or swap from becoming a sink.
        # codeql[py/path-injection]
        file_descriptor = os.open(path, flags)
        opened_before = os.fstat(file_descriptor)
        if not stat.S_ISREG(opened_before.st_mode):
            raise ValueError("policy state path must be a regular file")
        if _file_revision(opened_before) != _file_revision(before):
            raise RuntimeError("policy state changed while it was being opened")

        state_file = os.fdopen(file_descriptor, "rb")
        file_descriptor = -1
        with state_file:
            encoded = state_file.read(_MAX_POLICY_STATE_BYTES + 1)
            opened_after = os.fstat(state_file.fileno())
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)

    if _file_revision(opened_after) != _file_revision(opened_before):
        raise RuntimeError("policy state changed while it was being read")
    if len(encoded) > _MAX_POLICY_STATE_BYTES:
        raise ValueError(f"policy state exceeds {_MAX_POLICY_STATE_BYTES} byte limit")
    return encoded, opened_after


def _write_policy_state_temporary(
    path: Path,
    encoded: bytes,
    *,
    mode: int,
) -> tuple[Path, os.stat_result]:
    """Create and sync an exclusive same-directory temporary state file."""

    temporary_path: Path | None = None
    file_descriptor = -1
    try:
        # `path.name` cannot add a directory component. The directory itself is
        # the operator-selected state directory, so the final replace stays atomic.
        # codeql[py/path-injection]
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.tmp-",
            dir=path.parent,
        )
        temporary_path = Path(temporary_name)
        temporary_file = os.fdopen(file_descriptor, "wb")
        file_descriptor = -1
        with temporary_file:
            temporary_file.write(encoded)
            temporary_file.flush()
            if os.chmod in os.supports_fd:
                os.chmod(temporary_file.fileno(), mode)
            os.fsync(temporary_file.fileno())
            metadata = os.fstat(temporary_file.fileno())
            if metadata.st_nlink != 1:
                raise RuntimeError("temporary policy state acquired an unexpected hard link")
        return temporary_path, metadata
    except Exception:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _parse_policy_state_envelope(encoded: bytes) -> tuple[Any, str]:
    envelope = json.loads(encoded.decode("utf-8"))
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema_version", "payload", "mac"}
        or isinstance(envelope["schema_version"], bool)
        or not isinstance(envelope["schema_version"], int)
        or envelope["schema_version"] != _POLICY_STATE_SCHEMA_VERSION
    ):
        raise ValueError("invalid policy state envelope")
    state_mac = envelope["mac"]
    if (
        not isinstance(state_mac, str)
        or len(state_mac) != 64
        or any(character not in _LOWERCASE_HEX_DIGITS for character in state_mac)
    ):
        raise ValueError("invalid policy state MAC")
    return envelope["payload"], state_mac


def _fsync_parent(path: Path) -> None:
    if os.name == "nt":
        return
    directory_fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
