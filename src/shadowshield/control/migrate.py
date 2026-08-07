"""Operator tooling: re-key a stopped policy-state file (0.6.0 -> independent key)."""

from __future__ import annotations

import hmac
import os
import stat
from pathlib import Path

from ..core.config import Mode
from .policy_state import (
    _MIN_POLICY_STATE_KEY_BYTES,
    _assert_file_revision,
    _encode_policy_state,
    _fsync_parent,
    _normalize_operator_file_path,
    _parse_policy_state_envelope,
    _path_entry_exists,
    _policy_state_mac_for_key,
    _read_policy_state,
    _write_policy_state_temporary,
)
from .state import ShieldState


def migrate_policy_state(
    path: str | Path,
    *,
    old_key: bytes | str,
    new_key: bytes | str,
    backup_path: str | Path | None = None,
) -> Path:
    """Verify and atomically re-key a stopped 0.6.0 policy-state file.

    The source must authenticate with ``old_key`` and restore as a valid policy
    state before it is changed. The original bytes are preserved in an exclusive
    backup, and the replacement is constrained by the same size limit as startup.
    Run this only while every process using the state file is stopped.
    """

    state_argument = Path(path)
    backup_argument = (
        Path(backup_path)
        if backup_path is not None
        else state_argument.with_name(f"{state_argument.name}.pre-0.6.1.bak")
    )
    state_path = _normalize_operator_file_path(state_argument)
    backup = _normalize_operator_file_path(backup_argument)
    old_key_bytes = old_key.encode("utf-8") if isinstance(old_key, str) else old_key
    new_key_bytes = new_key.encode("utf-8") if isinstance(new_key, str) else new_key
    if not old_key_bytes:
        raise ValueError("old policy-state key must not be empty")
    if len(new_key_bytes) < _MIN_POLICY_STATE_KEY_BYTES:
        raise ValueError(
            f"new policy-state key must be at least {_MIN_POLICY_STATE_KEY_BYTES} bytes"
        )
    if hmac.compare_digest(old_key_bytes, new_key_bytes):
        raise ValueError("new policy-state key must be independent from the old key")
    if os.path.normcase(os.fspath(state_path)) == os.path.normcase(os.fspath(backup)):
        raise ValueError("backup path must differ from the policy-state path")
    if _path_entry_exists(backup):
        raise FileExistsError(f"refusing to overwrite existing backup {backup}")

    try:
        source_snapshot = _read_policy_state(state_path)
        assert source_snapshot is not None
        encoded_source, source_metadata = source_snapshot
        raw_payload, state_mac = _parse_policy_state_envelope(encoded_source)
        payload = ShieldState._validate_policy_state_payload(raw_payload)
        expected_mac = _policy_state_mac_for_key(payload, old_key_bytes)
        if not hmac.compare_digest(expected_mac, state_mac):
            raise ValueError("policy state authentication failed under the old key")

        restored_mode = str(payload["effective_config"].get("mode", Mode.BALANCED.value))
        ShieldState(
            restored_mode,
            policy_state_path=str(state_path),
            policy_state_auth_key=old_key_bytes,
        )
        encoded_replacement = _encode_policy_state(payload, new_key_bytes)
        source_mode = stat.S_IMODE(source_metadata.st_mode)
    except Exception as exc:
        raise RuntimeError(f"cannot verify policy state {state_path}: {exc}") from exc

    temporary: Path | None = None
    try:
        temporary, temporary_metadata = _write_policy_state_temporary(
            state_path,
            encoded_replacement,
            mode=source_mode,
        )

        # Detect an online writer or other change after verification.
        current_snapshot = _read_policy_state(state_path, expected=source_metadata)
        assert current_snapshot is not None
        if current_snapshot[0] != encoded_source:
            raise RuntimeError("policy state changed during migration; stop all writers and retry")
        _assert_file_revision(temporary, temporary_metadata)

        backup_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        backup_flags |= getattr(os, "O_BINARY", 0)
        backup_flags |= getattr(os, "O_CLOEXEC", 0)
        backup_flags |= getattr(os, "O_NOFOLLOW", 0)
        # The backup destination is intentionally selected by the local operator.
        # O_EXCL refuses every pre-existing entry, including symbolic links.
        # codeql[py/path-injection]
        backup_fd = os.open(
            backup,
            backup_flags,
            source_mode,
        )
        with os.fdopen(backup_fd, "wb") as backup_file:
            backup_file.write(encoded_source)
            backup_file.flush()
            os.fsync(backup_file.fileno())
        _fsync_parent(backup)

        _assert_file_revision(state_path, source_metadata)
        _assert_file_revision(temporary, temporary_metadata)
        # Both paths are local-operator destinations; the temporary source is an
        # exclusive regular sibling and the destination revision was rechecked.
        # codeql[py/path-injection]
        os.replace(temporary, state_path)
        temporary = None
        _fsync_parent(state_path)
    except Exception as exc:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise RuntimeError(
            f"cannot migrate policy state {state_path}: {exc}; "
            f"the original or backup at {backup} remains recoverable"
        ) from exc

    return backup_argument
