from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .errors import ContractError, SecurityError


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise SecurityError(f"{name} must be an integer") from exc
    if value <= 0:
        raise SecurityError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class SecurityLimits:
    max_event_bytes: int = 64 * 1024
    max_file_bytes: int = 5 * 1024 * 1024
    max_batch_events: int = 10_000
    max_batch_bytes: int = 5 * 1024 * 1024
    max_plugin_file_bytes: int = 256 * 1024

    @classmethod
    def from_env(cls) -> "SecurityLimits":
        return cls(
            max_event_bytes=_env_int("ULPF_MAX_EVENT_BYTES", cls.max_event_bytes),
            max_file_bytes=_env_int("ULPF_MAX_FILE_BYTES", cls.max_file_bytes),
            max_batch_events=_env_int("ULPF_MAX_BATCH_EVENTS", cls.max_batch_events),
            max_batch_bytes=_env_int("ULPF_MAX_BATCH_BYTES", cls.max_batch_bytes),
            max_plugin_file_bytes=_env_int("ULPF_MAX_PLUGIN_FILE_BYTES", cls.max_plugin_file_bytes),
        )

    def validate_payload(self, payload: str) -> int:
        size = len(payload.encode("utf-8"))
        if size > self.max_event_bytes:
            raise SecurityError(f"event exceeds {self.max_event_bytes} byte limit")
        return size

    def validate_batch(self, payloads: list[str]) -> int:
        if len(payloads) > self.max_batch_events:
            raise SecurityError(f"batch exceeds {self.max_batch_events} event limit")
        total = 0
        for payload in payloads:
            total += self.validate_payload(payload)
            if total > self.max_batch_bytes:
                raise SecurityError(f"batch exceeds {self.max_batch_bytes} byte limit")
        return total

    def validate_file_bytes(self, body: bytes) -> None:
        if len(body) > self.max_file_bytes:
            raise SecurityError(f"file body exceeds {self.max_file_bytes} byte limit")


def safe_plugin_child(root: Path, relative: str, *, max_bytes: int) -> Path:
    """Resolve a plugin-declared path without allowing traversal or symlink escape."""
    if not relative or Path(relative).is_absolute():
        raise ContractError("plugin file path must be relative")
    candidate = root / relative
    try:
        resolved_root = root.resolve(strict=True)
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ContractError(f"missing plugin file: {relative}") from exc
    if resolved_root != resolved and resolved_root not in resolved.parents:
        raise ContractError(f"plugin file escapes plugin directory: {relative}")
    if candidate.is_symlink():
        raise ContractError(f"plugin files may not be symlinks: {relative}")
    if resolved.stat().st_size > max_bytes:
        raise ContractError(f"plugin file too large: {relative}")
    return resolved
