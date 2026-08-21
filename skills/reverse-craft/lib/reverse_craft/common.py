from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import tempfile
import time
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_PREFIX = "reverse-craft"
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ReverseCraftError(RuntimeError):
    """Expected user-facing failure."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise ReverseCraftError(f"required file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ReverseCraftError(f"invalid JSON in {path}: {exc}") from exc


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            dir_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        tmp.unlink(missing_ok=True)


def atomic_write_json(path: Path, value: Any) -> None:
    content = json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    atomic_write_bytes(path, content)


def safe_component(value: str, *, field: str = "identifier") -> str:
    if not ID_RE.fullmatch(value):
        raise ReverseCraftError(f"invalid {field}: {value!r}")
    return value


def slugify(value: str, fallback: str = "case") -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (normalized[:48].strip("-") or fallback)


def home_root(explicit: str | None = None) -> Path:
    raw = explicit or os.environ.get("REVERSE_CRAFT_HOME") or str(Path.home() / ".reverse-craft")
    return Path(raw).expanduser().resolve()


def bounded_text(value: str, limit: int = 4000) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n...[truncated {len(value) - limit} chars]"


class FileLock(AbstractContextManager["FileLock"]):
    """Portable exclusive-create lock with bounded stale recovery."""

    def __init__(self, path: Path, timeout: float = 10.0, stale_after: float = 21_600.0) -> None:
        self.path = path
        self.timeout = timeout
        self.stale_after = stale_after
        self.acquired = False

    def __enter__(self) -> "FileLock":
        deadline = time.monotonic() + self.timeout
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = canonical_json({"pid": os.getpid(), "host": socket.gethostname(), "created_at": utc_now()}) + b"\n"
        while True:
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as handle:
                    handle.write(payload)
                    handle.flush()
                    os.fsync(handle.fileno())
                self.acquired = True
                return self
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                except FileNotFoundError:
                    continue
                owner_dead = False
                try:
                    owner = load_json(self.path)
                    if owner.get("host") == socket.gethostname() and isinstance(owner.get("pid"), int):
                        try:
                            os.kill(owner["pid"], 0)
                        except ProcessLookupError:
                            owner_dead = True
                        except (PermissionError, OSError):
                            owner_dead = False
                except (OSError, ReverseCraftError):
                    owner_dead = age > self.stale_after
                if owner_dead or age > self.stale_after:
                    try:
                        self.path.unlink()
                    except FileNotFoundError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise ReverseCraftError(f"timed out waiting for lock: {self.path}")
                time.sleep(0.05)

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.acquired:
            self.path.unlink(missing_ok=True)
            self.acquired = False
