from __future__ import annotations

import json
import os
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


class JsonStateStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> Any:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def backup_bad_file(self) -> None:
        backup = self.path.with_suffix(f".bad-{int(time.time())}.json")
        try:
            self.path.replace(backup)
        except OSError:
            pass

    def write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _state_file_lock(self.path):
            _atomic_write_json(self.path, data)


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    tmp_path = Path(tmp_name)
    try:
        _restrict_file_permissions(tmp_path)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            fd = -1
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _restrict_file_permissions(path)
        _fsync_parent(path.parent)
    except Exception:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


@contextmanager
def _state_file_lock(path: Path) -> Iterator[None]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        _lock_file(handle)
        try:
            yield
        finally:
            _unlock_file(handle)


def _lock_file(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(handle: Any) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _fsync_parent(parent: Path) -> None:
    if os.name == "nt":
        return
    try:
        fd = os.open(parent, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _restrict_file_permissions(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
