"""JSON 状态文件读写：加锁、原子替换、坏文件备份和权限收紧。"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator


class StateLockError(RuntimeError):
    """状态文件已被其他进程占用时抛出，避免多个插件实例同时写同一份 JSON。"""

    pass


@dataclass
class _ProcessLockSlot:
    """同一进程内的重入锁槽，防止测试或热路径重复打开同一把进程锁。"""

    handle: Any
    ref_count: int = 1


_PROCESS_LOCK_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[Path, _ProcessLockSlot] = {}


class JsonStateStore:
    """负责把内存状态读写到单个 JSON 文件。"""

    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self) -> Any:
        """读取 JSON 状态文件。"""
        return json.loads(self.path.read_text(encoding="utf-8"))

    def backup_bad_file(self) -> None:
        """状态文件损坏时改名备份，避免直接覆盖排查线索。"""
        backup = self.path.with_suffix(f".bad-{int(time.time())}.json")
        try:
            self.path.replace(backup)
        except OSError:
            pass

    def write(self, data: dict[str, Any]) -> None:
        """在文件锁保护下写入状态。"""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _state_file_lock(self.path):
            _atomic_write_json(self.path, data)

    def acquire_process_lock(self) -> "StateProcessLock":
        """获取运行期独占锁；同一进程可重入，其他进程会失败关闭。"""
        return acquire_process_lock(self.path)


class StateProcessLock:
    """持有状态文件的进程级独占锁，生命周期通常等于插件实例生命周期。"""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._released = False

    def release(self) -> None:
        """释放运行期独占锁；多次调用安全。"""
        if self._released:
            return
        self._released = True
        release_process_lock(self.path)


def acquire_process_lock(path: Path) -> StateProcessLock:
    """为状态文件获取非阻塞进程锁，防止多进程覆盖彼此的状态快照。"""
    normalized = _normalized_lock_path(path)
    with _PROCESS_LOCK_GUARD:
        slot = _PROCESS_LOCKS.get(normalized)
        if slot is not None:
            slot.ref_count += 1
            return StateProcessLock(normalized)

        lock_path = _runtime_lock_path(normalized)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = lock_path.open("a+b")
        try:
            _try_lock_file(handle)
        except OSError as exc:
            try:
                handle.close()
            finally:
                pass
            raise StateLockError(
                f"CloudCLI connector state is already locked by another process: {path}"
            ) from exc
        _PROCESS_LOCKS[normalized] = _ProcessLockSlot(handle)
        return StateProcessLock(normalized)


def release_process_lock(path: Path) -> None:
    """释放先前通过 `acquire_process_lock` 获取的运行期锁。"""
    normalized = _normalized_lock_path(path)
    with _PROCESS_LOCK_GUARD:
        slot = _PROCESS_LOCKS.get(normalized)
        if slot is None:
            return
        slot.ref_count -= 1
        if slot.ref_count > 0:
            return
        _PROCESS_LOCKS.pop(normalized, None)
        try:
            _unlock_file(slot.handle)
        finally:
            slot.handle.close()


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    """先写临时文件并 fsync，再原子替换目标文件，减少崩溃导致半截 JSON 的概率。"""
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
    """跨进程文件锁，防止多个 AstrBot 进程同时写同一个状态文件。"""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as handle:
        _lock_file(handle)
        try:
            yield
        finally:
            _unlock_file(handle)


def _lock_file(handle: Any) -> None:
    """按平台选择 Windows msvcrt 或 POSIX fcntl 加排他锁。"""
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


def _try_lock_file(handle: Any) -> None:
    """非阻塞获取排他锁，用于插件运行期单实例保护。"""
    if os.name == "nt":
        import msvcrt

        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"\0")
            handle.flush()
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        return

    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_file(handle: Any) -> None:
    """释放 `_lock_file` 获取的文件锁。"""
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
    """POSIX 下同步目录项，确保 os.replace 的结果落盘。"""
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
    """尽量把状态文件权限收紧到仅当前用户可读写。"""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _runtime_lock_path(path: Path) -> Path:
    """运行期锁与写入锁分开，避免长生命周期锁阻塞单次原子写入。"""
    return path.with_suffix(path.suffix + ".runtime.lock")


def _normalized_lock_path(path: Path) -> Path:
    """把相同状态文件路径归一成同一个进程内锁键。"""
    return path.resolve(strict=False)
