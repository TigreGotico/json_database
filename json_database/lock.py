"""Thread and process lock on ``filelock``, a drop-in for ``combo_lock.ComboLock``."""
from pathlib import Path
from threading import Lock

from filelock import FileLock, Timeout

LOCK_FILE_ACCESS_RIGHTS = 0o666


class ComboLock:
    """A lock held by one thread of one process at a time."""

    def __init__(self, path):
        self.path = Path(path)
        self._init_plock_file()
        self.plock = FileLock(str(self.path), mode=LOCK_FILE_ACCESS_RIGHTS)
        self.tlock = Lock()

    def _init_plock_file(self):
        if not self.path.exists():
            self.path.touch()
            self.path.chmod(LOCK_FILE_ACCESS_RIGHTS)

    def acquire(self, blocking: bool = True) -> bool:
        try:
            return self._acquire(blocking)
        except FileNotFoundError:
            self._init_plock_file()
            return self._acquire(blocking)

    def _acquire(self, blocking: bool) -> bool:
        if blocking:
            self.tlock.acquire()
            self.plock.acquire()
            return True
        if not self.tlock.acquire(blocking=False):
            return False
        try:
            self.plock.acquire(timeout=0.01)
        except Timeout:
            self.tlock.release()
            return False
        return True

    def release(self):
        self.plock.release()
        self.tlock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, _type, value, traceback):
        self.release()
