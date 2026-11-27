import multiprocessing
import time

from json_database.lock import ComboLock


def _hold(path, ready):
    with ComboLock(path):
        ready.set()
        time.sleep(1.0)


def test_thread_exclusion(tmp_path):
    lock = ComboLock(tmp_path / "a.lock")
    assert lock.acquire()
    assert lock.acquire(blocking=False) is False
    lock.release()
    assert lock.acquire(blocking=False) is True
    lock.release()


def test_process_exclusion(tmp_path):
    path = tmp_path / "b.lock"
    ready = multiprocessing.Event()
    proc = multiprocessing.Process(target=_hold, args=(path, ready))
    proc.start()
    ready.wait(5)
    lock = ComboLock(path)
    assert lock.acquire(blocking=False) is False
    proc.join()
    assert lock.acquire(blocking=False) is True
    lock.release()


def test_deleted_lock_file(tmp_path):
    lock = ComboLock(tmp_path / "c.lock")
    lock.path.unlink()
    with lock:
        assert lock.path.exists()
