"""The storage lock holds across processes and threads without combo-lock."""
import os
import re
import subprocess
import sys
import threading
import time
from importlib.metadata import requires
from pathlib import Path
from tempfile import gettempdir

from json_database import JsonStorage

HOLD_SECONDS = 1.5

# The holder runs with combo_lock made unimportable, so it proves the package
# works when combo-lock is not installed.
HOLDER = """
import sys, time
sys.modules["combo_lock"] = None
from json_database import JsonStorage
with JsonStorage(sys.argv[1]).lock:
    print("held", flush=True)
    time.sleep(float(sys.argv[2]))
"""


def requirement_names(dist: str) -> set:
    return {re.split(r"[\s;<>=!~\[]", req, maxsplit=1)[0].lower().replace("_", "-")
            for req in requires(dist) or []}


def test_metadata_requires_filelock_not_combo_lock():
    names = requirement_names("json_database")
    assert "combo-lock" not in names
    assert "filelock" in names


def test_lock_file_sits_in_temp_dir_and_all_users_can_write_it(tmp_path):
    path = tmp_path / f"lock_path_{os.getpid()}.json"
    db = JsonStorage(str(path))
    expected = Path(gettempdir(), path.name + ".lock")
    assert Path(db.lock.lock_file) == expected
    with db.lock:
        assert os.stat(expected).st_mode & 0o777 == 0o666


def test_load_in_other_process_waits_for_release(tmp_path):
    path = tmp_path / f"cross_process_{os.getpid()}.json"
    path.write_text('{"key": "value"}')
    holder = subprocess.Popen(
        [sys.executable, "-c", HOLDER, str(path), str(HOLD_SECONDS)],
        stdout=subprocess.PIPE, text=True)
    try:
        assert "held" in (line.strip() for line in holder.stdout)
        start = time.monotonic()
        db = JsonStorage(str(path))
        waited = time.monotonic() - start
    finally:
        holder.wait(timeout=30)
    assert holder.returncode == 0
    assert waited > HOLD_SECONDS / 2
    assert db == {"key": "value"}


def test_store_in_other_thread_waits_for_release(tmp_path):
    path = tmp_path / f"cross_thread_{os.getpid()}.json"
    holder_db = JsonStorage(str(path))
    writer_db = JsonStorage(str(path))
    writer_db["key"] = "value"
    held = threading.Event()

    def hold():
        with holder_db.lock:
            held.set()
            time.sleep(HOLD_SECONDS)

    holder = threading.Thread(target=hold)
    holder.start()
    assert held.wait(timeout=10)
    start = time.monotonic()
    writer_db.store()
    waited = time.monotonic() - start
    holder.join()
    assert waited > HOLD_SECONDS / 2
    assert JsonStorage(str(path)) == {"key": "value"}
