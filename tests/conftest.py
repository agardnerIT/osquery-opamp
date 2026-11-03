"""Test fixtures: boot a real osqueryd and hand tests its extension socket.

These tests deliberately run the daemon unprivileged with ``--ephemeral`` and
temp paths, so no root and no system state is required. ``--ephemeral`` still
spawns the watcher/worker pair, which is what we want: the tests exercise the
same process topology as a real deployment.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

#: Locations to look for the daemon, in order. The macOS pkg installs the app
#: bundle and only symlinks ``osqueryi``/``osqueryctl`` into /usr/local/bin, so
#: ``osqueryd`` usually has to be addressed by its bundle path.
_CANDIDATES = [
    os.environ.get("OSQUERYD", ""),
    "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd",
    "/usr/local/bin/osqueryd",
    "/usr/bin/osqueryd",
]


def find_osqueryd() -> str:
    for candidate in _CANDIDATES:
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    found = shutil.which("osqueryd")
    if found:
        return found
    pytest.skip("osqueryd not found; set OSQUERYD=/path/to/osqueryd")


class Daemon:
    def __init__(self, root: Path, extensions_interval: int = 3) -> None:
        self.root = root
        self.socket = str(root / "osq.em")
        self.log_dir = root / "logs"
        self.log_dir.mkdir(parents=True, exist_ok=True)
        config_path = root / "config.json"
        config_path.write_text("{}\n")
        self.process = subprocess.Popen(
            [
                find_osqueryd(),
                "--ephemeral",
                "--disable_database",
                f"--extensions_socket={self.socket}",
                f"--extensions_interval={extensions_interval}",
                "--config_plugin=filesystem",
                f"--config_path={config_path}",
                "--logger_plugin=filesystem",
                f"--logger_path={self.log_dir}",
                "--disable_events=true",
                "--verbose",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

    def wait_for_socket(self, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if Path(self.socket).exists():
                return
            if self.process.poll() is not None:
                output = self.process.stdout.read().decode(errors="replace") if self.process.stdout else ""
                raise RuntimeError(f"osqueryd exited early:\n{output}")
            time.sleep(0.1)
        raise TimeoutError(f"osqueryd did not create {self.socket} within {timeout}s")

    def stop(self) -> None:
        if self.process.poll() is None:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass


@pytest.fixture
def daemon():
    root = Path(tempfile.mkdtemp(prefix="osq-"))
    instance = Daemon(root)
    try:
        instance.wait_for_socket()
        yield instance
    finally:
        instance.stop()
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def extension(daemon):
    """A registered, serving extension against the fixture daemon."""
    from osquery_opamp.extension import OsqueryExtension

    ext = OsqueryExtension(daemon.socket, version="0.1.0")
    ext.start()
    try:
        yield ext
    finally:
        ext.stop()
