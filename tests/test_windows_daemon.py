"""Real ``osqueryd`` on Windows, over a named pipe.

Everything else in the suite runs on POSIX. ``tests/test_winpipe.py`` covers the
transport logic against a fake kernel32, but not the ctypes bindings, the pipe
names osquery actually creates, or the daemon's own Thrift pipe server. This
module is that missing test. It is skipped everywhere except Windows, where a
stock osqueryd is available.

Set ``OSQUERYD=C:\\path\\to\\osqueryd.exe`` to point at a specific build.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("win"), reason="Windows named pipes only"
)

_CANDIDATES = [
    os.environ.get("OSQUERYD", ""),
    r"C:\Program Files\osquery\osqueryd\osqueryd.exe",
    r"C:\Program Files\osquery\osqueryd.exe",
]


def find_osqueryd() -> str:
    for candidate in _CANDIDATES:
        if candidate and Path(candidate).is_file():
            return candidate
    found = shutil.which("osqueryd")
    if not found:
        pytest.skip("osqueryd.exe not found; set OSQUERYD")
    return found


def test_default_manager_socket_is_osquerys_pipe():
    """``OSQUERY_SOCKET "osquery.em"`` on Windows."""
    from osquery_opamp.osquery_thrift import default_manager_socket, is_windows

    assert is_windows()
    os.environ.pop("OSQUERY_EXTENSIONS_SOCKET", None)
    assert default_manager_socket() == r"\\.\pipe\osquery.em"


class WinDaemon:
    """osqueryd with its extension manager on a uniquely named pipe."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.pipe = rf"\\.\pipe\osq-opamp-test-{os.getpid()}-{int(time.time())}"
        config_path = root / "config.json"
        config_path.write_text("{}\n")
        self.log_path = root / "osqueryd.log"
        self._log = open(self.log_path, "wb")
        self.process = subprocess.Popen(
            [
                find_osqueryd(),
                "--ephemeral",
                "--disable_database",
                f"--extensions_socket={self.pipe}",
                "--extensions_interval=1",
                "--config_plugin=filesystem",
                f"--config_path={config_path}",
                "--logger_plugin=filesystem",
                f"--logger_path={root}",
                "--disable_events=true",
                "--disable_watchdog",
                "--verbose",
            ],
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=15)
        self._log.close()


def test_extension_registers_and_pushes_config_over_a_pipe():
    from osquery_opamp.extension import OsqueryExtension
    from osquery_opamp.osquery_thrift import make_manager_client

    root = Path(tempfile.mkdtemp(prefix="osq-win-"))
    daemon = WinDaemon(root)
    ext = None
    try:
        # There is no socket file to wait for on Windows; retry registration
        # instead, which is also what a service manager would do.
        ext = OsqueryExtension(daemon.pipe, version="0.1.0")
        ext.start(wait=30.0)

        assert ext.socket_path == f"{daemon.pipe}.{ext.uuid}"

        client = make_manager_client(daemon.pipe)
        assert ext.uuid in dict(client.extensions())

        assert ext.push_config(
            "opamp",
            {"schedule": {"win_pipe": {"query": "select 1 as n from osquery_info;", "interval": 300}}},
        ).ok
        names = {row["name"] for row in ext.core.scheduled_queries()}
        assert "win_pipe" in names
    finally:
        if ext is not None:
            ext.stop()
        daemon.stop()
        shutil.rmtree(root, ignore_errors=True)
