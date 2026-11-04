"""The program itself: flags, signal handling, shutdown ordering.

This runs ``python -m osquery_opamp`` as a subprocess against a real daemon and a
fake server. It is the test that catches wiring mistakes - it is how the missing
``shutdown_requested`` property and the unserialised Thrift client were found.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fake_opamp_server import FakeOpampServer, decode_query_result
from osquery_opamp.core import CoreClient
from osquery_opamp.opamp.pb import opamp

PYTHON = sys.executable
SRC = str(Path(__file__).resolve().parent.parent / "src")


def start_cli(server_url: str, daemon, root: Path, *extra: str):
    log_path = root / "cli.log"
    handle = open(log_path, "wb")
    process = subprocess.Popen(
        [
            PYTHON,
            "-m",
            "osquery_opamp",
            "--endpoint",
            server_url,
            "--extensions-socket",
            daemon.socket,
            "--identity",
            str(root / "instance_uid"),
            "--heartbeat",
            "0.5",
            "--retry",
            "0.5",
            *extra,
        ],
        env={**os.environ, "PYTHONPATH": SRC},
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    return process, log_path, handle


@pytest.fixture
def cli(daemon, tmp_path):
    server = FakeOpampServer()
    server.start()
    process, log_path, handle = start_cli(server.url, daemon, tmp_path, "--enable-commands")
    try:
        server.wait_for_connection(timeout=20)
        yield server, process, log_path
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
        handle.close()
        server.stop()


def test_cli_delivers_config_and_answers_queries(cli, daemon):
    server, process, _ = cli

    server.push_config(
        {"schedule": {"cli_smoke": {"query": "select 1 as n from osquery_info;", "interval": 300}}}
    )
    status = server.wait_for(
        lambda m: m.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED, timeout=20
    )
    assert status.remote_config_status.error_message == ""

    core = CoreClient(daemon.socket)
    assert "cli_smoke" in {row["name"] for row in core.scheduled_queries()}

    server.send_query("select version from osquery_info;", request_id="smoke-1")
    reply = server.wait_for(lambda m: m.HasField("custom_message"), timeout=20)
    payload = decode_query_result(reply)
    assert payload["id"] == "smoke-1"
    assert payload["status"] == "ok"
    assert payload["rows"] == [["5.24.0"]]

    assert process.poll() is None, "the agent should still be running"


def test_cli_shuts_down_cleanly_and_deregisters(cli, daemon):
    server, process, log_path = cli
    server.wait_for(lambda m: m.HasField("agent_description"), timeout=20)

    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=20) == 0

    core = CoreClient(daemon.socket)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not core.extensions():
            break
        time.sleep(0.1)
    assert not core.extensions(), "the extension should deregister on shutdown"

    # The spec wants agent_disconnect to be the last message on the stream.
    disconnects = [m for m in server.messages() if m.HasField("agent_disconnect")]
    assert disconnects, "agent_disconnect was not sent"
    log = log_path.read_text()
    assert "Traceback" not in log, log[-2000:]
