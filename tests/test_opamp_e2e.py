"""End-to-end: fake OpAMP server <-> agent/client <-> real osqueryd.

The daemon is the fixture from conftest, so these tests exercise the real
extension registration, the real ``config/update`` path and the real protocol
bytes. Only the server is fake.
"""

from __future__ import annotations

import json

import pytest

from osquery_opamp.opamp.agent import OpampAgent
from osquery_opamp.opamp.client import OpampClient
from osquery_opamp.opamp.pb import opamp
from osquery_opamp.opamp.transport import WebSocketTransport

from fake_opamp_server import FakeOpampServer, decode_query_result

UID = bytes.fromhex("00112233445566778899aabbccddeeff")


def build_client(server, core, *, commands_enabled=False, heartbeat=0.4):
    agent = OpampAgent(
        UID,
        core,
        extension_version="0.1.0",
        commands_enabled=commands_enabled,
        query_runner=(lambda sql: (core.query(sql), None)) if commands_enabled else None,
    )
    client = OpampClient(
        agent,
        lambda: WebSocketTransport(server.url, timeout=1.0),
        heartbeat_interval=heartbeat,
        retry_interval=0.2,
        max_retry_interval=0.4,
    )
    return agent, client


@pytest.fixture
def wired(extension):
    """A client connected to a fake server, torn down in the right order."""
    with FakeOpampServer() as server:
        agent, client = build_client(server, extension.core)
        client.start()
        server.wait_for_connection()
        yield server, agent, client
        client.stop()


def test_remote_config_lands_in_the_running_daemon(wired, extension):
    server, _agent, _ = wired
    server.push_config(
        {"schedule": {"e2e_pushed": {"query": "select 1 as n from osquery_info;", "interval": 300}}}
    )

    message = server.wait_for(
        lambda m: m.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED,
        description="APPLIED status",
    )
    assert message.remote_config_status.error_message == ""
    assert "e2e_pushed" in {row["name"] for row in extension.core.scheduled_queries()}
    assert extension.core.osquery_info()["config_valid"] == "1"


def test_rejected_config_is_reported_failed_with_the_daemon_error(wired):
    server, _agent, _ = wired
    server.push_raw_config(b"{definitely not json")

    message = server.wait_for(
        lambda m: m.remote_config_status.status == opamp.RemoteConfigStatuses_FAILED,
        description="FAILED status",
    )
    assert "not valid JSON" in message.remote_config_status.error_message


def test_agent_description_reaches_the_server(wired):
    server, agent, _ = wired
    message = server.wait_for(
        lambda m: m.HasField("agent_description"), description="agent description"
    )
    attrs = {kv.key: kv.value for kv in message.agent_description.identifying_attributes}
    assert attrs["service.name"].string_value == "osqueryd"
    assert attrs["service.version"].string_value == "5.24.0"
    assert message.capabilities == agent.capabilities()
    assert message.instance_uid == UID


def test_heartbeats_keep_the_stream_alive(wired):
    server, _agent, _ = wired
    server.wait_for(lambda m: m.sequence_num >= 3, description="three messages")
    sequences = [m.sequence_num for m in server.messages()]
    assert sequences == sorted(sequences)
    assert len(set(sequences)) == len(sequences), "sequence numbers must not repeat"


def test_server_can_request_full_state(wired):
    server, _agent, _ = wired
    server.wait_for(lambda m: m.HasField("agent_description"))
    server.clear()
    server.request_full_state()
    message = server.wait_for(
        lambda m: m.HasField("agent_description"), description="re-sent description"
    )
    assert message.sequence_num > 1


def test_effective_config_is_reported_when_accepted(wired):
    server, _agent, _ = wired
    server.push_config({"schedule": {"x": {"query": "select 1 from osquery_info;", "interval": 300}}})
    server.wait_for(lambda m: m.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED)

    message = server.wait_for(
        lambda m: m.HasField("effective_config")
        and "osquery.json" in m.effective_config.config_map.config_map,
        description="effective config",
    )
    body = json.loads(message.effective_config.config_map.config_map["osquery.json"].body)
    assert "x" in body["schedule"]


def test_adhoc_query_returns_rows_from_the_daemon(extension):
    with FakeOpampServer() as server:
        _agent, client = build_client(server, extension.core, commands_enabled=True)
        client.start()
        server.wait_for_connection()

        server.wait_for(
            lambda m: "com.osquery.query" in m.custom_capabilities.capabilities,
            description="query capability advertised",
        )
        server.send_query("select version from osquery_info;", request_id="q-42")

        message = server.wait_for(
            lambda m: m.HasField("custom_message"), description="query result"
        )
        payload = decode_query_result(message)
        assert payload["id"] == "q-42"
        assert payload["status"] == "ok"
        assert payload["rows"] == [["5.24.0"]]
        client.stop()


def test_client_reconnects_after_the_server_drops_it(wired):
    server, _agent, _client = wired
    first = server.wait_for(lambda m: m.sequence_num >= 1, description="first message")
    last_sequence = first.sequence_num
    server.drop_connection()

    deadline = 10.0
    import time

    start = time.monotonic()
    while time.monotonic() - start < deadline:
        if server.connection_count >= 2:
            break
        time.sleep(0.05)
    assert server.connection_count >= 2, "client did not reconnect"

    # The first message on a fresh connection is a full state report again.
    # Compare against the sequence number seen before the drop rather than
    # clearing the log: the reconnect message can arrive before we get here.
    message = server.wait_for(
        lambda m: m.HasField("agent_description") and m.sequence_num > last_sequence,
        description="full state after reconnect",
    )
    assert message.sequence_num > last_sequence, "sequence numbers continue across reconnects"


def test_a_withdrawal_hands_the_daemon_back_to_its_own_config(daemon_with_local_config):
    """Empty config map -> our source is emptied, the local file's query survives.

    Push mode merges our source next to the daemon's file, so a withdrawal has to
    *clear* ours. Before this, the empty map was reported FAILED and the pushed
    query stayed in the live schedule until someone restarted osqueryd.
    """
    from osquery_opamp.extension import OsqueryExtension

    daemon = daemon_with_local_config
    ext = OsqueryExtension(daemon.socket, version="0.1.0")
    ext.start()
    try:
        with FakeOpampServer() as server:
            agent, client = build_client(server, ext.core)
            client.start()
            server.wait_for_connection()
            try:
                server.push_config(
                    {"schedule": {"e2e_pushed": {"query": "select 1 as n from osquery_info;", "interval": 300}}},
                    config_hash=b"rev-1",
                )
                server.wait_for(
                    lambda m: m.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED
                    and m.remote_config_status.last_remote_config_hash == b"rev-1",
                    description="APPLIED for the pushed config",
                )
                assert "e2e_pushed" in {row["name"] for row in ext.core.scheduled_queries()}

                server.push_withdrawal(config_hash=b"rev-2")
                server.wait_for(
                    lambda m: m.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED
                    and m.remote_config_status.last_remote_config_hash == b"rev-2",
                    description="APPLIED for the withdrawal",
                )

                schedule = {row["name"]: row for row in ext.core.scheduled_queries()}
                assert "e2e_pushed" not in schedule, "the withdrawn source still schedules a query"
                assert set(schedule) == {"battery_stats"}, "the daemon's own config must survive"
                assert schedule["battery_stats"]["interval"] == "30"
            finally:
                client.stop()
    finally:
        ext.stop()
