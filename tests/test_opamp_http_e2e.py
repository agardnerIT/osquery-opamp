"""End-to-end over plain HTTP: fake server <-> agent/client <-> real osqueryd.

The HTTP counterpart of ``test_opamp_e2e``: same agent, same protocol bytes, the
other transport. It runs on the same fixture, because "the transport changed" must
not change what the daemon ends up running.
"""

from __future__ import annotations

from osquery_opamp.opamp.agent import OpampAgent
from osquery_opamp.opamp.client import OpampClient
from osquery_opamp.opamp.pb import opamp
from osquery_opamp.opamp.transport import HttpTransport

from fake_opamp_server import FakeHttpOpampServer

UID = bytes.fromhex("00112233445566778899aabbccddeeff")


def build_client(server, core, *, heartbeat=0.3):
    agent = OpampAgent(UID, core, extension_version="0.1.0")
    client = OpampClient(
        agent,
        lambda: HttpTransport(server.url, timeout=1.0, instance_uid=lambda: agent.instance_uid),
        heartbeat_interval=heartbeat,
        retry_interval=0.2,
        max_retry_interval=0.4,
    )
    return agent, client


def applied(message):
    return message.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED


def test_remote_config_lands_in_the_running_daemon_over_http(extension):
    with FakeHttpOpampServer() as server:
        _agent, client = build_client(server, extension.core)
        client.start()
        try:
            # A push can only be delivered on a poll, so it waits for the next one.
            server.push_config(
                {
                    "schedule": {
                        "http_pushed": {
                            "query": "select 1 as n from osquery_info;",
                            "interval": 300,
                        }
                    }
                }
            )
            message = server.wait_for(applied, description="config applied over http")
        finally:
            client.stop()

    assert message.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED
    assert message.remote_config_status.error_message == ""
    assert "http_pushed" in {row["name"] for row in extension.core.scheduled_queries()}
    assert extension.core.osquery_info()["config_valid"] == "1"


def test_the_agent_reports_over_http_like_it_does_over_websocket(extension):
    with FakeHttpOpampServer() as server:
        _agent, client = build_client(server, extension.core)
        client.start()
        try:
            described = server.wait_for(
                lambda m: m.HasField("agent_description") and m.agent_description.identifying_attributes,
                description="AgentDescription on the first request",
            )
            # Polling continues while idle, so the server keeps seeing state.
            server.wait_for(
                lambda m: m.sequence_num >= 3,
                description="a later poll",
            )
            server.push_config({"options": {"http_marker": "seen"}})
            server.wait_for(applied, description="config applied")
        finally:
            client.stop()

    assert described.agent_description.identifying_attributes
    assert server.request_count >= 3, "the agent stopped polling"


def test_the_agent_sends_its_instance_uid_as_a_header(extension):
    """Without it the server cannot name the agent in a log line for a body it
    refused, which is exactly when it needs to."""
    with FakeHttpOpampServer() as server:
        _agent, client = build_client(server, extension.core)
        client.start()
        try:
            server.wait_for(lambda m: True, description="first request")
        finally:
            client.stop()

    assert server.header_of("OpAMP-Instance-UID") == "00112233-4455-6677-8899-aabbccddeeff"


def test_the_client_recovers_after_the_server_sheds_a_request(extension):
    with FakeHttpOpampServer() as server:
        _agent, client = build_client(server, extension.core)
        client.start()
        try:
            server.wait_for(lambda m: True, description="first request")
            server.fail_next(503)
            server.wait_for(lambda m: True, description="a poll after the refusal")
            requests_at_refusal = server.request_count

            server.push_config({"schedule": {"after_shed": {"query": "select 1;", "interval": 60}}})
            server.wait_for(applied, description="config applied after a shed request")
        finally:
            client.stop()

    assert server.request_count > requests_at_refusal
