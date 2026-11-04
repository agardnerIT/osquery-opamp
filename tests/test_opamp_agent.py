"""Protocol state-machine tests. No sockets, no daemon, no threads."""

from __future__ import annotations

import hashlib
import json

import pytest

from osquery_opamp.opamp import constants
from osquery_opamp.opamp.agent import OpampAgent
from osquery_opamp.opamp.pb import opamp

UID = bytes.fromhex("00112233445566778899aabbccddeeff")


class FakeCore:
    """Stands in for CoreClient: records pushes, answers osquery_info."""

    def __init__(self, accept: bool = True, info: dict | None = None) -> None:
        self.accept = accept
        self.pushes: list[tuple[str, str]] = []
        self.info = info or {"version": "5.24.0", "config_hash": "abc", "config_valid": "1"}

    def push_config_raw(self, source: str, payload: str):
        self.pushes.append((source, payload))
        from osquery_opamp.core import ConfigPushResult

        return ConfigPushResult(self.accept, "OK" if self.accept else "Error parsing the config JSON")

    def osquery_info(self) -> dict:
        return dict(self.info)


def make_agent(core=None, **kwargs) -> OpampAgent:
    return OpampAgent(UID, core or FakeCore(), extension_version="0.1.0", **kwargs)


def remote_config(body: bytes, name="osquery.json", content_type="application/json", config_hash=b"") -> opamp.ServerToAgent:
    return opamp.ServerToAgent(
        instance_uid=UID,
        remote_config=opamp.AgentRemoteConfig(
            config=opamp.AgentConfigMap(
                config_map={name: opamp.AgentConfigObject(body=body, content_type=content_type)}
            ),
            config_hash=config_hash,
        ),
    )


def test_capabilities_exclude_what_we_cannot_do():
    capabilities = make_agent().capabilities()
    assert capabilities & opamp.AgentCapabilities_ReportsStatus
    assert capabilities & opamp.AgentCapabilities_AcceptsRemoteConfig
    assert not capabilities & opamp.AgentCapabilities_AcceptsRestartCommand, (
        "an extension cannot restart the daemon; claiming this would be a lie"
    )
    assert not capabilities & opamp.AgentCapabilities_AcceptsPackages
    assert not capabilities & opamp.AgentCapabilities_ReportsOwnLogs


def test_first_message_is_full_state_with_incrementing_sequence():
    agent = make_agent()
    first = agent.next_message()
    assert first.sequence_num == 1
    assert first.instance_uid == UID
    assert first.capabilities == agent.capabilities()
    assert first.HasField("agent_description")
    assert first.HasField("health")

    second = agent.next_message()
    assert second.sequence_num == 2
    # Nothing changed, so the optional sub-messages are omitted.
    assert not second.HasField("agent_description")
    assert not second.HasField("health")


def test_description_comes_from_osquery_info():
    agent = make_agent(FakeCore(info={"version": "5.24.0", "config_hash": "deadbeef", "config_valid": "1"}))
    description = agent.next_message().agent_description
    attrs = {kv.key: kv.value for kv in description.identifying_attributes}
    assert attrs["service.name"].string_value == "osqueryd"
    assert attrs["service.version"].string_value == "5.24.0"
    assert attrs["service.instance.id"].string_value == UID.hex()


def test_remote_config_applied_and_hash_reported():
    core = FakeCore()
    agent = make_agent(core)
    body = json.dumps({"schedule": {"q": {"query": "select 1;", "interval": 300}}}).encode()

    agent.handle(remote_config(body))
    assert core.pushes and core.pushes[0][0] == "opamp"
    assert core.pushes[0][1] == body.decode()

    message = agent.next_message()
    assert message.remote_config_status.status == opamp.RemoteConfigStatuses_APPLIED
    assert message.remote_config_status.last_remote_config_hash == hashlib.sha256(body).digest()


def test_server_hash_is_echoed_when_supplied():
    agent = make_agent()
    server_hash = b"\x01" * 32
    agent.handle(remote_config(b'{"schedule": {}}', config_hash=server_hash))
    assert agent.next_message().remote_config_status.last_remote_config_hash == server_hash


def test_invalid_json_is_reported_failed_and_not_pushed():
    core = FakeCore()
    agent = make_agent(core)
    agent.handle(remote_config(b"{not json"))
    assert core.pushes == [], "a config that does not parse must not reach the daemon"
    message = agent.next_message()
    assert message.remote_config_status.status == opamp.RemoteConfigStatuses_FAILED
    assert "not valid JSON" in message.remote_config_status.error_message


def test_daemon_rejection_is_reported_failed():
    agent = make_agent(FakeCore(accept=False))
    agent.handle(remote_config(b'{"schedule": {}}'))
    message = agent.next_message()
    assert message.remote_config_status.status == opamp.RemoteConfigStatuses_FAILED
    assert "osquery rejected" in message.remote_config_status.error_message


def test_non_json_content_type_is_refused():
    agent = make_agent()
    agent.handle(remote_config(b"a: 1", name="config.yaml", content_type="text/yaml"))
    assert agent.next_message().remote_config_status.status == opamp.RemoteConfigStatuses_FAILED


def test_config_map_without_expected_name_is_refused():
    agent = make_agent()
    agent.handle(remote_config(b"{}", name="collector.yaml", content_type=""))
    assert agent.next_message().remote_config_status.status == opamp.RemoteConfigStatuses_FAILED


def test_effective_config_only_sent_when_server_accepts_it():
    agent = make_agent()
    agent.handle(opamp.ServerToAgent(instance_uid=UID, capabilities=opamp.ServerCapabilities_AcceptsStatus))
    agent.handle(remote_config(b'{"schedule": {}}'))
    assert not agent.next_message().HasField("effective_config")

    agent.handle(
        opamp.ServerToAgent(
            instance_uid=UID,
            capabilities=opamp.ServerCapabilities_AcceptsStatus
            | opamp.ServerCapabilities_AcceptsEffectiveConfig,
        )
    )
    message = agent.next_message()
    assert message.HasField("effective_config")
    assert "osquery.json" in message.effective_config.config_map.config_map


def test_messages_for_another_instance_uid_are_ignored():
    core = FakeCore()
    agent = make_agent(core)
    other = opamp.ServerToAgent(
        instance_uid=b"\xff" * 16,
        remote_config=opamp.AgentRemoteConfig(
            config=opamp.AgentConfigMap(
                config_map={"osquery.json": opamp.AgentConfigObject(body=b"{}", content_type="application/json")}
            )
        ),
    )
    agent.handle(other)
    assert core.pushes == []


def test_server_assigned_uid_is_adopted():
    class Store:
        written = None

        def write(self, uid):
            Store.written = uid

    agent = make_agent(identity_store=Store())
    new_uid = b"\x02" * 16
    agent.handle(opamp.ServerToAgent(agent_identification=opamp.AgentIdentification(new_instance_uid=new_uid)))
    assert agent.instance_uid == new_uid
    assert Store.written == new_uid
    assert agent.next_message().instance_uid == new_uid


def test_restart_command_is_refused_and_visible_in_health():
    agent = make_agent()
    agent.handle(opamp.ServerToAgent(command=opamp.ServerToAgentCommand(type=opamp.CommandType_Restart)))
    message = agent.next_message()
    assert message.health.healthy is False
    assert "RESTART is not supported" in message.health.last_error


def test_query_capability_is_only_advertised_when_enabled():
    assert not make_agent().next_message().custom_capabilities.capabilities
    agent = make_agent(commands_enabled=True, query_runner=lambda sql: ([], None))
    assert constants.QUERY_CAPABILITY in agent.next_message().custom_capabilities.capabilities


def test_query_command_returns_rows():
    agent = make_agent(
        commands_enabled=True,
        query_runner=lambda sql: ([{"pid": "1", "name": "launchd"}], None),
    )
    request = opamp.CustomMessage(
        capability=constants.QUERY_CAPABILITY,
        type="run",
        data=json.dumps({"id": "q-7", "sql": "select 1"}).encode(),
    )
    replies = agent.handle(opamp.ServerToAgent(custom_message=request))
    assert len(replies) == 1
    payload = json.loads(replies[0].custom_message.data)
    assert payload["id"] == "q-7"
    assert payload["status"] == "ok"
    assert payload["rows"] == [["1", "launchd"]]


def test_query_command_when_disabled_returns_error():
    agent = make_agent(commands_enabled=False)
    request = opamp.CustomMessage(
        capability=constants.QUERY_CAPABILITY, type="run", data=json.dumps({"id": "q-1", "sql": "select 1"}).encode()
    )
    replies = agent.handle(opamp.ServerToAgent(custom_message=request))
    assert json.loads(replies[0].custom_message.data)["status"] == "error"


def test_query_runner_exception_does_not_escape():
    def boom(sql):
        raise RuntimeError("daemon exploded")

    agent = make_agent(commands_enabled=True, query_runner=boom)
    request = opamp.CustomMessage(
        capability=constants.QUERY_CAPABILITY, type="run", data=json.dumps({"id": "q-1", "sql": "x"}).encode()
    )
    replies = agent.handle(opamp.ServerToAgent(custom_message=request))
    payload = json.loads(replies[0].custom_message.data)
    assert payload["status"] == "error"
    assert "daemon exploded" in payload["error"]


def test_expired_query_is_dropped():
    agent = make_agent(commands_enabled=True, query_runner=lambda sql: ([], None), clock=lambda: 1000.0)
    request = opamp.CustomMessage(
        capability=constants.QUERY_CAPABILITY,
        type="run",
        data=json.dumps({"id": "q-1", "sql": "select 1", "expire_at": 999}).encode(),
    )
    payload = json.loads(agent.handle(opamp.ServerToAgent(custom_message=request))[0].custom_message.data)
    assert payload["error"] == "expired"


def test_sequence_numbers_never_repeat():
    agent = make_agent(commands_enabled=True, query_runner=lambda sql: ([], None))
    seen = [agent.next_message().sequence_num]
    request = opamp.CustomMessage(
        capability=constants.QUERY_CAPABILITY, type="run", data=json.dumps({"id": "1", "sql": "s"}).encode()
    )
    seen += [reply.sequence_num for reply in agent.handle(opamp.ServerToAgent(custom_message=request))]
    seen.append(agent.disconnect_message().sequence_num)
    assert seen == sorted(set(seen)), f"sequence numbers must strictly increase: {seen}"
