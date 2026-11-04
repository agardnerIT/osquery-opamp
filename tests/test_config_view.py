"""Config reporting and validation, without a daemon or a server.

Everything here is agent logic: what counts as a valid config, what the
effective-config report contains, and what happens when the daemon ends up with
two queries of the same name.
"""

from __future__ import annotations

import json

from osquery_opamp.opamp import constants
from osquery_opamp.opamp.agent import MAX_QUERIES_VALIDATED, OpampAgent
from osquery_opamp.opamp.configview import config_object_name, source_documents
from osquery_opamp.opamp.pb import opamp

UID = bytes.fromhex("00112233445566778899aabbccddeeff")


class FakeCore:
    """A core that records pushes and serves a scripted view of the daemon."""

    def __init__(
        self,
        accept: bool = True,
        bad_queries: dict | None = None,
        sources: dict | None = None,
        schedule: list | None = None,
        packs: list | None = None,
        plugin: str = "filesystem",
    ) -> None:
        self.accept = accept
        self.bad_queries = bad_queries or {}
        self.sources = sources or {}
        self.schedule = schedule or []
        self.packs = packs or []
        self.plugin = plugin
        self.pushes: list[tuple[str, str]] = []
        self.compiled: list[str] = []
        self.schedule_reads = 0

    def push_config_raw(self, source: str, payload: str):
        from osquery_opamp.core import ConfigPushResult

        self.pushes.append((source, payload))
        return ConfigPushResult(self.accept, "OK" if self.accept else "Error parsing the config JSON")

    def osquery_info(self) -> dict:
        return {"version": "5.24.0", "config_hash": "abc", "config_valid": "1"}

    def query_columns(self, sql: str) -> list:
        self.compiled.append(sql)
        for marker, error in self.bad_queries.items():
            if marker in sql:
                from osquery_opamp.core import CoreError

                raise CoreError(error)
        return [{"col": "TEXT"}]

    def active_config_plugin(self) -> str:
        return self.plugin

    def config_sources(self) -> dict:
        return dict(self.sources)

    def schedule_state(self) -> list:
        self.schedule_reads += 1
        return [dict(row) for row in self.schedule]

    def packs_state(self) -> list:
        return [dict(row) for row in self.packs]


class FakeCoreWithoutValidation:
    """A minimal core, like one from an older daemon: no compile RPC."""

    def push_config_raw(self, source: str, payload: str):
        from osquery_opamp.core import ConfigPushResult

        return ConfigPushResult(True, "OK")

    def osquery_info(self) -> dict:
        return {}


def make_agent(core, **kwargs) -> OpampAgent:
    return OpampAgent(UID, core, extension_version="0.1.0", **kwargs)


def server_message(body: bytes, config_hash: bytes = b"", capabilities: int = 0) -> opamp.ServerToAgent:
    return opamp.ServerToAgent(
        instance_uid=UID,
        capabilities=capabilities,
        remote_config=opamp.AgentRemoteConfig(
            config=opamp.AgentConfigMap(
                config_map={
                    constants.CONFIG_OBJECT_NAME: opamp.AgentConfigObject(
                        body=body, content_type="application/json"
                    )
                }
            ),
            config_hash=config_hash,
        ),
    )


def attributes_of(health) -> dict:
    """Flatten ``ComponentHealth.attributes`` into a plain dict."""
    out = {}
    for item in health.attributes:
        which = item.value.WhichOneof("value")
        out[item.key] = list(item.value.array_value.values) if which == "array_value" else getattr(
            item.value, which
        )
    if "osquery.schedule" in out:
        out["osquery.schedule"] = [v.string_value for v in out["osquery.schedule"]]
    if "osquery.schedule_duplicates" in out:
        out["osquery.schedule_duplicates"] = [
            v.string_value for v in out["osquery.schedule_duplicates"]
        ]
    return out


SCHEDULE = {"schedule": {"battery_stats": {"query": "select 1 from time;", "interval": 30}}}


# -- object naming ---------------------------------------------------------


def test_config_object_name_uses_basenames():
    assert config_object_name("/var/osquery/osquery.conf") == "osquery.osquery.conf.json"
    assert config_object_name("/tmp/osq-abcd/config.json") == "osquery.config.json"
    assert (
        config_object_name("/var/osquery/osquery.conf.d/10-schedule.conf")
        == "osquery.10-schedule.conf.json"
    )


def test_config_object_name_handles_windows_paths_and_odd_characters():
    assert config_object_name(r"C:\Program Files\osquery\osquery.conf") == "osquery.osquery.conf.json"
    assert config_object_name("/etc/osquery/my config!.conf") == "osquery.my_config_.conf.json"
    # Nothing usable left: still a valid, distinguishable key rather than a crash.
    assert config_object_name("/") == "osquery.source.json"


def test_source_documents_keeps_both_sources_when_basenames_clash():
    documents = source_documents(
        {"/a/osquery.conf": '{"a": 1}', "/b/osquery.conf": '{"b": 2}'}
    )
    assert sorted(documents) == ["osquery.osquery.conf-2.json", "osquery.osquery.conf.json"]
    assert sorted(documents.values()) == ['{"a": 1}', '{"b": 2}']


# -- validation ------------------------------------------------------------


def test_config_with_uncompilable_query_is_refused_and_never_pushed():
    core = FakeCore(bad_queries={"batteries": "no such table: batteries"})
    agent = make_agent(core)

    agent.handle(
        server_message(
            json.dumps(
                {"schedule": {"battery": {"query": "select * from batteries;", "interval": 30}}}
            ).encode()
        )
    )

    assert core.pushes == [], "a config osquery cannot run must not reach the daemon"
    assert agent.remote_config_status == opamp.RemoteConfigStatuses_FAILED
    assert "'battery'" in agent.remote_config_error
    assert "no such table: batteries" in agent.remote_config_error
    assert not agent.health.healthy


def test_config_with_compilable_queries_is_pushed():
    core = FakeCore()
    agent = make_agent(core)

    agent.handle(server_message(json.dumps(SCHEDULE).encode()))

    assert len(core.pushes) == 1
    assert core.compiled == ["select 1 from time;"]
    assert agent.remote_config_status == opamp.RemoteConfigStatuses_APPLIED


def test_pack_queries_are_validated_too():
    core = FakeCore(bad_queries={"nope": "no such table: nope"})
    agent = make_agent(core)

    agent.handle(
        server_message(
            json.dumps(
                {
                    "packs": {
                        "pack_a": {
                            "queries": {"q1": {"query": "select * from nope;", "interval": 60}}
                        }
                    }
                }
            ).encode()
        )
    )

    assert core.pushes == []
    assert "pack_a.q1" in agent.remote_config_error


def test_validation_is_skipped_when_the_core_cannot_compile():
    """An older daemon, or a transport error, must not reject every push."""
    agent = make_agent(FakeCoreWithoutValidation())
    agent.handle(server_message(json.dumps(SCHEDULE).encode()))
    assert agent.remote_config_status == opamp.RemoteConfigStatuses_APPLIED


def test_validation_can_be_disabled():
    core = FakeCore(bad_queries={"batteries": "no such table: batteries"})
    agent = make_agent(core, validate_queries=False)
    agent.handle(server_message(b'{"schedule": {"b": {"query": "select * from batteries;"}}}'))
    assert core.compiled == []
    assert len(core.pushes) == 1


def test_validation_is_capped_so_a_huge_config_cannot_stall_the_agent():
    core = FakeCore()
    agent = make_agent(core)
    schedule = {
        f"q{i}": {"query": f"select {i} from time;", "interval": 300}
        for i in range(MAX_QUERIES_VALIDATED + 5)
    }
    agent.handle(server_message(json.dumps({"schedule": schedule}).encode()))
    assert len(core.compiled) == MAX_QUERIES_VALIDATED


# -- effective config ------------------------------------------------------


def test_effective_config_reports_pushed_body_under_the_canonical_key():
    agent = make_agent(FakeCore())
    agent.handle(server_message(json.dumps(SCHEDULE).encode()))
    agent.server_capabilities = constants.SERVER_ACCEPTS_EFFECTIVE_CONFIG

    message = agent.next_message()
    config_map = message.effective_config.config_map.config_map

    assert list(config_map) == ["osquery.json"]
    assert json.loads(config_map["osquery.json"].body) == SCHEDULE


def test_effective_config_includes_local_sources_the_agent_did_not_push():
    """A server that cannot see /var/osquery/osquery.conf will misdiagnose conflicts."""
    core = FakeCore(
        sources={
            "/var/osquery/osquery.conf": '{"schedule": {"local": {"query": "select 1;"}}}',
            "/var/osquery/osquery.conf.d/10-extra.conf": '{"options": {}}',
        }
    )
    agent = make_agent(core)
    agent.refresh_state(force=True)
    agent.server_capabilities = constants.SERVER_ACCEPTS_EFFECTIVE_CONFIG

    config_map = agent.next_message().effective_config.config_map.config_map

    assert sorted(config_map) == [
        "osquery.10-extra.conf.json",
        "osquery.osquery.conf.json",
    ]
    assert json.loads(config_map["osquery.osquery.conf.json"].body)["schedule"]["local"]


def test_effective_config_is_omitted_when_the_server_does_not_want_it():
    agent = make_agent(FakeCore())
    agent.handle(server_message(json.dumps(SCHEDULE).encode()))
    message = agent.next_message()
    assert not message.HasField("effective_config")


def test_new_local_sources_mark_the_effective_config_dirty():
    core = FakeCore()
    agent = make_agent(core)
    agent.server_capabilities = constants.SERVER_ACCEPTS_EFFECTIVE_CONFIG
    agent.next_message()

    core.sources = {"/var/osquery/osquery.conf": "{}"}
    agent.refresh_state(force=True)
    assert agent.next_message().HasField("effective_config")


# -- state snapshot and conflicts -----------------------------------------


def test_health_reports_what_the_daemon_is_actually_running():
    core = FakeCore(
        schedule=[
            {"name": "battery_stats", "interval": "30", "executions": "4", "denylisted": "0"},
            {"name": "pack_query", "interval": "300", "executions": "1", "denylisted": "0"},
        ],
        packs=[{"name": "main", "active": "1"}],
    )
    agent = make_agent(core)
    agent.refresh_state(force=True)
    attrs = attributes_of(agent.next_message().health)

    assert attrs["osquery.config_plugin"] == "filesystem"
    assert attrs["osquery.schedule_query_count"] == 2
    assert attrs["osquery.pack_count"] == 1
    assert attrs["osquery.schedule"] == ["battery_stats@30", "pack_query@300"]
    assert "osquery.schedule_duplicates" not in attrs


def test_duplicate_query_names_are_reported_as_a_conflict():
    """Two config sources defining one query name produce two live schedules."""
    core = FakeCore(
        schedule=[
            {"name": "battery_stats", "interval": "30", "executions": "0", "denylisted": "0"},
            {"name": "battery_stats", "interval": "5", "executions": "0", "denylisted": "0"},
        ]
    )
    agent = make_agent(core)

    agent.handle(server_message(json.dumps(SCHEDULE).encode()))

    assert agent.remote_config_status == opamp.RemoteConfigStatuses_APPLIED
    assert agent.health.status == "config_conflict"
    assert "battery_stats" in agent.health.last_error
    assert attributes_of(agent.next_message().health)["osquery.schedule_duplicates"] == [
        "battery_stats"
    ]


def test_state_snapshot_is_read_on_an_interval_not_on_every_message():
    now = [1000.0]
    core = FakeCore(schedule=[{"name": "q", "interval": "30", "executions": "0"}])
    agent = make_agent(core, state_interval=60.0, clock=lambda: now[0])

    agent.next_message()
    reads = core.schedule_reads
    now[0] += 30
    agent.next_message()
    assert core.schedule_reads == reads, "a 30s heartbeat must not re-read the schedule"

    now[0] += 31
    agent.next_message()
    assert core.schedule_reads > reads


def test_a_failing_daemon_does_not_clear_the_previous_snapshot():
    class FlakyCore(FakeCore):
        fail = False

        def schedule_state(self):
            if self.fail:
                raise RuntimeError("daemon went away")
            return super().schedule_state()

    core = FlakyCore(schedule=[{"name": "q", "interval": "30", "executions": "0"}])
    agent = make_agent(core)
    agent.refresh_state(force=True)
    assert agent.schedule_state

    core.fail = True
    agent.refresh_state(force=True)
    assert agent.schedule_state, "a transient failure must not blank the server's view"


def test_snapshot_exposes_the_new_fields():
    core = FakeCore(sources={"/var/osquery/osquery.conf": "{}"}, plugin="filesystem")
    agent = make_agent(core)
    agent.refresh_state(force=True)
    snapshot = agent.snapshot()

    assert snapshot["config_plugin"] == "filesystem"
    assert snapshot["config_sources"] == ["/var/osquery/osquery.conf"]
    assert snapshot["duplicate_queries"] == []
