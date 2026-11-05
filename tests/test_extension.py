"""The extension must register, push config, and survive the daemon's pings.

These are the behaviours the whole design rests on, so they are tested against a
real daemon rather than a mock:

* ``registerExtension`` is accepted from a non-C++ process.
* ``call("config", "update", ...)`` actually changes the live schedule.
* the extension stays registered (the daemon pings it every
  ``--extensions_interval`` and drops it after two failures).
* a rejected config is reported as a failure, not silently swallowed.
"""

from __future__ import annotations

import time



def test_extension_registers_and_is_visible(extension, daemon):
    assert extension.uuid > 0
    assert extension.socket_path == f"{daemon.socket}.{extension.uuid}"

    from osquery_opamp.osquery_thrift import make_manager_client

    client = make_manager_client(daemon.socket)
    registered = dict(client.extensions())
    assert extension.uuid in registered
    info = registered[extension.uuid]
    assert info.name == "opamp"


def test_pushed_config_lands_in_the_live_schedule(extension):
    result = extension.push_config(
        "opamp",
        {
            "schedule": {
                "opamp_pushed": {
                    "query": "select 1 as n from osquery_info;",
                    "interval": 300,
                }
            }
        },
    )
    assert result.ok, result.message

    names = {row["name"] for row in extension.core.scheduled_queries()}
    assert "opamp_pushed" in names


def test_pushed_config_is_reported_as_applied_by_the_daemon(extension):
    before = extension.core.osquery_info()
    result = extension.push_config(
        "opamp",
        {"schedule": {"second": {"query": "select 2 as n from osquery_info;", "interval": 300}}},
    )
    assert result.ok, result.message
    after = extension.core.osquery_info()

    assert after["config_valid"] == "1"
    assert after["config_hash"] != before["config_hash"], "config hash should change on apply"


def test_malformed_json_is_rejected(extension):
    """The one failure mode Config::update() actually reports."""
    result = extension.core.push_config_raw("opamp", "{this is not json")
    assert not result.ok
    assert result.status == "FAILED"
    assert "parsing the config JSON" in result.message


def test_semantically_broken_config_is_accepted_by_osquery(extension):
    """Pins real osquery behaviour, so a change in it shows up as a test failure.

    osquery applies config structure eagerly and validates SQL only at execution
    time, so a query naming a table that does not exist is *accepted*. This is
    why an OpAMP ``APPLIED`` status must not be presented to users as "the
    config is correct" - see docs/opamp-contract.md.
    """
    result = extension.push_config(
        "opamp", {"schedule": {"bad_table": {"query": "select * from nope;", "interval": 300}}}
    )
    assert result.ok, result.message
    assert "bad_table" in {row["name"] for row in extension.core.scheduled_queries()}


def test_extension_survives_daemon_pings(extension, daemon):
    """The daemon pings every extensions_interval and drops us after 2 misses."""
    from osquery_opamp.osquery_thrift import make_manager_client

    # Two ping intervals plus margin: this is exactly the window in which an
    # extension that never serves its socket gets deregistered.
    time.sleep(8)

    client = make_manager_client(daemon.socket)
    assert extension.uuid in dict(client.extensions()), "extension was deregistered"
    assert extension.service.ping_count >= 2, (
        f"daemon never pinged the extension (count={extension.service.ping_count})"
    )


def test_config_source_is_merged_not_replaced(extension, daemon):
    """A pushed source coexists with the daemon's own config plugin source."""
    assert extension.push_config(
        "opamp", {"schedule": {"from_opamp": {"query": "select 3 as n from osquery_info;", "interval": 300}}}
    ).ok

    # Re-pushing the same source replaces it wholesale (per-source semantics).
    assert extension.push_config(
        "opamp", {"schedule": {"from_opamp_v2": {"query": "select 4 as n from osquery_info;", "interval": 300}}}
    ).ok

    names = {row["name"] for row in extension.core.scheduled_queries()}
    assert "from_opamp_v2" in names
    assert "from_opamp" not in names, "sources are replaced per source name, not merged key-wise"


def test_genconfig_serves_the_cached_config(extension, daemon):
    """--config_plugin=opamp (pull mode) is answered from the pushed config."""
    from osquery_opamp.osquery_thrift import EXT_FAILED, make_manager_client

    client = make_manager_client(daemon.socket)

    # Before any config is pushed the plugin must fail cleanly, so osquery falls
    # back to its own handling instead of loading an empty config silently. The
    # fixture runs with pull_wait=0 to keep this immediate; the waiting
    # behaviour gets its own test below.
    response = client.call(
        "config", "opamp", {"action": "genConfig", "source": "opamp"}
    )
    assert response.status.code == EXT_FAILED

    extension.push_config("opamp", {"schedule": {"x": {"query": "select 1 from osquery_info;", "interval": 300}}})

    response = client.call("config", "opamp", {"action": "genConfig", "source": "opamp"})
    assert response.status.code == 0
    assert response.response and "opamp" in response.response[0]


def test_genconfig_answers_a_request_with_no_source(extension, daemon):
    """osquery sends no ``source`` when this extension is the active config plugin.

    ``Config::refresh()`` calls ``Registry::call("config", {{"action",
    "genConfig"}})`` - there is no source key - so the extension has to know
    which source it serves.
    """
    from osquery_opamp.osquery_thrift import make_manager_client

    extension.push_config("opamp", {"schedule": {"sourceless": {"query": "select 1 from osquery_info;", "interval": 300}}})

    response = make_manager_client(daemon.socket).call("config", "opamp", {"action": "genConfig"})
    assert response.status.code == 0
    assert "sourceless" in response.response[0]["opamp"]


def test_genconfig_waits_for_a_config_that_is_still_in_flight(daemon):
    """A cold daemon must not fail just because OpAMP is 300ms behind.

    This is the race ``--config_plugin=opamp`` actually loses: osquery asks for
    config during its own initialisation, while the OpAMP round-trip is still in
    progress.
    """
    import threading
    import time

    from osquery_opamp.extension import OsqueryExtension
    from osquery_opamp.osquery_thrift import make_manager_client

    ext = OsqueryExtension(daemon.socket, version="0.1.0", pull_wait=5.0)
    ext.start()
    try:
        timer = threading.Timer(
            0.3,
            lambda: ext.service.set_config(
                "opamp", {"schedule": {"late": {"query": "select 1 from osquery_info;", "interval": 300}}}
            ),
        )
        timer.start()

        started = time.monotonic()
        response = make_manager_client(daemon.socket).call(
            "config", "opamp", {"action": "genConfig", "source": "opamp"}
        )
        waited = time.monotonic() - started
    finally:
        ext.stop()

    assert response.status.code == 0
    assert "late" in response.response[0]["opamp"]
    assert 0.2 <= waited < 5.0, f"genConfig returned after {waited:.2f}s; the wait did not happen"


def test_genconfig_gives_up_after_the_wait(daemon):
    """Bounded, not infinite: a daemon start must not hang on a dead OpAMP server."""
    import time

    from osquery_opamp.extension import OsqueryExtension
    from osquery_opamp.osquery_thrift import EXT_FAILED, make_manager_client

    ext = OsqueryExtension(daemon.socket, version="0.1.0", pull_wait=0.3)
    ext.start()
    try:
        started = time.monotonic()
        response = make_manager_client(daemon.socket).call(
            "config", "opamp", {"action": "genConfig", "source": "opamp"}
        )
        waited = time.monotonic() - started
    finally:
        ext.stop()

    assert response.status.code == EXT_FAILED
    assert "waited" in response.status.message
    assert waited >= 0.25


def test_config_plugin_opamp_serves_the_schedule_at_boot(tmp_path):
    """End to end: `osqueryd --config_plugin=opamp` gets its config from us.

    osquery resolves the active config plugin before it loads configuration, so
    the extension must be registered by then. `--extensions_require` makes the
    daemon wait inside `startExtensionManager()`, which runs first.

    Without it this is not a degraded mode, it is a dead daemon. Measured on
    5.24.0: `initActivePlugin("config", "opamp")` fails with "Cannot activate
    opamp config plugin: Unknown registry plugin: opamp", `requestShutdown` is
    called, and osqueryd exits before it ever loads a config. `--config_refresh`
    defaults to 0, so even a daemon that survived would not retry.
    """
    import tempfile
    import time
    from pathlib import Path

    from conftest import Daemon
    from osquery_opamp.extension import OsqueryExtension

    root = Path(tempfile.mkdtemp(prefix="osq-pull-"))
    daemon = Daemon(
        root,
        config_plugin="opamp",
        extensions_require="opamp",
        extensions_timeout="30",
    )
    ext = None
    try:
        ext = OsqueryExtension(daemon.socket, version="0.1.0", pull_wait=20.0)
        # Simulate OpAMP delivering config before osqueryd finishes booting. No
        # push: the only way this config can reach the daemon is genConfig.
        ext.service.set_config(
            "opamp",
            {"schedule": {"pulled": {"query": "select 1 as n from osquery_info;", "interval": 300}}},
        )
        ext.start(wait=25.0)

        deadline = time.monotonic() + 20.0
        names = set()
        while time.monotonic() < deadline:
            names = {row["name"] for row in ext.core.scheduled_queries()}
            if "pulled" in names:
                break
            time.sleep(0.2)
    finally:
        if ext is not None:
            ext.stop()
        daemon.stop()

    assert "pulled" in names, "osqueryd booted without the config served by genConfig"


def test_extension_works_under_the_watchdog(tmp_path):
    """The watcher/worker topology, which the rest of the suite skips for speed."""
    import tempfile
    from pathlib import Path

    from conftest import Daemon
    from osquery_opamp.extension import OsqueryExtension

    root = Path(tempfile.mkdtemp(prefix="osq-wd-"))
    daemon = Daemon(root, watchdog=True)
    ext = None
    try:
        daemon.wait_for_socket()
        ext = OsqueryExtension(daemon.socket, version="0.1.0")
        ext.start()
        assert ext.push_config(
            "opamp", {"schedule": {"under_watcher": {"query": "select 1 from osquery_info;", "interval": 300}}}
        ).ok
        names = {row["name"] for row in ext.core.scheduled_queries()}
        assert "under_watcher" in names
        # The worker has a launcher process; the watcher column proves it.
        assert ext.core.osquery_info().get("watcher", "-1") not in ("", "-1")
    finally:
        if ext is not None:
            ext.stop()
        daemon.stop()


def test_core_client_is_safe_under_concurrent_rpcs(extension):
    """Regression: an unlocked Thrift client silently lost config pushes.

    The extension pings the daemon from its liveness thread while the OpAMP
    thread pushes config. thriftpy2 clients own one socket and are not thread
    safe, so without a lock the two interleave and responses are misattributed -
    which looked like "the server's config was never applied".
    """
    import threading

    errors = []
    barrier = threading.Barrier(4)

    def ping_worker():
        barrier.wait()
        for _ in range(25):
            try:
                assert extension.core.ping()
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    def push_worker(source):
        barrier.wait()
        for i in range(10):
            try:
                result = extension.core.push_config(
                    source, {"schedule": {f"{source}_{i}": {"query": "select 1 from osquery_info;", "interval": 300}}}
                )
                if not result.ok:
                    errors.append(AssertionError(result.message))
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [
        threading.Thread(target=ping_worker),
        threading.Thread(target=ping_worker),
        threading.Thread(target=push_worker, args=("conc_a",)),
        threading.Thread(target=push_worker, args=("conc_b",)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)

    assert not errors, f"concurrent RPCs failed: {errors[:3]}"
    names = {row["name"] for row in extension.core.scheduled_queries()}
    assert "conc_a_9" in names and "conc_b_9" in names, "a concurrent push was lost"


def test_registration_retries_past_a_stale_route(monkeypatch):
    """A supervisor restart must not need a human: retry the duplicate."""
    import osquery_opamp.extension as extension_module
    from osquery_opamp.core import CoreError

    attempts = {"n": 0}

    class FakeCore:
        def register(self, **kwargs):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise CoreError("registerExtension failed: Duplicate extension registered")
            return 4242

    ext = extension_module.OsqueryExtension("/tmp/does-not-matter")
    ext.core = FakeCore()
    monkeypatch.setattr(extension_module.time, "sleep", lambda _s: None)

    assert ext._register(wait=0.0, duplicate_wait=5.0) == 4242
    assert attempts["n"] == 3


def test_registration_does_not_retry_a_real_error(monkeypatch):
    """Only duplicates are transient; a bad socket must fail immediately."""
    import osquery_opamp.extension as extension_module
    from osquery_opamp.core import CoreError

    attempts = {"n": 0}

    class FakeCore:
        def register(self, **kwargs):
            attempts["n"] += 1
            raise CoreError("registerExtension failed: socket is not writable")

    ext = extension_module.OsqueryExtension("/tmp/does-not-matter")
    ext.core = FakeCore()
    monkeypatch.setattr(extension_module.time, "sleep", lambda _s: None)

    try:
        ext._register(wait=0.0, duplicate_wait=5.0)
    except CoreError as exc:
        assert "not writable" in str(exc)
    else:
        raise AssertionError("a non-duplicate error must not be retried")
    assert attempts["n"] == 1


# -- reading the daemon back -------------------------------------------------


def test_core_reads_the_config_sources_the_daemon_is_running(extension, daemon):
    """The read side of effective config: filesystem genConfig is a pure read."""
    from osquery_opamp.opamp.configview import config_object_name

    assert extension.core.active_config_plugin() == "filesystem"
    sources = extension.core.config_sources()

    assert list(sources) == [str(daemon.config_path)]
    assert sources[str(daemon.config_path)].strip() == "{}"
    assert config_object_name(str(daemon.config_path)) == "osquery.config.json"


def test_core_does_not_read_a_plugin_with_side_effects(extension, monkeypatch):
    """genConfig on the tls plugin fetches over the network; never call it blind."""
    monkeypatch.setattr(extension.core, "active_config_plugin", lambda: "tls")
    assert extension.core.config_sources() == {}


def test_core_compiles_a_query_without_running_it(extension):
    columns = extension.core.query_columns("select percent_remaining from battery;")
    assert [list(row) for row in columns] == [["percent_remaining"]]


def test_core_query_columns_surfaces_osquery_error_text(extension):
    import pytest as _pytest

    from osquery_opamp.core import CoreError

    with _pytest.raises(CoreError) as excinfo:
        extension.core.query_columns("select * from batteries;")
    assert "no such table: batteries" in str(excinfo.value)


# -- the agent against a real daemon ----------------------------------------


def _agent_for(extension, **kwargs):
    from osquery_opamp.opamp.agent import OpampAgent

    uid = bytes.fromhex("00112233445566778899aabbccddeeff")
    return OpampAgent(uid, extension.core, extension_version="0.1.0", **kwargs)


def _remote_config(body: bytes):
    from osquery_opamp.opamp import constants
    from osquery_opamp.opamp.pb import opamp

    return opamp.ServerToAgent(
        instance_uid=bytes.fromhex("00112233445566778899aabbccddeeff"),
        remote_config=opamp.AgentRemoteConfig(
            config=opamp.AgentConfigMap(
                config_map={
                    constants.CONFIG_OBJECT_NAME: opamp.AgentConfigObject(
                        body=body, content_type="application/json"
                    )
                }
            )
        ),
    )


def test_agent_refuses_a_scheduled_query_that_cannot_compile(extension):
    """osquery would accept it; the agent is the only thing that can say no."""
    import json

    from osquery_opamp.opamp.pb import opamp

    agent = _agent_for(extension)
    agent.handle(
        _remote_config(
            json.dumps(
                {"schedule": {"ghost": {"query": "select * from no_such_table;", "interval": 30}}}
            ).encode()
        )
    )

    assert agent.remote_config_status == opamp.RemoteConfigStatuses_FAILED
    assert "no such table: no_such_table" in agent.remote_config_error
    assert "ghost" not in {row["name"] for row in extension.core.scheduled_queries()}


def test_agent_reports_local_sources_alongside_the_pushed_config(extension, daemon):
    import json

    from osquery_opamp.opamp import constants

    agent = _agent_for(extension)
    agent.handle(
        _remote_config(
            json.dumps(
                {"schedule": {"pushed": {"query": "select 1 from time;", "interval": 300}}}
            ).encode()
        )
    )
    agent.server_capabilities = constants.SERVER_ACCEPTS_EFFECTIVE_CONFIG

    config_map = agent.next_message().effective_config.config_map.config_map

    assert sorted(config_map) == ["osquery.config.json", "osquery.json"]
    assert json.loads(config_map["osquery.json"].body)["schedule"]["pushed"]
    assert config_map["osquery.config.json"].body.decode().strip() == "{}"


def test_agent_detects_one_query_defined_by_two_config_sources(daemon_with_local_config):
    """A pushed query name that the local file also defines runs twice, silently."""
    import json

    from osquery_opamp.extension import OsqueryExtension
    from osquery_opamp.opamp.pb import opamp

    extension = OsqueryExtension(daemon_with_local_config.socket, version="0.1.0")
    extension.start()
    try:
        assert [row["name"] for row in extension.core.scheduled_queries()] == ["battery_stats"]

        agent = _agent_for(extension)
        agent.handle(
            _remote_config(
                json.dumps(
                    {
                        "schedule": {
                            "battery_stats": {
                                "query": "select percent_remaining from battery;",
                                "interval": 5,
                            }
                        }
                    }
                ).encode()
            )
        )

        assert (
            agent.remote_config_status == opamp.RemoteConfigStatuses_APPLIED
        ), "the config itself is still applied"
        assert agent.duplicate_queries == ["battery_stats"]
        assert agent.health.status == "config_conflict"
        assert "battery_stats" in agent.health.last_error
    finally:
        extension.stop()


def test_a_resolved_duplicate_clears_the_conflict_without_an_apply(
    daemon_with_local_config, monkeypatch
):
    """The operator's fix arrives as a *state* change, not a new config.

    Deleting the local query (or moving the daemon to ``--config_plugin=opamp``) leaves
    the pushed config untouched, so no apply happens — health has to be re-derived in
    ``refresh_state`` or the agent reports `config_conflict` forever and the fleet
    manager's rollout stays paused after the host is clean.
    """
    import json

    from osquery_opamp.extension import OsqueryExtension

    extension = OsqueryExtension(daemon_with_local_config.socket, version="0.1.0")
    extension.start()
    try:
        agent = _agent_for(extension)
        agent.handle(
            _remote_config(
                json.dumps(
                    {
                        "schedule": {
                            "battery_stats": {
                                "query": "select percent_remaining from battery;",
                                "interval": 5,
                            }
                        }
                    }
                ).encode()
            )
        )
        assert agent.health.status == "config_conflict"

        # Only the local schedule is left (the pushed source and the file no longer
        # define the same name), which is what the daemon reports after the fix.
        monkeypatch.setattr(
            extension.core,
            "schedule_state",
            lambda: [
                {
                    "name": "battery_stats",
                    "interval": "5",
                    "query": "select percent_remaining from battery;",
                }
            ],
        )
        agent.refresh_state(force=True)

        assert agent.duplicate_queries == []
        assert agent.health.status == "ok"
        assert agent.health.last_error == ""
    finally:
        extension.stop()


# --------------------------------------- durability: genConfig after a restart

BODY_TEXT = '{"schedule": {"battery_stats": {"query": "SELECT percent_remaining FROM battery;", "interval": 30}}}'
HASH_HEX = "22aa53ff9c3b270753bf4cb01d23ccc7593fbf4e8436ccb4a516cbf35742d576"


def _service(tmp_path, *, body=None, config_hash="", agent_version="0.1.0"):
    from osquery_opamp.configcache import ConfigCache
    from osquery_opamp.extension import ExtensionService

    service = ExtensionService(ConfigCache(tmp_path / "config.json"))
    service.agent_version = agent_version
    if body is not None:
        service.set_config_body("opamp", body, config_hash=config_hash)
    return service


def test_genconfig_survives_an_extension_restart(tmp_path):
    """The whole point: the daemon gets its config back without the OpAMP server.

    Before this, ``genConfig`` answered from a dict in the extension process, so a
    restart (or a host reboot) meant the daemon booted on ``--config_path`` - the
    fleet's config silently reverting to whatever that file held.
    """
    _service(tmp_path, body=BODY_TEXT, config_hash=HASH_HEX)

    # A brand-new process: empty memory, same cache file.
    restarted = _service(tmp_path)
    assert restarted.cached_config("opamp") == BODY_TEXT
    assert restarted.cached_entry().config_hash == HASH_HEX


def test_genconfig_serves_the_cached_body_through_a_real_daemon(daemon, tmp_path):
    """End to end: a fresh extension answers ``genConfig`` from disk, no push."""
    from osquery_opamp.configcache import ConfigCache
    from osquery_opamp.extension import OsqueryExtension
    from osquery_opamp.osquery_thrift import make_manager_client

    _service(tmp_path, body=BODY_TEXT, config_hash=HASH_HEX)

    ext = OsqueryExtension(
        daemon.socket, version="0.1.0", config_cache=ConfigCache(tmp_path / "config.json")
    )
    ext.start()
    try:
        response = make_manager_client(daemon.socket).call(
            "config", "opamp", {"action": "genConfig"}
        )
        assert response.status.code == 0
        assert response.response[0]["opamp"] == BODY_TEXT, (
            "the cached body must be served byte for byte, not re-serialised"
        )
    finally:
        ext.stop()


def test_a_new_body_drops_the_stale_hash(tmp_path):
    """A hash describes one body. Keeping it next to a different body is a lie."""
    service = _service(tmp_path, body=BODY_TEXT, config_hash=HASH_HEX)
    service.set_config_body("opamp", '{"schedule": {}}')
    entry = service.cached_entry()
    assert entry.body == '{"schedule": {}}'
    assert entry.config_hash == "", "the old hash must not be attached to a new body"


def test_resending_the_same_body_keeps_the_hash(tmp_path):
    """The server re-offers with the hash it already acked; that is not a new hash."""
    service = _service(tmp_path, body=BODY_TEXT, config_hash=HASH_HEX)
    service.set_config_body("opamp", BODY_TEXT)
    assert service.cached_entry().config_hash == HASH_HEX


def test_memory_is_preferred_and_disk_is_the_fallback(tmp_path):
    service = _service(tmp_path, body=BODY_TEXT, config_hash=HASH_HEX)
    assert service.cached_config("opamp") == BODY_TEXT
    # A different source is not invented from the cache.
    assert service.cached_config("something-else") is None


def test_a_restarted_daemon_is_served_the_cached_config(tmp_path):
    """The failure this whole cache exists for, end to end.

    Boot a `--config_plugin=opamp` daemon, let the extension serve it a config,
    then restart *the daemon* with no OpAMP server, no re-push and no
    ``--config_enable_backup``. Before the cache existed the second boot came up
    with no config (``genConfig`` had nothing to answer with), and a push-mode
    daemon came up on its own ``--config_path`` while the server still showed
    ``APPLIED``.

    Two daemons, same socket, same cache file; the only state carried across is
    what the extension persisted.
    """
    import tempfile
    import time
    from pathlib import Path

    from conftest import Daemon
    from osquery_opamp.configcache import ConfigCache
    from osquery_opamp.extension import OsqueryExtension

    body = '{"schedule": {"from_cache": {"query": "select 1 as n from osquery_info;", "interval": 300}}}'
    cache_path = tmp_path / "config.json"
    root = Path(tempfile.mkdtemp(prefix="osq-restart-"))
    socket_path = root / "osq.em"
    names = set()
    first = second = None
    try:
        daemon = Daemon(
            root, config_plugin="opamp", extensions_require="opamp", extensions_timeout="30"
        )
        first = OsqueryExtension(
            daemon.socket, version="0.1.0", pull_wait=20.0, config_cache=ConfigCache(cache_path)
        )
        # What the OpAMP apply path does: remember, then let genConfig serve it.
        first.service.set_config_body("opamp", body, config_hash=HASH_HEX)
        first.start(wait=25.0)

        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if "from_cache" in {row["name"] for row in first.core.scheduled_queries()}:
                break
            time.sleep(0.2)
        assert ConfigCache(cache_path).load().body == body
        first.stop()
        first = None
        daemon.stop()

        # Fresh daemon, fresh extension process state: only the file survives.
        socket_path.unlink(missing_ok=True)
        daemon = Daemon(
            root, config_plugin="opamp", extensions_require="opamp", extensions_timeout="30"
        )
        assert ConfigCache(cache_path).load() is not None
        second = OsqueryExtension(
            daemon.socket, version="0.1.0", pull_wait=20.0, config_cache=ConfigCache(cache_path)
        )
        second.start(wait=25.0)

        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            names = {row["name"] for row in second.core.scheduled_queries()}
            if "from_cache" in names:
                break
            time.sleep(0.2)
    finally:
        for ext in (first, second):
            if ext is not None:
                try:
                    ext.stop()
                except Exception:
                    pass
        try:
            daemon.stop()
        except Exception:
            pass

    assert "from_cache" in names, (
        "the restarted daemon booted without the cached config; genConfig did not serve it"
    )


# --------------------------------------- supervision: the daemon restarts

class _FakeCore:
    """Just enough CoreClient to drive registration and ping behaviour."""

    def __init__(self, register=None, pings=None, on_exhausted=None, routes=None):
        self.registered = 0
        self.deregistered = []
        self.pings = list(pings or [])
        self._register = register
        self._on_exhausted = on_exhausted
        # None means "the daemon always knows us"; a list is the set of route uuids
        # the fake daemon holds, so a restart can be simulated.
        self.routes = routes

    def register(self, **kwargs):
        self.registered += 1
        if callable(self._register):
            return self._register(self.registered)
        if isinstance(self._register, Exception):
            raise self._register
        return 1 if self._register is None else self._register

    def deregister(self, uuid):
        self.deregistered.append(uuid)

    def ping(self):
        if not self.pings:
            if self._on_exhausted is not None:
                self._on_exhausted()
            return True
        return self.pings.pop(0)

    def is_registered(self, uuid):
        if self.routes is None:
            return True
        return int(uuid) in self.routes

    def active_config_plugin(self):
        return ""


def _extension(**kwargs):
    from osquery_opamp.extension import OsqueryExtension

    return OsqueryExtension("/tmp/does-not-exist.osq.em", sdk_version="5.24.0", **kwargs)


def test_a_live_duplicate_fails_with_the_reason_and_the_fix():
    """Twenty seconds of "retrying" then a bare exception is not a usable failure."""
    import pytest as _pytest

    from osquery_opamp.core import CoreError

    ext = _extension()
    ext.core = _FakeCore(register=RuntimeError("Duplicate extension registered"))
    with _pytest.raises(CoreError) as caught:
        ext._register(wait=0.3)
    message = str(caught.value).lower()
    assert "another copy" in message
    assert "stop that process" in message


def test_the_duplicate_wait_is_the_startup_budget():
    """--startup-timeout has to cover both failure modes, or a restart loop is unexplainable."""
    import pytest as _pytest
    import time as _time

    from osquery_opamp.core import CoreError

    ext = _extension()
    ext.core = _FakeCore(register=RuntimeError("Duplicate extension registered"))
    started = _time.monotonic()
    with _pytest.raises(CoreError):
        ext._register(wait=0.6)
    elapsed = _time.monotonic() - started
    assert elapsed >= 0.6
    assert elapsed < 5.0


def test_registration_recovers_when_the_daemon_drops_the_old_route():
    """A crashed previous process is a few seconds of duplicates, then success."""
    ext = _extension()

    def flaky(attempt):
        if attempt <= 2:
            raise RuntimeError("Duplicate extension registered")
        return 42

    ext.core = _FakeCore(register=flaky)
    assert ext._register(wait=10) == 42
    assert ext.core.registered == 3


def _run_ping_loop(ext, pings, timeout: float = 5.0):
    """Drive ``_ping_loop`` in a thread and stop it once the scripted answers run out.

    Stopping the *thread* is not the daemon asking us to stop, which is exactly the
    distinction these tests are about - hence ``request_stop`` on the extension
    rather than the scripted ping consuming ``_stopping``.
    """
    import threading

    done = threading.Event()
    ext.core = _FakeCore(pings=pings, on_exhausted=done.set)
    thread = threading.Thread(target=ext._ping_loop, daemon=True)
    thread.start()
    assert done.wait(timeout), "the ping loop never consumed the scripted answers"
    ext.request_stop()
    thread.join(timeout=5.0)


def test_one_failed_ping_does_not_tear_down_a_registration():
    """An RPC that timed out under load is not a dead daemon."""
    ext = _extension(ping_interval=0.01)
    calls = []
    ext._reregister = lambda: calls.append(1) or True

    _run_ping_loop(ext, [False, True, True])

    assert calls == []
    assert ext.service.shutdown_requested is False


def test_two_failed_pings_reregister_instead_of_exiting():
    ext = _extension(ping_interval=0.01)
    calls = []
    ext._reregister = lambda: (calls.append(1), True)[1]

    _run_ping_loop(ext, [False, False])

    assert calls == [1]
    assert ext.service.shutdown_requested is False, "a restarted daemon is not a reason to exit"


def test_a_daemon_that_dropped_our_route_triggers_reregistration():
    """The restart a ping cannot see: new process, answering, no idea we exist."""
    import threading

    ext = _extension(ping_interval=0.01)
    calls = []
    ext._reregister = lambda: (calls.append(1), True)[1]
    ext.uuid = 5000

    done = threading.Event()
    # The daemon answers every ping, but its route table is empty: this is what a
    # restarted daemon looks like from here, and it is why ping() alone is not enough.
    ext.core = _FakeCore(pings=[True, True], on_exhausted=done.set, routes=set())
    assert ext._daemon_knows_us() is False

    thread = threading.Thread(target=ext._ping_loop, daemon=True)
    thread.start()
    assert done.wait(5.0)
    ext.request_stop()
    thread.join(timeout=5.0)

    assert calls, "an answering daemon without our route is a restarted daemon"


def test_a_failed_reregistration_finally_stops_the_extension():
    """If the daemon never comes back, exiting is the honest end state."""
    ext = _extension(ping_interval=0.01)
    ext._reregister = lambda: False
    ext.core = _FakeCore(pings=[False, False])

    ext._ping_loop()

    assert ext.shutdown_requested is True


def test_reregister_rebinds_the_new_uuid_and_asks_for_full_state(monkeypatch):
    """The old socket path is dead once the uuid changes; serving it is a silent loss."""
    import osquery_opamp.extension as extension_module

    class Server:
        def serve(self):
            return

        def close(self):
            return

    monkeypatch.setattr(extension_module, "make_extension_server", lambda path, service: Server())
    monkeypatch.setattr(extension_module, "poke_extension_socket", lambda path: None)
    monkeypatch.setattr(extension_module, "close_extension_socket", lambda path: None)

    ext = _extension()
    ext.core = _FakeCore(register=777)
    state = []
    ext.on_reregistered = lambda: state.append("full state")

    assert ext._reregister() is True
    assert ext.uuid == 777
    assert ext.service.uuid == 777, "answers must carry the uuid the daemon now knows us by"
    assert ext.socket_path.endswith(".777")
    assert state == ["full state"]


def test_the_extension_reregisters_after_a_daemon_restart(tmp_path):
    """The real thing: a daemon restart must not take the agent with it.

    Before this, the first failed ping called ``request_stop()``, so
    ``osqueryctl restart`` killed the agent - and a daemon started with
    ``--extensions_require=opamp`` then exited because nothing registered. With the
    restart below there is no re-launch and no re-push: the same process has to
    notice, re-register and rebind its socket.
    """
    import tempfile
    import time
    from pathlib import Path

    from conftest import Daemon
    from osquery_opamp.extension import OsqueryExtension
    from osquery_opamp.osquery_thrift import make_manager_client

    root = Path(tempfile.mkdtemp(prefix="osq-rereg-"))
    socket_path = root / "osq.em"
    first_uuid = 0
    ext = None
    second = None
    try:
        first = Daemon(root)
        first.wait_for_socket()
        ext = OsqueryExtension(first.socket, version="0.1.0", ping_interval=0.3)
        ext.start()
        first_uuid = ext.uuid

        first.stop()
        socket_path.unlink(missing_ok=True)

        second = Daemon(root)
        second.wait_for_socket()

        deadline = time.monotonic() + 25.0
        while time.monotonic() < deadline:
            if ext.uuid != first_uuid and ext.core.is_registered(ext.uuid):
                break
            time.sleep(0.2)

        assert ext.uuid != first_uuid, "the extension kept the uuid of the daemon that died"
        assert ext.service.uuid == ext.uuid
        assert ext.shutdown_requested is False
        assert ext.uuid in dict(make_manager_client(second.socket).extensions())
    finally:
        if ext is not None:
            try:
                ext.stop()
            except Exception:
                pass
        if second is not None:
            second.stop()
