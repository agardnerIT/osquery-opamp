"""The OpAMP agent state machine.

Pure logic: no sockets, no threads, no osquery calls of its own. Everything that
touches the outside world is injected (``core`` for config pushes and reads,
``query_runner`` for ad-hoc SQL), which is what makes the protocol behaviour
testable without a daemon or a server.

Responsibilities:

* own ``sequence_num`` (increments on every ``AgentToServer``, starts at 1)
* decide what goes into each message (the spec allows omitting unchanged
  sub-messages; we report on change, on heartbeat, or when asked with
  ``ReportFullState``)
* apply remote config and produce an honest ``RemoteConfigStatus``
* reject a config whose scheduled queries cannot compile, because osquery
  itself will not (``Config::update()`` accepts them and fails later, at
  execution time)
* report an effective config that includes the config sources the daemon is
  running besides our own, when the active plugin can be read safely
* notice when the daemon ends up with two queries of the same name, which is
  what happens when a pushed source and a local file both define one
* answer ``com.osquery.query`` custom messages

Deliberate omissions, all advertised honestly via the capability bitmask:

* no packages (osquery has none)
* no telemetry (``own_metrics``/``own_traces``/``own_logs``)
* no ``RESTART``: an osquery extension has no RPC that restarts the daemon, so
  ``AcceptsRestartCommand`` is not advertised and an inbound restart is refused
  rather than silently dropped.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import constants
from .configview import PRIMARY_OBJECT_NAME, source_documents
from .description import build_description, kv
from .pb import opamp

log = logging.getLogger(__name__)

QueryRunner = Callable[[str], Tuple[List[Dict[str, str]], Optional[str]]]

#: How many scheduled queries one push will pre-compile. Each one is an RPC, and
#: the whole check runs on the OpAMP thread, so a pathological config must not be
#: able to stall heartbeats. Above this the config is pushed unchecked and the
#: gap is logged.
MAX_QUERIES_VALIDATED = 200

#: How often the schedule/pack snapshot is refreshed, in seconds. The snapshot
#: rides along with health, so this is the staleness bound on "what is actually
#: running" as seen by the server.
DEFAULT_STATE_INTERVAL = 60.0

#: Sentinel meaning "the read failed", as opposed to "the answer was empty".
_FAILED = object()


@dataclass
class Health:
    healthy: bool = True
    status: str = "ok"
    last_error: str = ""
    changed_at: float = field(default_factory=time.time)


class OpampAgent:
    """Protocol state for one agent instance."""

    def __init__(
        self,
        instance_uid: bytes,
        core: Any,
        *,
        source: str = constants.DEFAULT_SOURCE,
        service_name: str = "osqueryd",
        extension_version: Optional[str] = None,
        commands_enabled: bool = False,
        query_runner: Optional[QueryRunner] = None,
        identity_store: Any = None,
        sdk_version_source: str = "",
        validate_queries: bool = True,
        state_interval: float = DEFAULT_STATE_INTERVAL,
        config_service: Any = None,
        pull_mode: bool = False,
        clock: Callable[[], float] = time.time,
    ) -> None:
        constants.capabilities_sanity_check()

        self.instance_uid = instance_uid
        self.core = core
        self.source = source
        self.service_name = service_name
        self.extension_version = extension_version
        self.commands_enabled = commands_enabled
        self.query_runner = query_runner
        self.identity_store = identity_store
        self.sdk_version_source = sdk_version_source
        self.validate_queries = validate_queries
        self.state_interval = state_interval
        self._clock = clock

        self.sequence_num = 0
        self.server_capabilities = 0

        # Remote config state
        self.last_remote_config_hash: bytes = b""
        self.remote_config_status: int = opamp.RemoteConfigStatuses_UNSET
        self.remote_config_error: str = ""
        self._status_dirty = False
        self._applied_body: Optional[bytes] = None
        self._applied_config: Optional[Dict[str, Any]] = None

        # Durability (see ``configcache``): ``config_service`` is the
        # ``ExtensionService`` that answers ``genConfig``, so the two must agree
        # about the body. ``pull_mode`` means the daemon's active config plugin is
        # this extension, which is what makes adopting the cached metadata safe.
        self.config_service = config_service
        self.pull_mode = pull_mode

        self.health = Health()
        self.start_time_unix_nano = int(clock() * 1_000_000_000)

        # The daemon's own state, refreshed on an interval and reported with
        # health. Empty until the first successful read.
        self.config_plugin: str = ""
        self.schedule_state: List[Dict[str, str]] = []
        self.packs_state: List[Dict[str, str]] = []
        self.config_sources: Dict[str, str] = {}
        self.duplicate_queries: List[str] = []
        self._state_deadline: float = 0.0

        # What needs to go out in the next message
        self._full_state_needed = True
        self._description_dirty = True
        self._health_dirty = True
        self._effective_config_dirty = True
        self._status_dirty = True

        self._ignored_uid_messages = 0

        self._restore_cached_config()

    # -- durability --------------------------------------------------------

    def _restore_cached_config(self) -> None:
        """Adopt the config the previous process applied, before the first message.

        Only in **pull mode**, and only because that is the one mode where the claim
        is verifiable: the daemon's config plugin is this extension, so a boot asks
        ``genConfig`` and is answered from this same cache. Reporting ``APPLIED``
        with the stored hash then means exactly what the spec says - the agent is
        running that config - and it stops the server from re-delivering a config
        the fleet already has (and from counting the restart against
        ``CONFIG_MAX_DELIVERY_ATTEMPTS``).

        In push mode (``--config_plugin=filesystem``, our body merged as a source)
        nothing is adopted: a restarted daemon re-read its file and does *not* have
        our config, so the honest state is ``UNSET`` and the server must re-deliver.
        The body is still cached there, because switching the daemon to pull mode
        should not require re-pushing the fleet first.
        """
        service = self.config_service
        if service is None or not self.pull_mode:
            return
        where = getattr(service, "cache_path", "the config cache")
        try:
            entry = service.cached_entry()
        except Exception as exc:  # noqa: BLE001 - a cache must never block startup
            log.warning("could not read the config cache: %s", exc)
            return
        if entry is None:
            log.info("no cached config yet (%s); waiting for the OpAMP server", where)
            return
        try:
            parsed = json.loads(entry.body)
        except ValueError as exc:
            log.warning(
                "cached config in %s is not valid JSON (%s); ignoring it",
                where,
                exc,
            )
            return
        if not isinstance(parsed, dict):
            log.warning("cached config in %s is not a JSON object; ignoring it", where)
            return

        self._applied_body = entry.body.encode("utf-8")
        self._applied_config = parsed
        self._effective_config_dirty = True

        if not entry.config_hash:
            log.info(
                "restored %d bytes of config from %s for genConfig, but no OpAMP hash "
                "was stored; status stays UNSET until the server sends one",
                len(self._applied_body),
                where,
            )
            return
        try:
            self.last_remote_config_hash = bytes.fromhex(entry.config_hash)
        except ValueError:
            log.warning(
                "cached config hash %r is not hex; reporting UNSET instead",
                entry.config_hash,
            )
            return

        self.remote_config_status = opamp.RemoteConfigStatuses_APPLIED
        self.remote_config_error = ""
        self._status_dirty = True
        log.info(
            "restored config from %s (%d bytes, hash=%s, applied %s); the daemon is "
            "served this at boot and APPLIED is reported without waiting for the server",
            where,
            len(self._applied_body),
            entry.config_hash[:16],
            entry.applied_at or "unknown",
        )

    def _remember(self, body: bytes, report_hash: bytes, content_type: str = "") -> None:
        """Persist the body the daemon just accepted, for the next restart.

        Called only after ``Config::update()`` returned OK, so the cache never holds
        a config the daemon rejected. Every failure is a log line: durability is
        best effort, and an applied config is not un-applied because a disk is full.
        """
        if self.config_service is None:
            return
        try:
            self.config_service.set_config_body(
                self.source,
                body.decode("utf-8"),
                content_type=content_type or constants.CONFIG_CONTENT_TYPE,
                config_hash=report_hash.hex() if report_hash else "",
            )
        except Exception as exc:  # noqa: BLE001 - never fail an applied config
            log.warning("could not cache the applied config for the next restart: %s", exc)

    # -- outbound ----------------------------------------------------------

    def capabilities(self) -> int:
        return constants.AGENT_CAPABILITIES

    def request_full_state(self) -> None:
        self._full_state_needed = True
        self._description_dirty = True
        self._health_dirty = True
        self._effective_config_dirty = True
        self._status_dirty = True

    def next_message(self) -> Any:
        """Build the next ``AgentToServer``, consuming the dirty flags."""
        self.refresh_state()
        self.sequence_num += 1
        message = opamp.AgentToServer(
            instance_uid=self.instance_uid,
            sequence_num=self.sequence_num,
            capabilities=self.capabilities(),
        )

        if self.commands_enabled:
            message.custom_capabilities.capabilities.append(constants.QUERY_CAPABILITY)

        full = self._full_state_needed
        if full or self._description_dirty:
            message.agent_description.CopyFrom(self._build_description())
            self._description_dirty = False

        if full or self._health_dirty:
            message.health.CopyFrom(self._build_health())
            self._health_dirty = False

        if (full or self._effective_config_dirty) and self._wants_effective_config():
            message.effective_config.CopyFrom(self._build_effective_config())
            self._effective_config_dirty = False

        if full or self._status_dirty:
            if self.remote_config_status != opamp.RemoteConfigStatuses_UNSET:
                message.remote_config_status.CopyFrom(
                    opamp.RemoteConfigStatus(
                        last_remote_config_hash=self.last_remote_config_hash,
                        status=self.remote_config_status,
                        error_message=self.remote_config_error,
                    )
                )
            self._status_dirty = False

        self._full_state_needed = False
        return message

    def disconnect_message(self) -> Any:
        """The final message, per the spec."""
        self.sequence_num += 1
        return opamp.AgentToServer(
            instance_uid=self.instance_uid,
            sequence_num=self.sequence_num,
            capabilities=self.capabilities(),
            agent_disconnect=opamp.AgentDisconnect(),
        )

    # -- inbound -----------------------------------------------------------

    def handle(self, message: Any) -> List[Any]:
        """Apply a ``ServerToAgent``; return any custom messages to send back."""
        if message.instance_uid and message.instance_uid != self.instance_uid:
            # The spec requires the server to echo our uid; a mismatch means the
            # message is addressed to a different agent on a multiplexed
            # connection.
            self._ignored_uid_messages += 1
            log.debug("ignoring ServerToAgent for a different instance_uid")
            return []

        # uint64 fields are proto3 scalars and have no presence, so this is a
        # value check, not HasField.
        if message.capabilities:
            self.server_capabilities = message.capabilities

        if message.flags & opamp.ServerToAgentFlags_ReportFullState:
            log.debug("server requested full state")
            self.request_full_state()

        if message.HasField("error_response"):
            err = message.error_response
            log.warning(
                "server error response type=%s: %s", err.type, err.error_message
            )
            self._set_health(False, "server_error", err.error_message)

        if message.HasField("agent_identification") and message.agent_identification.new_instance_uid:
            self._adopt_uid(message.agent_identification.new_instance_uid)

        if message.HasField("remote_config"):
            self._apply_remote_config(message.remote_config)

        if message.HasField("command"):
            # CommandType_Restart is the only defined command, and value 0, so a
            # present command message always means restart.
            self._refuse_restart()

        if message.HasField("custom_message"):
            return self._handle_custom_message(message.custom_message)

        return []

    # -- remote config -----------------------------------------------------

    def _apply_remote_config(self, remote_config: Any) -> None:
        entries = dict(remote_config.config.config_map)
        if not entries:
            self._fail("remote config contained no configuration objects")
            return

        name = constants.CONFIG_OBJECT_NAME
        if name not in entries:
            json_entries = [k for k in entries if k.endswith(".json")]
            if len(json_entries) != 1:
                self._fail(
                    "expected a single "
                    f"{constants.CONFIG_OBJECT_NAME} object, got {sorted(entries)}"
                )
                return
            name = json_entries[0]

        obj = entries[name]
        content_type = (obj.content_type or "").strip().lower()
        if content_type and content_type != constants.CONFIG_CONTENT_TYPE:
            self._fail(f"unsupported content_type {obj.content_type!r} for {name}")
            return

        body = bytes(obj.body)
        computed = hashlib.sha256(body).digest()
        # config_hash is server-defined: the reference server hashes a canonical
        # encoding of the whole config map, not the body, so a body hash will not
        # match and comparing them proves nothing. Use the server's value verbatim
        # (that is what it correlates on) and only compute our own when absent.
        report_hash = bytes(remote_config.config_hash) if remote_config.config_hash else computed

        if (
            report_hash
            and report_hash == self.last_remote_config_hash
            and self.remote_config_status == opamp.RemoteConfigStatuses_APPLIED
        ):
            # Desired-state servers re-offer the active config on every reply.
            # Re-applying it churns the daemon's config hash and status logs for
            # no reason; the spec gives us the hash precisely to detect this.
            log.debug("remote config unchanged (hash=%s); not re-applying", report_hash.hex()[:16])
            # Re-offered after a restart (ours or the daemon's): make sure the cache
            # describes it, so the next boot can be served it even if this process
            # was the one that came back without one.
            self._remember(body, report_hash, content_type)
            self._effective_config_dirty = True
            return

        # Validate JSON before claiming anything applied: osquery itself only
        # rejects unparseable JSON, and we want the failure attributed correctly.
        try:
            parsed = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            self._fail(f"config body is not valid JSON: {exc}", report_hash)
            return

        if not isinstance(parsed, dict):
            self._fail("config body must be a JSON object", report_hash)
            return

        # Reject a config the daemon would accept and then fail on at execution
        # time. ``Config::update()`` validates structure only, so this is the
        # only place a broken scheduled query can be caught *before* the server
        # is told the config is fine.
        invalid = self.validate_config(parsed)
        if invalid:
            self._fail(invalid, report_hash)
            return

        self.last_remote_config_hash = report_hash
        self.remote_config_status = opamp.RemoteConfigStatuses_APPLYING
        self.remote_config_error = ""
        self._status_dirty = True

        result = self.core.push_config_raw(self.source, body.decode("utf-8"))
        if not result.ok:
            self._fail(f"osquery rejected the config: {result.message}", report_hash)
            return

        self._applied_body = body
        self._applied_config = parsed
        # The daemon accepted it, so this is the body a restart must be served.
        self._remember(body, report_hash, content_type)
        self.remote_config_status = opamp.RemoteConfigStatuses_APPLIED
        self.remote_config_error = ""
        self._status_dirty = True
        self._effective_config_dirty = True
        # Refresh immediately: the server asked for this config, so the next
        # message should tell it what the daemon now has, not what it had up to
        # ``state_interval`` ago.
        self.refresh_state(force=True)
        if self.duplicate_queries:
            self._set_health(
                True,
                "config_conflict",
                "the same query name is scheduled more than once: "
                + ", ".join(self.duplicate_queries)
                + " (a pushed source and a local config source both define it)",
            )
        else:
            self._set_health(True, "ok", "")
        log.info(
            "applied remote config (%d bytes, hash=%s)", len(body), report_hash.hex()[:16]
        )

    # -- config validation -------------------------------------------------

    def validate_config(self, config: Dict[str, Any]) -> str:
        """Return ``""`` if the config's queries compile, else osquery's error.

        Only statements are checked, and only in the two places a config puts
        them: ``schedule`` and inline packs. A pack that names a file path
        rather than an object is left to osquery, and so is everything else -
        this is a compile check, not a schema validator.

        Degrades to "no opinion" when the daemon cannot answer (old osquery, a
        transport error): reporting an APPLIED config is better than refusing
        every push because the check itself broke.
        """
        if not self.validate_queries:
            return ""
        get_columns = getattr(self.core, "query_columns", None)
        if get_columns is None:
            log.debug("core cannot compile queries; skipping config validation")
            return ""

        checks: List[Tuple[str, str]] = []
        schedule = config.get("schedule")
        if isinstance(schedule, dict):
            for name, entry in schedule.items():
                if isinstance(entry, dict) and isinstance(entry.get("query"), str):
                    checks.append((str(name), entry["query"]))

        packs = config.get("packs")
        if isinstance(packs, dict):
            for pack_name, pack in packs.items():
                queries = pack.get("queries") if isinstance(pack, dict) else None
                if not isinstance(queries, dict):
                    continue
                for name, entry in queries.items():
                    if isinstance(entry, dict) and isinstance(entry.get("query"), str):
                        checks.append((f"{pack_name}.{name}", entry["query"]))

        if len(checks) > MAX_QUERIES_VALIDATED:
            log.warning(
                "config has %d scheduled queries; compiling only the first %d"
                " before applying",
                len(checks),
                MAX_QUERIES_VALIDATED,
            )
            checks = checks[:MAX_QUERIES_VALIDATED]

        for name, sql in checks:
            try:
                get_columns(sql)
            except Exception as exc:  # noqa: BLE001 - any failure is a rejection
                return f"scheduled query {name!r} does not compile: {exc}"
        return ""

    # -- state snapshot ----------------------------------------------------

    def refresh_state(self, force: bool = False) -> None:
        """Read the daemon's schedule, packs and config sources, on an interval.

        Everything here is best effort: a daemon that cannot answer leaves the
        previous snapshot in place rather than clearing the server's view.
        """
        now = self._clock()
        if not force and now < self._state_deadline:
            return
        self._state_deadline = now + self.state_interval

        changed = False

        plugin = self._call_core("active_config_plugin", "")
        if plugin is not _FAILED and (plugin or "") != self.config_plugin:
            self.config_plugin = plugin or ""
            changed = True

        schedule = self._call_core("schedule_state", [])
        if schedule is not _FAILED and (schedule or []) != self.schedule_state:
            self.schedule_state = schedule or []
            changed = True

        packs = self._call_core("packs_state", [])
        if packs is not _FAILED and (packs or []) != self.packs_state:
            self.packs_state = packs or []
            changed = True

        sources = self._call_core("config_sources", {})
        if sources is not _FAILED and (sources or {}) != self.config_sources:
            self.config_sources = sources or {}
            # New sources are worth sending even when health says nothing changed.
            self._effective_config_dirty = True
            changed = True

        duplicates = self._find_duplicate_queries(self.schedule_state)
        if duplicates != self.duplicate_queries:
            self.duplicate_queries = duplicates
            changed = True

        if changed:
            self._health_dirty = True

    def _call_core(self, method: str, default: Any) -> Any:
        """Call an optional core method.

        Returns ``default`` when the core does not implement the method (an
        older daemon, a test double) and ``_FAILED`` when the call raised, so a
        failed read can be told apart from an empty answer and the previous
        snapshot left in place.
        """
        fn = getattr(self.core, method, None)
        if fn is None:
            return default
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - a snapshot is never fatal
            log.debug("core.%s() failed: %s", method, exc)
            return _FAILED

    @staticmethod
    def _find_duplicate_queries(schedule: List[Dict[str, str]]) -> List[str]:
        """Query names that appear more than once in the live schedule.

        osquery merges config sources additively. Two sources defining the same
        query name therefore produce two live schedules under one name, sharing
        the counter and diff state, with no warning from the daemon. That is
        almost always a mistake - a leftover local file next to a managed
        config - so it is surfaced rather than left to be discovered.
        """
        seen: Dict[str, int] = {}
        for row in schedule:
            name = row.get("name", "")
            if name:
                seen[name] = seen.get(name, 0) + 1
        return sorted(name for name, count in seen.items() if count > 1)

    def _fail(self, message: str, report_hash: Optional[bytes] = None) -> None:
        log.warning("remote config rejected: %s", message)
        self.remote_config_status = opamp.RemoteConfigStatuses_FAILED
        self.remote_config_error = message
        self._status_dirty = True
        if report_hash is not None:
            self.last_remote_config_hash = report_hash
        self._set_health(False, "config_failed", message)

    # -- commands ----------------------------------------------------------

    def _refuse_restart(self) -> None:
        message = (
            "RESTART is not supported: an osquery extension cannot restart the daemon"
        )
        log.warning(message)
        self._set_health(False, "restart_refused", message)

    def _handle_custom_message(self, custom_message: Any) -> List[Any]:
        capability = custom_message.capability
        if capability != constants.QUERY_CAPABILITY:
            log.debug("ignoring custom message for unsupported capability %r", capability)
            return []

        if not self.commands_enabled or self.query_runner is None:
            return [self._query_response(custom_message.data, error="commands are disabled")]

        try:
            payload = json.loads(custom_message.data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            return [self._query_response(custom_message.data, error=f"bad payload: {exc}")]

        request_id = payload.get("id", "")
        sql = payload.get("sql", "")
        expire_at = payload.get("expire_at")
        if expire_at and self._clock() > float(expire_at):
            return [self._query_response(custom_message.data, error="expired")]

        log.info("running remote query id=%r", request_id)
        started = self._clock()
        try:
            rows, error = self.query_runner(sql)
        except Exception as exc:  # noqa: BLE001 - a query must never kill the agent
            rows, error = [], str(exc)
        duration_ms = int((self._clock() - started) * 1000)

        if error is not None:
            log.warning("remote query id=%r failed: %s", request_id, error)
            return [
                self._query_response(
                    custom_message.data, error=error, duration_ms=duration_ms
                )
            ]

        log.info(
            "remote query id=%r returned %d row(s) in %dms", request_id, len(rows), duration_ms
        )
        columns = list(rows[0].keys()) if rows else []
        body = {
            "id": request_id,
            "status": "ok",
            "columns": columns,
            "rows": [[row.get(col, "") for col in columns] for row in rows],
            "duration_ms": duration_ms,
        }
        return [self._custom_message(body)]

    def _query_response(
        self, data: bytes, *, error: str, duration_ms: int = 0
    ) -> Any:
        try:
            request_id = json.loads(data.decode("utf-8")).get("id", "")
        except Exception:  # noqa: BLE001
            request_id = ""
        return self._custom_message(
            {"id": request_id, "status": "error", "error": error, "duration_ms": duration_ms}
        )

    def _custom_message(self, payload: Dict[str, Any]) -> Any:
        # Sequence numbers are global to the agent, not per message kind: the
        # server uses gaps to detect dropped messages, so this must consume a
        # number rather than reuse the next one.
        self.sequence_num += 1
        return opamp.AgentToServer(
            instance_uid=self.instance_uid,
            sequence_num=self.sequence_num,
            capabilities=self.capabilities(),
            custom_message=opamp.CustomMessage(
                capability=constants.QUERY_CAPABILITY,
                type="result",
                data=json.dumps(payload).encode("utf-8"),
            ),
        )

    # -- identity ----------------------------------------------------------

    def _adopt_uid(self, new_uid: bytes) -> None:
        if new_uid == self.instance_uid:
            return
        if len(new_uid) != 16:
            log.warning("ignoring AgentIdentification with a %d-byte uid", len(new_uid))
            return
        log.info("adopting server-assigned instance_uid %s", new_uid.hex())
        self.instance_uid = new_uid
        if self.identity_store is not None:
            try:
                self.identity_store.write(new_uid)
            except Exception as exc:  # noqa: BLE001 - identity still usable this run
                log.warning("could not persist the new instance_uid: %s", exc)
        self.request_full_state()

    # -- reporting helpers -------------------------------------------------

    def _wants_effective_config(self) -> bool:
        return bool(self.server_capabilities & constants.SERVER_ACCEPTS_EFFECTIVE_CONFIG)

    def _build_description(self) -> Any:
        info = {}
        try:
            info = self.core.osquery_info()
        except Exception as exc:  # noqa: BLE001 - report what we can
            log.debug("osquery_info unavailable: %s", exc)
        return build_description(
            self.instance_uid,
            info,
            service_name=self.service_name,
            extension_version=self.extension_version,
            config_plugin=self.config_plugin or "opamp",
            extra_non_identifying={
                "osquery.opamp_sequence_num": self.sequence_num,
                "osquery.opamp_ignored_uid_messages": self._ignored_uid_messages,
                **(
                    {"osquery.sdk_version_source": self.sdk_version_source}
                    if self.sdk_version_source
                    else {}
                ),
            },
        )

    def _build_health(self) -> Any:
        attributes = [
            kv("osquery.config_plugin", self.config_plugin or "unknown"),
            kv("osquery.schedule_query_count", len(self.schedule_state)),
            kv("osquery.pack_count", len(self.packs_state)),
        ]
        if self.schedule_state:
            attributes.append(
                kv(
                    "osquery.schedule",
                    [f"{row.get('name', '')}@{row.get('interval', '')}" for row in self.schedule_state],
                )
            )
        if self.duplicate_queries:
            attributes.append(kv("osquery.schedule_duplicates", self.duplicate_queries))

        return opamp.ComponentHealth(
            healthy=self.health.healthy,
            start_time_unix_nano=self.start_time_unix_nano,
            last_error=self.health.last_error,
            status=self.health.status,
            status_time_unix_nano=int(self.health.changed_at * 1_000_000_000),
            attributes=attributes,
        )

    def _build_effective_config(self) -> Any:
        """Report the config the agent delivered *and* the sources the daemon runs.

        Two reasons this is not simply "the bytes we were sent":

        * a daemon can be running config from a plugin we did not touch (the
          packaged ``/var/osquery/osquery.conf`` next to our pushed source), and
          a server that cannot see it will misdiagnose every conflict;
        * reporting sources rather than the merge is the accurate claim: no RPC
          hands out osquery's merged config, and inventing one would be a lie.

        The pushed config keeps the canonical ``osquery.json`` key. Extra local
        sources follow as ``osquery.<basename>.json`` - see ``configview``.
        """
        config_map = opamp.AgentConfigMap()
        if self._applied_body is not None:
            config_map.config_map[PRIMARY_OBJECT_NAME].CopyFrom(
                opamp.AgentConfigObject(
                    body=self._applied_body,
                    content_type=constants.CONFIG_CONTENT_TYPE,
                )
            )

        for name, body in source_documents(self.config_sources).items():
            try:
                encoded = body.encode("utf-8")
            except UnicodeEncodeError:  # pragma: no cover - thrift gives us str
                log.warning("config source %s is not valid UTF-8; not reporting it", name)
                continue
            config_map.config_map[name].CopyFrom(
                opamp.AgentConfigObject(
                    body=encoded,
                    content_type=constants.CONFIG_CONTENT_TYPE,
                )
            )

        return opamp.EffectiveConfig(config_map=config_map)

    def _set_health(self, healthy: bool, status: str, error: str) -> None:
        if (
            healthy == self.health.healthy
            and status == self.health.status
            and error == self.health.last_error
        ):
            return
        self.health = Health(healthy=healthy, status=status, last_error=error, changed_at=self._clock())
        self._health_dirty = True

    # -- introspection -----------------------------------------------------

    @property
    def applied_config(self) -> Optional[Dict[str, Any]]:
        return self._applied_config

    def snapshot(self) -> Dict[str, Any]:
        return {
            "instance_uid": self.instance_uid.hex(),
            "sequence_num": self.sequence_num,
            "capabilities": self.capabilities(),
            "remote_config_status": opamp.RemoteConfigStatuses.Name(self.remote_config_status),
            "remote_config_error": self.remote_config_error,
            "last_remote_config_hash": self.last_remote_config_hash.hex(),
            "health": {
                "healthy": self.health.healthy,
                "status": self.health.status,
                "last_error": self.health.last_error,
            },
            "config_plugin": self.config_plugin,
            "scheduled_queries": len(self.schedule_state),
            "packs": len(self.packs_state),
            "config_sources": sorted(self.config_sources),
            "duplicate_queries": list(self.duplicate_queries),
        }


__all__ = ["OpampAgent", "Health", "DEFAULT_STATE_INTERVAL", "MAX_QUERIES_VALIDATED"]
