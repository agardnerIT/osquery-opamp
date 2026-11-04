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
from .description import build_description
from .pb import opamp

log = logging.getLogger(__name__)

QueryRunner = Callable[[str], Tuple[List[Dict[str, str]], Optional[str]]]


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

        self.health = Health()
        self.start_time_unix_nano = int(clock() * 1_000_000_000)

        # What needs to go out in the next message
        self._full_state_needed = True
        self._description_dirty = True
        self._health_dirty = True
        self._effective_config_dirty = True
        self._status_dirty = True

        self._ignored_uid_messages = 0

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
        if remote_config.config_hash:
            if remote_config.config_hash != computed:
                log.warning(
                    "server config_hash does not match the body; reporting the server's"
                    " value so it can correlate"
                )
            report_hash = bytes(remote_config.config_hash)
        else:
            report_hash = computed

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
        self.remote_config_status = opamp.RemoteConfigStatuses_APPLIED
        self.remote_config_error = ""
        self._status_dirty = True
        self._effective_config_dirty = True
        self._set_health(True, "ok", "")
        log.info(
            "applied remote config (%d bytes, hash=%s)", len(body), report_hash.hex()[:16]
        )

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

        started = self._clock()
        try:
            rows, error = self.query_runner(sql)
        except Exception as exc:  # noqa: BLE001 - a query must never kill the agent
            rows, error = [], str(exc)
        duration_ms = int((self._clock() - started) * 1000)

        if error is not None:
            return [
                self._query_response(
                    custom_message.data, error=error, duration_ms=duration_ms
                )
            ]

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
            extra_non_identifying={
                "osquery.opamp_sequence_num": self.sequence_num,
                "osquery.opamp_ignored_uid_messages": self._ignored_uid_messages,
            },
        )

    def _build_health(self) -> Any:
        return opamp.ComponentHealth(
            healthy=self.health.healthy,
            start_time_unix_nano=self.start_time_unix_nano,
            last_error=self.health.last_error,
            status=self.health.status,
            status_time_unix_nano=int(self.health.changed_at * 1_000_000_000),
        )

    def _build_effective_config(self) -> Any:
        """Report the config we actually delivered, not the bytes we were sent.

        The daemon does not expose its merged configuration, so this is the last
        applied source plus a hash the server can correlate. Documented as an
        approximation in docs/opamp-contract.md.
        """
        config_map = opamp.AgentConfigMap()
        if self._applied_body is not None:
            config_map.config_map[constants.CONFIG_OBJECT_NAME].CopyFrom(
                opamp.AgentConfigObject(
                    body=self._applied_body,
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
        }


__all__ = ["OpampAgent", "Health"]
