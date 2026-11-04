"""The operations this extension performs against a running osquery daemon.

Each one maps onto a documented registry item or RPC:

``push_config``
    ``Registry::call("config", "update", ...)`` -> ``ConfigPlugin::call`` ->
    ``Config::update()``. The daemon merges the payload as a *config source*,
    exactly as if a config plugin had produced it. This is the mechanism
    ``plugins/config/update.cpp`` exists for: an extension changing core config
    asynchronously.

``config_sources``
    ``Registry::call("config", <plugin>, {"action": "genConfig"})`` returns the
    raw JSON each source currently contributes. This is how the agent can report
    a config it did not push itself - but only for plugins whose ``genConfig``
    is a pure read. ``tls`` is not one: it performs an HTTP fetch and answers
    "config unchanged" with no body when the etag matches.

``query_columns``
    ``ExtensionManager.getQueryColumns(sql)`` prepares a statement without
    running it. Used to reject a pushed config whose scheduled queries cannot
    compile, which ``Config::update()`` itself accepts happily.

``query``
    ``ExtensionManager.query(sql)`` runs against the daemon's SQLite, including
    tables this extension has no access to locally. Used for effective config
    and health reporting.

``options``
    ``ExtensionManager.options()`` returns the daemon's flags, used to learn the
    active config/logger/distributed plugins.

Nothing here requires a change to osquery: every call is an existing RPC.
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .osquery_thrift import (
    EXT_SUCCESS,
    ExtensionStatus,
    make_manager_client,
    rows_to_dicts,
)

log = logging.getLogger(__name__)

#: ``osquery_info`` columns this package reports. Kept as a projection over
#: ``select *`` rather than a SELECT list, so a daemon that drops or renames a
#: column degrades to a missing attribute instead of a failing query.
INFO_COLUMNS = (
    "version",
    "config_hash",
    "config_valid",
    "pid",
    "uuid",
    "instance_id",
    "start_time",
    "watcher",
    "build_platform",
    "build_distro",
)

#: ``osquery_schedule`` columns this package reports.
SCHEDULE_COLUMNS = ("name", "query", "interval")

#: ``osquery_schedule`` columns used for the state snapshot. ``executions`` and
#: ``denylisted`` distinguish "pushed and running" from "pushed and failing".
STATE_SCHEDULE_COLUMNS = ("name", "query", "interval", "executions", "denylisted")

#: ``osquery_packs`` columns used for the state snapshot.
STATE_PACK_COLUMNS = ("name", "active")

#: Config plugins whose ``genConfig`` can be called purely for reading. Anything
#: else may have side effects (``tls`` fetches over the network, ``opamp`` would
#: block on the OpAMP server, ...), so it is not read back.
SIDE_EFFECT_FREE_CONFIG_PLUGINS = frozenset({"filesystem"})


class CoreError(RuntimeError):
    """A call reached the daemon and failed."""


@dataclass
class ConfigPushResult:
    ok: bool
    message: str

    @property
    def status(self) -> str:
        return "APPLIED" if self.ok else "FAILED"


class CoreClient:
    """Thin, typed wrapper over the daemon's ``ExtensionManager``.

    The underlying Thrift client is not thread safe; every call is serialised
    with a lock (see ``Extension``). The connection is opened lazily and dropped
    on transport failure, so constructing a ``CoreClient`` never requires the
    daemon to be up - which is what lets an extension wait for a daemon that is
    still starting, and reconnect to one that restarted underneath it.
    """

    def __init__(self, manager_socket: str, timeout_ms: int = 5000) -> None:
        self.manager_socket = manager_socket
        self.timeout_ms = timeout_ms
        self._client: Any = None
        # One Thrift client owns one socket. The extension pings the daemon from
        # its liveness thread while the OpAMP thread pushes config, so every RPC
        # must be serialised or the two interleave on the wire and responses get
        # mismatched with requests. This is not theoretical: it produced a
        # silent "config never applied" before the lock existed.
        self._lock = threading.RLock()

    # -- connection --------------------------------------------------------

    def _connection(self) -> Any:
        if self._client is None:
            self._client = make_manager_client(self.manager_socket, timeout_ms=self.timeout_ms)
        return self._client

    def _drop(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                client._oprot.trans.close()
            except Exception as exc:  # noqa: BLE001 - already failing
                log.debug("closing the daemon connection failed: %s", exc)

    def close(self) -> None:
        """Drop the connection, if any. Safe to call more than once."""
        with self._lock:
            self._drop()

    def _rpc(self, call: Any) -> Any:
        """Run one RPC, reconnecting on the next call if the transport failed."""
        with self._lock:
            client = self._connection()
            try:
                return call(client)
            except Exception:
                self._drop()
                raise

    # -- lifecycle ---------------------------------------------------------

    def register(
        self,
        name: str,
        version: str,
        sdk_version: str,
        min_sdk_version: str,
        registry: Dict[str, Dict[str, List[Dict[str, str]]]],
    ) -> int:
        """Register this extension and return its route UUID."""
        info = self._info(name, version, sdk_version, min_sdk_version)
        status: ExtensionStatus = self._rpc(lambda c: c.registerExtension(info, registry))
        if status.code != EXT_SUCCESS:
            raise CoreError(f"registerExtension failed: {status.message}")
        if not status.uuid:
            raise CoreError("registerExtension returned no uuid")
        return int(status.uuid)

    def deregister(self, uuid: int) -> None:
        try:
            self._rpc(lambda c: c.deregisterExtension(uuid))
        except Exception as exc:  # noqa: BLE001 - best effort on shutdown
            log.debug("deregisterExtension(%s) failed: %s", uuid, exc)

    def ping(self) -> bool:
        """Ping the daemon. False means the daemon is gone."""
        try:
            status: ExtensionStatus = self._rpc(lambda c: c.ping())
        except Exception as exc:  # noqa: BLE001 - transport failures are expected
            log.debug("ping failed: %s", exc)
            return False
        return status.code == EXT_SUCCESS

    def extensions(self) -> Dict[int, Any]:
        try:
            return dict(self._rpc(lambda c: c.extensions()))
        except Exception as exc:  # noqa: BLE001
            log.debug("extensions() failed: %s", exc)
            return {}

    def options(self) -> Dict[str, Any]:
        try:
            return dict(self._rpc(lambda c: c.options()))
        except Exception as exc:  # noqa: BLE001
            log.debug("options() failed: %s", exc)
            return {}

    def flags(self) -> Dict[str, str]:
        """The daemon's flags as plain strings (``options()`` returns structs)."""
        return {name: str(getattr(info, "value", "")) for name, info in self.options().items()}

    def active_config_plugin(self) -> str:
        """The config plugin the daemon is actually running, or ``""`` if unknown."""
        return self.flags().get("config_plugin", "")

    # -- config ------------------------------------------------------------

    def push_config(self, source: str, config: Dict[str, Any]) -> ConfigPushResult:
        """Merge ``config`` into the daemon's live config as ``source``."""
        return self.push_config_raw(source, json.dumps(config))

    def push_config_raw(self, source: str, payload: str) -> ConfigPushResult:
        """Merge an already-encoded config document as ``source``.

        The return value is the daemon's own verdict, and it is narrower than it
        looks. Verified against osquery 5.24.0: ``Config::update()`` only fails
        for unparseable JSON (and the size limit). A document that parses but is
        semantically wrong - ``{"schedule": []}``, an unknown top-level key, a
        scheduled query naming a table that does not exist - returns OK, because
        osquery applies config structure eagerly and validates SQL only when a
        query actually runs.

        So ``ok`` means "accepted and merged", not "this config is correct".
        Per-query failures surface later in ``osquery_schedule`` and the status
        logs. Reporting that distinction to the OpAMP server matters: an
        ``APPLIED`` status must not be read as "the queries work".
        """
        request = {"action": "update", "source": source, "data": payload}
        try:
            response = self._rpc(lambda c: c.call("config", "update", request))
        except Exception as exc:  # noqa: BLE001
            return ConfigPushResult(False, f"transport error: {exc}")

        status = response.status
        ok = status.code == EXT_SUCCESS
        return ConfigPushResult(ok, status.message or ("OK" if ok else "rejected"))

    # -- read-back ---------------------------------------------------------

    def config_sources(self, plugin: Optional[str] = None) -> Dict[str, str]:
        """Read the config sources the daemon is running, keyed by source name.

        Only side-effect-free plugins are read (see
        ``SIDE_EFFECT_FREE_CONFIG_PLUGINS``); for anything else this returns an
        empty mapping and logs why, rather than reaching into a plugin whose
        ``genConfig`` would fetch from the network or block on a server.

        What comes back is the *sources*, not the merge: osquery's merge of them
        is deterministic, but the merged document is not exposed by any RPC.
        """
        plugin = plugin if plugin is not None else self.active_config_plugin()
        if plugin not in SIDE_EFFECT_FREE_CONFIG_PLUGINS:
            log.debug(
                "not reading config sources back: active plugin %r is not known to be "
                "side-effect free",
                plugin or "unknown",
            )
            return {}

        try:
            response = self._rpc(
                lambda c: c.call("config", plugin, {"action": "genConfig"})
            )
        except Exception as exc:  # noqa: BLE001 - reporting must survive this
            log.debug("reading config sources from %s failed: %s", plugin, exc)
            return {}

        if response.status.code != EXT_SUCCESS:
            log.debug(
                "reading config sources from %s failed: %s", plugin, response.status.message
            )
            return {}

        sources: Dict[str, str] = {}
        for entry in response.response or []:
            for source, body in dict(entry).items():
                sources[str(source)] = str(body)
        return sources

    def query_columns(self, sql: str) -> List[Dict[str, str]]:
        """Prepare ``sql`` (without running it) and return its columns.

        Raises ``CoreError`` with osquery's own message when the statement does
        not compile - ``"no such table: batteries"``, ``"incomplete input"`` -
        which is exactly the text an operator needs to see in a config error.
        """
        try:
            response = self._rpc(lambda c: c.getQueryColumns(sql))
        except Exception as exc:  # noqa: BLE001
            raise CoreError(f"getQueryColumns failed: {exc}") from exc
        if response.status.code != EXT_SUCCESS:
            raise CoreError(response.status.message or "query did not compile")
        return rows_to_dicts(response)
    def query(self, sql: str) -> List[Dict[str, str]]:
        """Run ``sql`` in the daemon and return rows as dicts of strings."""
        try:
            response = self._rpc(lambda c: c.query(sql))
        except Exception as exc:  # noqa: BLE001
            raise CoreError(f"query failed: {exc}") from exc
        if response.status.code != EXT_SUCCESS:
            raise CoreError(f"query rejected: {response.status.message}")
        return rows_to_dicts(response)

    def osquery_info(self) -> Dict[str, str]:
        """One row of ``osquery_info``, restricted to the columns we report.

        Selected with ``*`` on purpose. The column set changes between osquery
        releases (``instance_id`` is newer than the rest, and ``build_platform``
        is not present on every build), and naming columns explicitly turns a
        schema change into a hard ``query rejected`` failure. Reading ``*`` and
        projecting here degrades instead: a missing column is simply absent.
        """
        rows = self.query("select * from osquery_info")
        row = rows[0] if rows else {}
        return {name: row.get(name, "") for name in INFO_COLUMNS}

    def scheduled_queries(self) -> List[Dict[str, str]]:
        """The live schedule, projected to the columns OpAMP reports.

        Same reasoning as ``osquery_info``: ``osquery_schedule`` carries a dozen
        version-dependent performance columns, and we need three of them.
        """
        rows = self.query("select * from osquery_schedule")
        return [{name: row.get(name, "") for name in SCHEDULE_COLUMNS} for row in rows]

    def schedule_state(self) -> List[Dict[str, str]]:
        """The live schedule with execution counters, for the state snapshot."""
        rows = self.query("select * from osquery_schedule")
        return [
            {name: row.get(name, "") for name in STATE_SCHEDULE_COLUMNS} for row in rows
        ]

    def packs_state(self) -> List[Dict[str, str]]:
        """The loaded packs, for the state snapshot."""
        rows = self.query("select * from osquery_packs")
        return [{name: row.get(name, "") for name in STATE_PACK_COLUMNS} for row in rows]

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _info(name: str, version: str, sdk_version: str, min_sdk_version: str) -> Any:
        from .osquery_thrift import InternalExtensionInfo

        return InternalExtensionInfo(
            name=name,
            version=version,
            sdk_version=sdk_version,
            min_sdk_version=min_sdk_version,
        )


__all__ = [
    "CoreClient",
    "CoreError",
    "ConfigPushResult",
    "SIDE_EFFECT_FREE_CONFIG_PLUGINS",
]
