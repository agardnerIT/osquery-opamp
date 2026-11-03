"""The operations this extension performs against a running osquery daemon.

Three of them matter, and each maps onto a documented registry item:

``push_config``
    ``Registry::call("config", "update", ...)`` -> ``ConfigPlugin::call`` ->
    ``Config::update()``. The daemon merges the payload as a *config source*,
    exactly as if a config plugin had produced it. This is the mechanism
    ``plugins/config/update.cpp`` exists for: an extension changing core config
    asynchronously.

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
from dataclasses import dataclass
from typing import Any, Dict, List

from .osquery_thrift import (
    EXT_SUCCESS,
    ExtensionStatus,
    make_manager_client,
    rows_to_dicts,
)

log = logging.getLogger(__name__)


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

    One instance per connection. The underlying Thrift client is not thread
    safe; the extension serialises access with a lock (see ``Extension``).
    """

    def __init__(self, manager_socket: str, timeout_ms: int = 5000) -> None:
        self.manager_socket = manager_socket
        self._client = make_manager_client(manager_socket, timeout_ms=timeout_ms)

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
        status: ExtensionStatus = self._client.registerExtension(info, registry)
        if status.code != EXT_SUCCESS:
            raise CoreError(f"registerExtension failed: {status.message}")
        if not status.uuid:
            raise CoreError("registerExtension returned no uuid")
        return int(status.uuid)

    def deregister(self, uuid: int) -> None:
        try:
            self._client.deregisterExtension(uuid)
        except Exception as exc:  # noqa: BLE001 - best effort on shutdown
            log.debug("deregisterExtension(%s) failed: %s", uuid, exc)

    def ping(self) -> bool:
        """Ping the daemon. False means the daemon is gone."""
        try:
            status: ExtensionStatus = self._client.ping()
        except Exception as exc:  # noqa: BLE001 - transport failures are expected
            log.debug("ping failed: %s", exc)
            return False
        return status.code == EXT_SUCCESS

    def extensions(self) -> Dict[int, Any]:
        try:
            return dict(self._client.extensions())
        except Exception as exc:  # noqa: BLE001
            log.debug("extensions() failed: %s", exc)
            return {}

    def options(self) -> Dict[str, Any]:
        try:
            return dict(self._client.options())
        except Exception as exc:  # noqa: BLE001
            log.debug("options() failed: %s", exc)
            return {}

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
            response = self._client.call("config", "update", request)
        except Exception as exc:  # noqa: BLE001
            return ConfigPushResult(False, f"transport error: {exc}")

        status = response.status
        ok = status.code == EXT_SUCCESS
        return ConfigPushResult(ok, status.message or ("OK" if ok else "rejected"))

    # -- read-back ---------------------------------------------------------

    def query(self, sql: str) -> List[Dict[str, str]]:
        """Run ``sql`` in the daemon and return rows as dicts of strings."""
        try:
            response = self._client.query(sql)
        except Exception as exc:  # noqa: BLE001
            raise CoreError(f"query failed: {exc}") from exc
        if response.status.code != EXT_SUCCESS:
            raise CoreError(f"query rejected: {response.status.message}")
        return rows_to_dicts(response)

    def osquery_info(self) -> Dict[str, str]:
        rows = self.query(
            "select version, config_hash, config_valid, pid, uuid, instance_id,"
            " start_time, watcher, build_platform, build_distro from osquery_info"
        )
        return rows[0] if rows else {}

    def scheduled_queries(self) -> List[Dict[str, str]]:
        return self.query("select name, query, interval from osquery_schedule")

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


__all__ = ["CoreClient", "CoreError", "ConfigPushResult"]
