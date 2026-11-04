"""Build the ``AgentDescription`` from state the daemon already exposes.

Every attribute here comes from ``osquery_info`` or the host itself; nothing new
is collected. That is a deliberate constraint: adding OpAMP must not widen what
osquery reads from the machine.
"""

from __future__ import annotations

import platform
import socket
from typing import Any, Dict, List, Optional, Tuple

from .pb import anyvalue, opamp

#: ``service.name`` values, per the server contract.
SERVICE_DAEMON = "osqueryd"
SERVICE_SHELL = "osqueryi"


def _kv(key: str, value: Any) -> Any:
    """Build a KeyValue with the AnyValue variant that fits ``value``."""
    if isinstance(value, bool):
        return anyvalue.KeyValue(key=key, value=anyvalue.AnyValue(bool_value=value))
    if isinstance(value, int):
        return anyvalue.KeyValue(key=key, value=anyvalue.AnyValue(int_value=value))
    if isinstance(value, float):
        return anyvalue.KeyValue(key=key, value=anyvalue.AnyValue(double_value=value))
    if isinstance(value, (list, tuple)):
        return anyvalue.KeyValue(
            key=key,
            value=anyvalue.AnyValue(
                array_value=anyvalue.ArrayValue(
                    values=[anyvalue.AnyValue(string_value=str(item)) for item in value]
                )
            ),
        )
    return anyvalue.KeyValue(key=key, value=anyvalue.AnyValue(string_value=str(value)))


def _os_type() -> str:
    system = platform.system().lower()
    return {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(system, system)


def kv(key: str, value: Any) -> Any:
    """Build a ``KeyValue`` with the AnyValue variant that fits ``value``.

    Public because health attributes are built outside this module.
    """
    return _kv(key, value)


def build_description(
    instance_uid: bytes,
    info: Dict[str, str],
    *,
    service_name: str = SERVICE_DAEMON,
    hostname: Optional[str] = None,
    extension_version: Optional[str] = None,
    config_plugin: str = "opamp",
    extra_identifying: Optional[Dict[str, Any]] = None,
    extra_non_identifying: Optional[Dict[str, Any]] = None,
) -> Any:
    """Return a populated ``AgentDescription``.

    ``info`` is a row from ``osquery_info`` (see ``CoreClient.osquery_info``); an
    empty mapping is tolerated so the agent can report something useful before
    the daemon answers.
    """
    identifying: List[Tuple[str, Any]] = [
        ("service.name", service_name),
        ("service.version", info.get("version", "unknown")),
        ("service.instance.id", instance_uid.hex()),
        ("host.name", hostname or socket.gethostname()),
        ("os.type", _os_type()),
        ("os.description", info.get("build_distro") or platform.platform()),
        ("host.arch", info.get("build_platform") or platform.machine()),
        # The daemon's active config plugin, not ours: an extension can push into
        # a daemon that is configured by the filesystem or tls plugin, and
        # claiming "opamp" there would hide exactly the conflict an operator
        # needs to see.
        ("osquery.config_plugin", config_plugin),
    ]
    if extension_version:
        identifying.append(("osquery.opamp_extension_version", extension_version))
    for key, value in (extra_identifying or {}).items():
        identifying.append((key, value))

    non_identifying: List[Tuple[str, Any]] = []
    for key, value in (
        ("osquery.config_hash", info.get("config_hash", "")),
        ("osquery.config_valid", info.get("config_valid", "0") == "1"),
        ("osquery.instance_id", info.get("instance_id", "")),
        ("osquery.host_uuid", info.get("uuid", "")),
        ("osquery.watcher_pid", info.get("watcher", "-1")),
        ("osquery.pid", info.get("pid", "")),
        ("osquery.start_time", info.get("start_time", "")),
        ("osquery.build_platform", info.get("build_platform", "")),
        ("osquery.build_distro", info.get("build_distro", "")),
    ):
        if value != "":
            non_identifying.append((key, value))
    for key, value in (extra_non_identifying or {}).items():
        non_identifying.append((key, value))

    return opamp.AgentDescription(
        identifying_attributes=[_kv(k, v) for k, v in identifying],
        non_identifying_attributes=[_kv(k, v) for k, v in non_identifying],
    )


def description_to_dict(description: Any) -> Dict[str, Any]:
    """Flatten an ``AgentDescription`` into a plain dict, for logs and tests."""
    out: Dict[str, Any] = {}
    for field in ("identifying_attributes", "non_identifying_attributes"):
        for item in getattr(description, field):
            value = item.value
            which = value.WhichOneof("value")
            out[item.key] = getattr(value, which) if which else None
    return out


__all__ = [
    "build_description",
    "description_to_dict",
    "kv",
    "SERVICE_DAEMON",
    "SERVICE_SHELL",
]
