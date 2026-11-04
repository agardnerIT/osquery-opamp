"""Protocol constants, derived from the pinned v0.20.0 enums.

Capabilities are a uint64 bitmask that the agent MUST always send. What we
advertise is deliberately narrow: everything here is implemented, and anything
missing is something we cannot do. In particular ``AcceptsRestartCommand`` is
**not** set, because an osquery extension has no RPC that restarts the daemon -
claiming it would make servers send a command we would have to refuse.
"""

from __future__ import annotations

from .pb import opamp

#: Agent capabilities we implement. See
#: [03-wire-format.md](../../../osquery/opamp-plans/03-wire-format.md) for the
#: full table and the reasoning.
AGENT_CAPABILITIES: int = (
    opamp.AgentCapabilities_ReportsStatus
    | opamp.AgentCapabilities_AcceptsRemoteConfig
    | opamp.AgentCapabilities_ReportsEffectiveConfig
    | opamp.AgentCapabilities_ReportsRemoteConfig
    | opamp.AgentCapabilities_ReportsHealth
    | opamp.AgentCapabilities_ReportsHeartbeat
)

#: Capabilities we must never claim. Kept explicit so a future edit has to delete
#: a line to get it wrong.
NOT_ADVERTISED = {
    "AcceptsPackages": opamp.AgentCapabilities_AcceptsPackages,
    "ReportsPackageStatuses": opamp.AgentCapabilities_ReportsPackageStatuses,
    "ReportsOwnTraces": opamp.AgentCapabilities_ReportsOwnTraces,
    "ReportsOwnMetrics": opamp.AgentCapabilities_ReportsOwnMetrics,
    "ReportsOwnLogs": opamp.AgentCapabilities_ReportsOwnLogs,
    "AcceptsRestartCommand": opamp.AgentCapabilities_AcceptsRestartCommand,
    "AcceptsOpAMPConnectionSettings": opamp.AgentCapabilities_AcceptsOpAMPConnectionSettings,
    "ReportsConnectionSettingsStatus": opamp.AgentCapabilities_ReportsConnectionSettingsStatus,
}

#: The custom capability used for ad-hoc SQL, matching the server contract.
QUERY_CAPABILITY = "com.osquery.query"

#: Server capabilities we act on.
SERVER_ACCEPTS_EFFECTIVE_CONFIG = opamp.ServerCapabilities_AcceptsEffectiveConfig
SERVER_OFFERS_REMOTE_CONFIG = opamp.ServerCapabilities_OffersRemoteConfig

#: The config object name used for an osquery configuration document.
CONFIG_OBJECT_NAME = "osquery.json"
CONFIG_CONTENT_TYPE = "application/json"

#: The config source name this agent pushes into osquery.
DEFAULT_SOURCE = "opamp"

#: Spec: "The minimum recommended retry interval is 30 seconds."
MIN_RETRY_SECONDS = 30.0

#: Default heartbeat, per the spec's guidance when the server does not set one.
DEFAULT_HEARTBEAT_SECONDS = 30.0


def capabilities_sanity_check() -> None:
    """Fail loudly if the advertised mask ever overlaps the never-claim set."""
    for name, bit in NOT_ADVERTISED.items():
        if AGENT_CAPABILITIES & bit:
            raise AssertionError(f"agent advertises {name}, which it does not implement")


__all__ = [
    "AGENT_CAPABILITIES",
    "NOT_ADVERTISED",
    "QUERY_CAPABILITY",
    "SERVER_ACCEPTS_EFFECTIVE_CONFIG",
    "SERVER_OFFERS_REMOTE_CONFIG",
    "CONFIG_OBJECT_NAME",
    "CONFIG_CONTENT_TYPE",
    "DEFAULT_SOURCE",
    "MIN_RETRY_SECONDS",
    "DEFAULT_HEARTBEAT_SECONDS",
    "capabilities_sanity_check",
]
