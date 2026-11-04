"""Run the agent: osquery extension on one side, OpAMP server on the other.

    python -m osquery_opamp --endpoint http://localhost:4320/v1/opamp

The endpoint scheme picks the transport: ``http(s)://`` for the spec's
request/reply transport (works against any server, no server-side opt-in),
``ws(s)://`` for websocket (needs the server to accept the upgrade, and lets it
push without waiting for a poll).

Shutdown is ordered on purpose: stop the OpAMP client first (so
``agent_disconnect`` goes out), then deregister the extension (so the daemon
forgets the route immediately instead of waiting for two failed pings).
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
from typing import Any, List, Optional

from .configcache import ConfigCache, default_config_path
from .extension import OsqueryExtension
from .opamp.agent import DEFAULT_STATE_INTERVAL, OpampAgent
from .opamp.client import OpampClient
from .opamp.constants import (
    DEFAULT_HEARTBEAT_SECONDS,
    DEFAULT_SOURCE,
    MIN_RETRY_SECONDS,
)
from .opamp.identity import IdentityStore, default_identity_path
from .opamp.transport import transport_for_url
from .osquery_thrift import default_manager_socket

#: Where a local OpAMP server listens by default (opamp-server-py, opamp-go's
#: example, the docker-compose in this repo's docs). Defaulted rather than
#: required so that ``python -m osquery_opamp`` is a complete command against a
#: stock server: plain HTTP works on any of them, and needs no server-side flag.
DEFAULT_ENDPOINT = "http://localhost:4320/v1/opamp"

#: How long a cold ``--config_plugin=opamp`` request waits for the first config.
#: It delays daemon startup, so it is bounded and documented rather than infinite.
DEFAULT_PULL_WAIT_SECONDS = 10.0

#: Registration retry budget. Covers systemd starting both units at once and
#: osqueryd's own ``--extensions_require`` wait, without making a mistyped
#: ``--extensions-socket`` take 30s to report.
DEFAULT_STARTUP_TIMEOUT_SECONDS = 10.0

log = logging.getLogger("osquery_opamp")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osquery-opamp",
        description="OpAMP agent for osquery, delivered as an osquery extension.",
    )
    parser.add_argument(
        "--endpoint",
        default=DEFAULT_ENDPOINT,
        help=(
            "OpAMP server URL: http(s):// for the request/reply transport, ws(s):// for"
            " websocket (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--extensions-socket",
        default=default_manager_socket(),
        help="osquery daemon extension socket (default: %(default)s)",
    )
    parser.add_argument(
        "--identity",
        default=str(default_identity_path()),
        help="file holding the 16-byte instance_uid (default: %(default)s)",
    )
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="osquery config source name")
    parser.add_argument(
        "--config-cache",
        default=str(default_config_path()),
        help=(
            "file holding the last config the daemon accepted, so a restart is served"
            " it before the OpAMP server is reachable; pass an empty string to disable"
            " it (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--heartbeat",
        type=float,
        default=DEFAULT_HEARTBEAT_SECONDS,
        help="seconds between heartbeats when idle (default: %(default)s)",
    )
    parser.add_argument(
        "--retry",
        type=float,
        default=MIN_RETRY_SECONDS,
        help="initial reconnect delay in seconds; the spec recommends >= 30 (default: %(default)s)",
    )
    parser.add_argument("--ca-file", default=None, help="CA bundle for https:// or wss:// verification")
    parser.add_argument(
        "--tls-hostname",
        default=None,
        help="wss:// only: override the name verified against the certificate",
    )
    parser.add_argument(
        "--header",
        action="append",
        default=[],
        metavar="'Name: Value'",
        help="extra HTTP header for the WebSocket handshake (repeatable)",
    )
    parser.add_argument(
        "--pull-wait",
        type=float,
        default=DEFAULT_PULL_WAIT_SECONDS,
        help=(
            "seconds a --config_plugin=opamp config request may wait for the first"
            " OpAMP config (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--startup-timeout",
        type=float,
        default=DEFAULT_STARTUP_TIMEOUT_SECONDS,
        help=(
            "seconds to retry registering with osqueryd before giving up, covering both"
            " a daemon that is still starting and a previous copy of this extension that"
            " is still registered; raise it when osqueryd uses --extensions_require"
            " (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--enable-commands",
        action="store_true",
        help="advertise com.osquery.query and run ad-hoc SQL from the server",
    )
    parser.add_argument(
        "--state-interval",
        type=float,
        default=DEFAULT_STATE_INTERVAL,
        help=(
            "seconds between reads of the daemon's live schedule, packs and config"
            " sources, reported with agent health (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--no-validate-queries",
        action="store_true",
        help=(
            "apply pushed configs without pre-compiling their scheduled queries;"
            " by default a config whose SQL does not compile is rejected"
        ),
    )
    parser.add_argument("--log-level", default="INFO", help="debug, info, warning, error")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    if args.retry < MIN_RETRY_SECONDS:
        log.warning(
            "retry interval %.0fs is below the spec's recommended minimum of %.0fs",
            args.retry,
            MIN_RETRY_SECONDS,
        )

    if args.tls_hostname and args.endpoint.startswith(("http://", "https://")):
        # Reported here rather than in the transport: the transport is built inside
        # the client's reconnect loop, so raising there would log a traceback and
        # retry forever instead of telling the operator what is wrong.
        log.error(
            "--tls-hostname is only supported for wss:// endpoints; over %s the"
            " certificate must match the URL host",
            args.endpoint.split(":", 1)[0],
        )
        return 2

    identity = IdentityStore(args.identity)
    uid = identity.load_or_create()

    cache = ConfigCache(args.config_cache) if args.config_cache else None
    if cache is None:
        log.warning(
            "no --config-cache: a restarted extension cannot serve the daemon its last"
            " config, and a --config_plugin=opamp daemon will boot without one"
            " unless --config_enable_backup restores it"
        )
    else:
        log.info("config cache: %s", cache.path)

    extension = OsqueryExtension(
        args.extensions_socket,
        version=_version(),
        source=args.source,
        pull_wait=args.pull_wait,
        config_cache=cache,
    )
    try:
        extension.start(wait=args.startup_timeout)
    except Exception as exc:  # noqa: BLE001 - a clear message beats a traceback
        log.error("could not register with osqueryd at %s: %s", args.extensions_socket, exc)
        log.error(
            "is the daemon running with --extensions_socket=%s, and is another copy of this"
            " extension already registered?",
            args.extensions_socket,
        )
        return 2

    pull_mode = _is_pull_mode(extension.core, args.source)
    if pull_mode:
        log.info(
            "config mode: PULL - %r is the daemon's --config_plugin, so the daemon is"
            " served config over genConfig and a restart is served %s",
            args.source,
            cache.path if cache is not None else "nothing (no --config-cache)",
        )
    else:
        log.info(
            "config mode: PUSH - the daemon runs its own --config_plugin; config is"
            " merged as source %r via config/update and re-pushed after a restart",
            args.source,
        )

    agent = OpampAgent(
        uid,
        extension.core,
        source=args.source,
        extension_version=_version(),
        commands_enabled=args.enable_commands,
        query_runner=(lambda sql: (extension.core.query(sql), None)) if args.enable_commands else None,
        identity_store=identity,
        sdk_version_source=extension.sdk_version_source,
        validate_queries=not args.no_validate_queries,
        state_interval=args.state_interval,
        config_service=extension.service,
        pull_mode=pull_mode,
    )
    # A restarted daemon is a new process with no state: after we register again,
    # tell the server everything (description, health, effective config, status) so
    # its view of the daemon matches the one that just booted, not the dead one.
    extension.on_reregistered = agent.request_full_state
    client = OpampClient(
        agent,
        lambda: transport_for_url(
            args.endpoint,
            headers=args.header,
            ca_file=args.ca_file,
            hostname=args.tls_hostname,
            timeout=max(args.heartbeat, 10.0),
            instance_uid=lambda: agent.instance_uid,
        ),
        heartbeat_interval=args.heartbeat,
        retry_interval=args.retry,
    )

    stop = threading.Event()

    def _handle_signal(signum, _frame):
        log.info("received signal %s, shutting down", signum)
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _handle_signal)
        except ValueError:  # not the main thread (tests)
            pass

    client.start()
    log.info(
        "agent running: uid=%s endpoint=%s source=%s commands=%s",
        uid.hex(),
        args.endpoint,
        args.source,
        "on" if args.enable_commands else "off",
    )

    try:
        while not stop.is_set():
            if not client.running:
                log.error("opamp client stopped unexpectedly")
                break
            if extension.shutdown_requested:
                log.warning("osqueryd asked the extension to shut down")
                break
            stop.wait(0.5)
    finally:
        client.stop()
        extension.stop()
    return 0


def _is_pull_mode(core: Any, source: str) -> bool:
    """True when the daemon's active config plugin is us (``--config_plugin=opamp``).

    This is the difference between "the daemon got its config from us" and "the
    daemon has its own config and we merged a source into it", and it decides
    whether the agent may adopt the cached ``config_hash`` at startup. A daemon that
    cannot answer is assumed to be in push mode: re-delivering a config is cheap,
    claiming one the daemon never loaded is not.
    """
    try:
        return core.active_config_plugin().strip() == source
    except Exception as exc:  # noqa: BLE001 - unknown is not pull
        log.warning("could not read the daemon's config plugin (%s); assuming push mode", exc)
        return False


def _version() -> str:
    from . import __version__

    return __version__


if __name__ == "__main__":
    sys.exit(main())
