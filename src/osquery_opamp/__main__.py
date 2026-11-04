"""Run the agent: osquery extension on one side, OpAMP server on the other.

    python -m osquery_opamp --endpoint wss://opamp.example.com/v1/opamp

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
from typing import List, Optional

from .extension import OsqueryExtension
from .opamp.agent import OpampAgent
from .opamp.client import OpampClient
from .opamp.constants import (
    DEFAULT_HEARTBEAT_SECONDS,
    DEFAULT_SOURCE,
    MIN_RETRY_SECONDS,
)
from .opamp.identity import IdentityStore, default_identity_path
from .opamp.transport import WebSocketTransport
from .osquery_thrift import default_manager_socket

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
    parser.add_argument("--endpoint", required=True, help="OpAMP server URL (ws:// or wss://)")
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
    parser.add_argument("--ca-file", default=None, help="CA bundle for wss:// verification")
    parser.add_argument(
        "--tls-hostname", default=None, help="override the name verified against the certificate"
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
            "seconds to retry registering with osqueryd before giving up; raise it"
            " when osqueryd uses --extensions_require (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--enable-commands",
        action="store_true",
        help="advertise com.osquery.query and run ad-hoc SQL from the server",
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

    identity = IdentityStore(args.identity)
    uid = identity.load_or_create()

    extension = OsqueryExtension(
        args.extensions_socket,
        version=_version(),
        source=args.source,
        pull_wait=args.pull_wait,
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

    agent = OpampAgent(
        uid,
        extension.core,
        source=args.source,
        extension_version=_version(),
        commands_enabled=args.enable_commands,
        query_runner=(lambda sql: (extension.core.query(sql), None)) if args.enable_commands else None,
        identity_store=identity,
        sdk_version_source=extension.sdk_version_source,
    )
    client = OpampClient(
        agent,
        lambda: WebSocketTransport(
            args.endpoint,
            headers=args.header,
            ca_file=args.ca_file,
            hostname=args.tls_hostname,
            timeout=max(args.heartbeat, 10.0),
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


def _version() -> str:
    from . import __version__

    return __version__


if __name__ == "__main__":
    sys.exit(main())
