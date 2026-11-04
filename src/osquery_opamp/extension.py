"""The osquery side of the extension: registration, liveness and the server.

An osquery extension is two things at once:

1. A **client** of the daemon's ``ExtensionManager`` (register, ping, call,
   query).
2. A **server** of the ``Extension`` service, on ``<manager_socket>.<uuid>``,
   because the daemon pings that socket every ``--extensions_interval`` seconds
   and deregisters the extension after two consecutive failures
   (``ExtensionManagerWatcher::watch()`` in ``osquery/extensions/extensions.cpp``).

This module owns both, plus the thread that keeps the registration alive.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from .core import CoreClient
from .osquery_thrift import (
    EXT_FAILED,
    EXT_SUCCESS,
    EXTENSION_NAME,
    MIN_SDK_VERSION,
    ExtensionStatus,
    close_extension_socket,
    extension_socket_path,
    make_extension_server,
    poke_extension_socket,
)

log = logging.getLogger(__name__)

#: Registry this extension advertises. Registering a ``config`` plugin named
#: ``opamp`` makes the extension visible in ``osquery_extensions`` and allows
#: ``--config_plugin=opamp`` (pull mode) in addition to the default push mode.
DEFAULT_REGISTRY: Dict[str, Dict[str, List[Dict[str, str]]]] = {
    "config": {EXTENSION_NAME: []}
}


class ExtensionService:
    """Implementation of the daemon-facing ``Extension`` Thrift service.

    The daemon calls ``ping()`` for liveness and ``call()`` when one of the
    registry items this extension advertised is invoked. Because this extension
    also *pushes* config, ``call()`` is mostly a fallback: it answers
    ``genConfig`` with the last configuration we were given, which is what makes
    ``--config_plugin=opamp`` work.
    """

    def __init__(self) -> None:
        self.uuid: int = 0
        self.ping_count: int = 0
        self.first_ping: threading.Event = threading.Event()
        self._lock = threading.Lock()
        self._config_ready = threading.Condition(self._lock)
        self._config_by_source: Dict[str, str] = {}
        self._shutdown = threading.Event()
        self.on_shutdown: Optional[Callable[[], None]] = None

        #: Source a bare ``genConfig`` (the daemon sends no ``source`` when this
        #: extension is the active config plugin) is answered from.
        self.default_source: str = EXTENSION_NAME
        #: How long ``genConfig`` may block waiting for the first OpAMP config.
        self.pull_wait: float = 0.0

    # -- state -------------------------------------------------------------

    def set_config(self, source: str, config: Dict[str, Any]) -> None:
        with self._config_ready:
            self._config_by_source[source] = json.dumps(config)
            self._config_ready.notify_all()

    def cached_config(self, source: str) -> Optional[str]:
        with self._lock:
            return self._config_by_source.get(source)

    def wait_for_config(self, source: str, timeout: float) -> Optional[str]:
        """Block until ``source`` has a config, or ``timeout`` elapses.

        This is what makes ``--config_plugin=opamp`` survive a cold start: the
        daemon asks for the config during its own initialisation, possibly
        before the OpAMP round-trip that produces it has finished.
        """
        deadline = time.monotonic() + timeout
        with self._config_ready:
            while source not in self._config_by_source:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._config_ready.wait(remaining)
            return self._config_by_source[source]

    def request_shutdown(self) -> None:
        self._shutdown.set()
        if self.on_shutdown is not None:
            self.on_shutdown()

    @property
    def shutdown_requested(self) -> bool:
        return self._shutdown.is_set()

    # -- Thrift methods ----------------------------------------------------

    def ping(self) -> ExtensionStatus:
        self.ping_count += 1
        if not self.first_ping.is_set():
            self.first_ping.set()
            log.debug("first ping from daemon received")
        return ExtensionStatus(code=EXT_SUCCESS, message="OK", uuid=self.uuid)

    def shutdown(self) -> None:
        log.info("daemon requested extension shutdown")
        self.request_shutdown()

    def call(
        self,
        registry: str,
        item: str,
        request: Dict[str, str],
    ) -> Any:
        """Serve a registry call routed to this extension by the daemon."""
        from .osquery_thrift import ExtensionResponse

        log.debug("call registry=%s item=%s action=%s", registry, item, request.get("action"))

        if registry == "config" and item == EXTENSION_NAME:
            action = request.get("action")
            if action == "genConfig":
                source = request.get("source") or self.default_source
                cached = self.cached_config(source)
                if cached is None and self.pull_wait > 0:
                    log.info(
                        "daemon asked for config %r before the OpAMP server delivered one; "
                        "waiting up to %.0fs",
                        source,
                        self.pull_wait,
                    )
                    cached = self.wait_for_config(source, self.pull_wait)
                if cached is None:
                    return ExtensionResponse(
                        status=ExtensionStatus(
                            code=EXT_FAILED,
                            message=(
                                "no configuration received from the OpAMP server yet"
                                + (
                                    f" (waited {self.pull_wait:.0f}s); the config will be pushed"
                                    " once it arrives"
                                    if self.pull_wait > 0
                                    else ""
                                )
                            ),
                            uuid=self.uuid,
                        ),
                        response=[],
                    )
                return ExtensionResponse(
                    status=ExtensionStatus(code=EXT_SUCCESS, message="OK", uuid=self.uuid),
                    response=[{source: cached}],
                )
            return ExtensionResponse(
                status=ExtensionStatus(
                    code=EXT_FAILED, message=f"unsupported config action {action!r}", uuid=self.uuid
                ),
                response=[],
            )

        return ExtensionResponse(
            status=ExtensionStatus(
                code=EXT_FAILED, message=f"unknown registry item {registry}/{item}", uuid=self.uuid
            ),
            response=[],
        )


class OsqueryExtension:
    """Runs the extension: register, serve, stay alive, deregister.

    Typical use::

        ext = OsqueryExtension("/tmp/osq.em")
        ext.start()          # registers and serves in background threads
        ext.core.push_config("opamp", {...})
        ext.stop()
    """

    def __init__(
        self,
        manager_socket: str,
        name: str = EXTENSION_NAME,
        version: str = "0.1.0",
        sdk_version: Optional[str] = None,
        min_sdk_version: str = MIN_SDK_VERSION,
        ping_interval: float = 10.0,
        registry: Optional[Dict[str, Dict[str, List[Dict[str, str]]]]] = None,
        source: str = EXTENSION_NAME,
        pull_wait: float = 0.0,
    ) -> None:
        self.manager_socket = manager_socket
        self.name = name
        self.version = version
        self.min_sdk_version = min_sdk_version
        self.ping_interval = ping_interval
        self.registry = registry if registry is not None else DEFAULT_REGISTRY
        self.source = source

        # The SDK version reported at registration is the daemon's real version,
        # resolved in _register() once a connection is possible. Until then the
        # minimum the daemon accepts is the only defensible value: inventing a
        # plausible number would make `osquery_extensions` lie to the operator.
        self.sdk_version = sdk_version or MIN_SDK_VERSION
        self.sdk_version_source = "pinned" if sdk_version else "unknown"

        self.service = ExtensionService()
        self.service.default_source = source
        self.service.pull_wait = pull_wait
        self.core = CoreClient(manager_socket)
        self.uuid: int = 0
        self.socket_path: str = ""

        self._server: Any = None
        self._server_thread: Optional[threading.Thread] = None
        self._ping_thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()

    # -- lifecycle ---------------------------------------------------------

    def start(self, wait_for_ping: bool = True, wait: float = 0.0) -> int:
        """Register, start serving, and start the liveness thread.

        Returns the route UUID. Raises ``CoreError`` if the daemon refuses the
        registration (usually a duplicate extension name).

        ``wait`` retries the registration until the daemon's socket appears,
        which is what a ``--extensions_require=opamp`` deployment needs: the
        daemon binds the manager socket and waits for us, while we may already
        be running and finding nothing to connect to.
        """
        self.uuid = self._register(wait)
        self.service.uuid = self.uuid
        self.socket_path = extension_socket_path(self.manager_socket, self.uuid)
        log.info(
            "registered extension %s (uuid=%s, sdk=%s) at %s",
            self.name,
            self.uuid,
            self.sdk_version,
            self.socket_path,
        )

        self._server = make_extension_server(self.socket_path, self.service)
        self._server_thread = threading.Thread(
            target=self._serve, name="osquery-extension-server", daemon=True
        )
        self._server_thread.start()

        if wait_for_ping:
            self._await_first_ping()

        self._ping_thread = threading.Thread(
            target=self._ping_loop, name="osquery-extension-ping", daemon=True
        )
        self._ping_thread.start()
        return self.uuid

    def _register(self, wait: float, duplicate_wait: float = 20.0) -> int:
        """Register with the daemon, retrying transient failures.

        Two different waits, because the two failures have different causes:

        * the manager socket is not there yet (``wait``) - the daemon may still be
          starting, or it is waiting for us via ``--extensions_require``;
        * the daemon still holds a route for this extension name
          (``duplicate_wait``) - a crashed or restarted process. The daemon drops
          the stale route only after two failed pings
          (``ExtensionManagerWatcher::watch``), so a replacement process is
          refused for a few seconds. Retrying this is what makes a supervisor
          restart work without a human.
        """
        deadline = time.monotonic() + wait
        duplicate_deadline = time.monotonic() + duplicate_wait
        while True:
            self._resolve_sdk_version()
            try:
                uuid = self.core.register(
                    name=self.name,
                    version=self.version,
                    sdk_version=self.sdk_version,
                    min_sdk_version=self.min_sdk_version,
                    registry=self.registry,
                )
            except Exception as exc:  # noqa: BLE001 - socket may not exist yet
                now = time.monotonic()
                if "duplicate" in str(exc).lower():
                    if now >= duplicate_deadline:
                        raise
                    log.info(
                        "daemon still holds a registration for %r; retrying in 0.5s",
                        self.name,
                    )
                    time.sleep(0.5)
                    continue
                if now >= deadline:
                    raise
                log.debug("registration attempt failed (%s); retrying", exc)
                time.sleep(0.25)
                continue
            if self.sdk_version_source == "unknown":
                log.warning(
                    "could not read the daemon version; registered with the minimum "
                    "SDK version %s",
                    MIN_SDK_VERSION,
                )
            return uuid

    def _resolve_sdk_version(self) -> None:
        """Ask a reachable daemon for its version, once."""
        if self.sdk_version_source != "unknown":
            return
        version = resolve_daemon_version(self.manager_socket, timeout_ms=2000)
        if version:
            self.sdk_version = version
            self.sdk_version_source = "daemon"

    def stop(self, timeout: float = 5.0) -> None:
        if self._stopping.is_set():
            return
        self._stopping.set()
        self.core.deregister(self.uuid)
        if self._server is not None:
            # thriftpy2's TThreadedServer.close() only sets a flag; the serve
            # loop is parked in accept() and will not notice until something
            # connects. Without this poke, shutdown costs a full join timeout.
            try:
                self._server.close()
            except Exception as exc:  # noqa: BLE001 - best effort
                log.debug("server close: %s", exc)
            poke_extension_socket(self.socket_path)
        close_extension_socket(self.socket_path)
        for thread in (self._ping_thread, self._server_thread):
            if thread is not None:
                thread.join(timeout=timeout)
        log.info("extension stopped (uuid=%s)", self.uuid)

    # -- threads -----------------------------------------------------------

    def _serve(self) -> None:
        try:
            self._server.serve()
        except Exception:  # noqa: BLE001
            if not self._stopping.is_set():
                log.exception("extension server failed")

    def _ping_loop(self) -> None:
        """Ping the daemon; stop if it disappears.

        The daemon pings *us* for liveness; this loop is the other direction, and
        exists so the extension notices a restarted daemon instead of holding a
        stale registration.
        """
        while not self._stopping.wait(self.ping_interval):
            if not self.core.ping():
                log.warning("osquery daemon is not responding; stopping extension")
                self.request_stop()
                return

    def _await_first_ping(self, timeout: float = 15.0) -> None:
        """Block until the daemon has actually pinged our socket.

        This is the real proof that the extension is reachable at the path the
        daemon expects, and it is the single most common way an extension fails
        silently: it registers, never answers, and is dropped two intervals
        later.
        """
        if self.service.first_ping.wait(timeout):
            log.debug("extension reachable at %s", self.socket_path)
        else:
            log.warning(
                "daemon did not ping %s within %.0fs; it may deregister us",
                self.socket_path,
                timeout,
            )

    def request_stop(self) -> None:
        self._stopping.set()

    @property
    def shutdown_requested(self) -> bool:
        """True once the daemon asked us to shut down (``Extension.shutdown``)."""
        return self.service.shutdown_requested or self._stopping.is_set()

    def _poke_socket(self) -> None:
        """Kept for callers; delegates to the platform-aware poke."""
        poke_extension_socket(self.socket_path)

    # -- convenience -------------------------------------------------------

    def push_config(self, source: str, config: Dict[str, Any]) -> Any:
        """Push config to the daemon and remember it for ``genConfig``."""
        result = self.core.push_config(source, config)
        if result.ok:
            self.service.set_config(source, config)
        return result


def resolve_daemon_version(manager_socket: str, timeout_ms: int = 5000) -> Optional[str]:
    """Ask the daemon for its version, or return ``None`` if it cannot be read.

    The daemon only enforces a *minimum* SDK version, so a guess would be
    accepted - but it would also be indistinguishable from the truth in
    ``osquery_extensions`` and in any OpAMP attribute derived from it. Returning
    ``None`` lets the caller report the minimum it actually knows about and mark
    the value as unresolved, instead of inventing a plausible number.
    """
    client = CoreClient(manager_socket, timeout_ms=timeout_ms)
    try:
        version = client.osquery_info().get("version", "")
        if version:
            return version
    except Exception as exc:  # noqa: BLE001 - the daemon may not be up yet
        log.debug("could not read daemon version: %s", exc)
    finally:
        client.close()
    return None


__all__ = ["OsqueryExtension", "ExtensionService", "DEFAULT_REGISTRY"]
