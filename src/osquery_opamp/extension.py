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

from .configcache import CachedConfig, ConfigCache
from .core import CoreClient, CoreError
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

#: How many consecutive failed pings mean "the daemon is gone", not "one RPC
#: timed out". The daemon itself drops us after two missed pings, so one is too
#: trigger-happy and three is slower than the daemon's own timeout.
PING_FAILURES_BEFORE_REREGISTER = 2


class ExtensionService:
    """Implementation of the daemon-facing ``Extension`` Thrift service.

    The daemon calls ``ping()`` for liveness and ``call()`` when one of the
    registry items this extension advertised is invoked. ``genConfig`` is not a
    fallback: with ``--config_plugin=opamp`` it is how the daemon gets its config
    at every boot, so what it answers has to outlive this process. The body the
    daemon accepted is therefore served from RAM first and from
    :class:`~osquery_opamp.configcache.ConfigCache` second, which is what makes a
    restart (of the extension, the daemon, or the host) keep the fleet's config
    instead of reverting to whatever ``--config_path`` holds.
    """

    def __init__(self, cache: Optional[ConfigCache] = None) -> None:
        self.uuid: int = 0
        self.ping_count: int = 0
        self.first_ping: threading.Event = threading.Event()
        self._lock = threading.Lock()
        self._config_ready = threading.Condition(self._lock)
        self._config_by_source: Dict[str, str] = {}
        self._shutdown = threading.Event()
        self.on_shutdown: Optional[Callable[[], None]] = None

        #: Durable copy of the last applied config (``None`` disables persistence).
        self.cache: Optional[ConfigCache] = cache
        #: Version string recorded in the cache entry, for "which agent wrote this".
        self.agent_version: str = ""
        self._cache_lock = threading.Lock()
        self._entry: Optional[CachedConfig] = None
        self._entry_loaded = False

        #: Source a bare ``genConfig`` (the daemon sends no ``source`` when this
        #: extension is the active config plugin) is answered from.
        self.default_source: str = EXTENSION_NAME
        #: How long ``genConfig`` may block waiting for the first OpAMP config.
        self.pull_wait: float = 0.0

    # -- state -------------------------------------------------------------

    @property
    def cache_path(self) -> str:
        """Where the config is persisted, or a phrase saying it is not."""
        if self.cache is None or self.cache.path is None:
            return "no persistent config cache"
        return str(self.cache.path)

    def set_config(self, source: str, config: Dict[str, Any]) -> None:
        """Remember a config given as data (tests, ``push_config``)."""
        self.set_config_body(source, json.dumps(config))

    def set_config_body(
        self,
        source: str,
        body: str,
        *,
        content_type: str = "",
        config_hash: str = "",
    ) -> None:
        """Remember the exact body the daemon accepted, and persist it.

        The body is a **string**, not a dict: this is the text osquery parsed, and
        re-serialising it would change the bytes for no benefit. ``config_hash``
        is the server's opaque value in hex; when it is omitted and the body is
        unchanged, the previous hash is kept, and when the body is new the hash is
        dropped rather than left describing a config that is no longer current.
        """
        previous = self.cached_entry()
        entry = CachedConfig(
            source=source,
            body=body,
            content_type=content_type or (
                previous.content_type if previous is not None else "application/json"
            ),
            config_hash=config_hash or (
                previous.config_hash
                if previous is not None and previous.body == body
                else ""
            ),
            agent_version=self.agent_version
            or (previous.agent_version if previous is not None else ""),
        )
        with self._cache_lock:
            self._entry = entry
            self._entry_loaded = True
        with self._config_ready:
            self._config_by_source[source] = body
            self._config_ready.notify_all()
        if self.cache is not None:
            self.cache.save(entry)

    def cached_entry(self) -> Optional[CachedConfig]:
        """The last applied config with its metadata, from RAM or from disk."""
        with self._cache_lock:
            if not self._entry_loaded:
                self._entry = self.cache.load() if self.cache is not None else None
                self._entry_loaded = True
            return self._entry

    def cached_config(self, source: str) -> Optional[str]:
        """The body to serve for ``source``, memory first, durable cache second."""
        with self._lock:
            body = self._config_by_source.get(source)
        if body is not None:
            return body
        entry = self.cached_entry()
        if entry is None or entry.source != source:
            return None
        # Seed the in-memory copy so the next ``genConfig`` is a dict lookup. This
        # is the cold-start path: a daemon that booted before the OpAMP server was
        # reachable is answered from disk, not with a failure.
        with self._lock:
            self._config_by_source.setdefault(source, entry.body)
        return entry.body

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
                    log.warning(
                        "no config to serve for source %r (%s); reporting a failed "
                        "refresh so osquery keeps its current state",
                        source,
                        self.cache_path,
                    )
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
        config_cache: Optional[ConfigCache] = None,
        reregister_wait: float = 300.0,
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

        self.service = ExtensionService(config_cache)
        self.service.default_source = source
        self.service.pull_wait = pull_wait
        self.service.agent_version = version
        self.core = CoreClient(manager_socket)
        self.uuid: int = 0
        self.socket_path: str = ""

        #: How long to keep trying to register again after the daemon restarts.
        #: A restart drops the registration, and a deployment with
        #: ``--extensions_require=opamp`` needs this process back before the daemon
        #: gives up and exits - so "retry" is the correct answer to a dead daemon,
        #: not "shut down".
        self.reregister_wait = reregister_wait
        #: Called after a successful re-registration (the agent uses it to re-send
        #: full state, so the server sees the new daemon's truth immediately).
        self.on_reregistered: Optional[Callable[[], None]] = None
        self._ping_failures = 0

        self._server: Any = None
        self._server_thread: Optional[threading.Thread] = None
        self._server_lock = threading.Lock()
        self._ping_thread: Optional[threading.Thread] = None
        self._stopping = threading.Event()
        # The daemon's own "please shut down" is a restart signal, not a decision
        # to exit: see _note_daemon_shutdown.
        self.service.on_shutdown = self._note_daemon_shutdown

    # -- lifecycle ---------------------------------------------------------

    def start(self, wait_for_ping: bool = True, wait: float = 0.0) -> int:
        """Register, start serving, and start the liveness thread.

        Returns the route UUID. Raises ``CoreError`` if the daemon refuses the
        registration (usually a duplicate extension name).

        ``wait`` is one budget for both ways registration can fail, because both
        have the same answer - keep trying:

        * the manager socket is not there yet: the daemon may still be starting, or
          it is waiting for us via ``--extensions_require``;
        * the daemon still has a route for this name, held by a previous process
          that is either dead (dropped after two missed pings) or **still running**.
          The second case can never succeed, so the budget doubles as the time limit
          for telling the operator to stop the other copy.
        """
        self.uuid = self._register(wait)
        self._bind_server()

        if wait_for_ping:
            self._await_first_ping()

        self._ping_thread = threading.Thread(
            target=self._ping_loop, name="osquery-extension-ping", daemon=True
        )
        self._ping_thread.start()
        return self.uuid

    def _bind_server(self) -> None:
        """Serve the ``Extension`` service at ``<manager>.em.<uuid>``.

        Separated from :meth:`start` because a daemon restart gives us a **new**
        uuid and therefore a new socket path: re-registration has to rebind, not
        just remember a number.
        """
        with self._server_lock:
            self.service.uuid = self.uuid
            self.socket_path = extension_socket_path(self.manager_socket, self.uuid)
            self._server = make_extension_server(self.socket_path, self.service)
            self._server_thread = threading.Thread(
                target=self._serve, name="osquery-extension-server", daemon=True
            )
            self._server_thread.start()
        log.info(
            "registered extension %s (uuid=%s, sdk=%s) at %s",
            self.name,
            self.uuid,
            self.sdk_version,
            self.socket_path,
        )

    def _unbind_server(self, timeout: float = 5.0) -> None:
        """Stop serving, and remove the socket so a new uuid can be bound."""
        with self._server_lock:
            server, thread, path = self._server, self._server_thread, self.socket_path
            self._server = None
            self._server_thread = None
        if server is not None:
            # thriftpy2's TThreadedServer.close() only sets a flag; the serve
            # loop is parked in accept() and will not notice until something
            # connects. Without this poke, shutdown costs a full join timeout.
            try:
                server.close()
            except Exception as exc:  # noqa: BLE001 - best effort
                log.debug("server close: %s", exc)
            poke_extension_socket(path)
        close_extension_socket(path)
        if thread is not None:
            thread.join(timeout=timeout)

    def _register(self, wait: float, duplicate_wait: Optional[float] = None) -> int:
        """Register with the daemon, retrying transient failures.

        One deadline for both failure modes (see :meth:`start`). A duplicate is not
        retried forever: while the other process is alive the daemon will keep
        refusing, and a boot loop that never says why is worse than a failure that
        names the cause.
        """
        deadline = time.monotonic() + wait
        duplicate_deadline = time.monotonic() + (wait if duplicate_wait is None else duplicate_wait)
        duplicate_seen = False
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
                    duplicate_seen = True
                    if now >= duplicate_deadline:
                        raise CoreError(
                            f"cannot register extension {self.name!r}: the daemon still "
                            f"has a registration for it after {wait:g}s. Another copy of "
                            "this extension is running and still answering the daemon's "
                            "pings - stop that process (the daemon drops a dead one after "
                            "two missed pings, so a crash recovers on its own and a live "
                            "duplicate never does)"
                        ) from exc
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
            if duplicate_seen:
                # Worth a line: it means a previous copy of this extension was still
                # registered when we started, which is how a botched upgrade looks.
                log.info(
                    "registered %r after the daemon dropped the previous route",
                    self.name,
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
        self._unbind_server(timeout=timeout)
        # The ping thread may be parked in _reregister(); _stopping breaks it out.
        if self._ping_thread is not None:
            self._ping_thread.join(timeout=timeout)
        log.info("extension stopped (uuid=%s)", self.uuid)

    # -- threads -----------------------------------------------------------

    def _serve(self) -> None:
        try:
            self._server.serve()
        except Exception:  # noqa: BLE001
            if not self._stopping.is_set():
                log.exception("extension server failed")

    def _ping_loop(self) -> None:
        """Ping the daemon; re-register when it restarts.

        The daemon pings *us* for liveness; this loop is the other direction. When
        it fails, the daemon is usually restarting rather than gone for good - and in
        a deployment using ``--extensions_require=opamp`` this process exiting is
        precisely what makes the daemon give up and exit too. So a dead daemon means
        "register again", not "shut down".

        One failed ping is not enough: an RPC that timed out under load, or a restart
        we called the ping in the middle of, must not tear down a healthy
        registration.
        """
        while not self._stopping.wait(self.ping_interval):
            if self._daemon_knows_us():
                self._ping_failures = 0
                continue
            self._ping_failures += 1
            if self._ping_failures < PING_FAILURES_BEFORE_REREGISTER:
                log.warning(
                    "osquery daemon did not answer a ping (failure %d/%d)",
                    self._ping_failures,
                    PING_FAILURES_BEFORE_REREGISTER,
                )
                continue
            log.warning(
                "osquery daemon is gone; re-registering (a restart is the normal "
                "case, and the daemon needs this extension back if it requires it)"
            )
            if not self._reregister():
                log.error(
                    "could not re-register with osqueryd within %.0fs; stopping extension",
                    self.reregister_wait,
                )
                self.request_stop()
                return

    def _daemon_knows_us(self) -> bool:
        """Is the daemon still there **and** still holding our registration?

        Both halves matter. A daemon that answers ``ping()`` but no longer has our
        route is a daemon that just restarted, and that is the common case of all:
        ``osqueryctl restart`` finishes in about a second, so the next ping succeeds
        against the new process while the old route is gone for good. Checking only
        the ping leaves the extension silently unregistered until the daemon's own
        watcher gives up on the socket nobody serves.
        """
        if not self.core.ping():
            return False
        knows = getattr(self.core, "is_registered", None)
        if knows is None:  # a core that cannot answer is not evidence of a problem
            return True
        try:
            return bool(knows(self.uuid))
        except Exception as exc:  # noqa: BLE001 - counted as a failure and retried
            log.debug("could not read the daemon's extension list: %s", exc)
            return False

    def _reregister(self) -> bool:
        """Re-register after a daemon restart, rebinding the extension socket.

        The old route is gone with the old daemon, so a successful ``register``
        returns a **new** uuid and the service has to move to
        ``<manager>.em.<new uuid>``: keeping the old one would leave the daemon
        pinging a socket nobody serves and dropping us two intervals later.

        ``register`` failing while the route is still held is expected for a few
        seconds in the other direction (the daemon restarted but the route survived),
        and while *our own* previous route is still live, so the loop backs off
        instead of giving up.
        """
        self._unbind_server()
        deadline = time.monotonic() + self.reregister_wait
        delay = 0.5
        attempt = 0
        while not self._stopping.is_set():
            if time.monotonic() >= deadline:
                return False
            attempt += 1
            self._resolve_sdk_version()
            try:
                uuid = self.core.register(
                    name=self.name,
                    version=self.version,
                    sdk_version=self.sdk_version,
                    min_sdk_version=self.min_sdk_version,
                    registry=self.registry,
                )
            except Exception as exc:  # noqa: BLE001 - daemon may still be coming up
                log.debug(
                    "re-registration attempt %d failed (%s); retrying in %.1fs",
                    attempt,
                    exc,
                    delay,
                )
                if self._stopping.wait(delay):
                    return False
                delay = min(delay * 2, 10.0)
                continue

            self.uuid = uuid
            self._ping_failures = 0
            self._bind_server()
            log.info(
                "re-registered %s as uuid=%s at %s after the daemon restarted",
                self.name,
                uuid,
                self.socket_path,
            )
            if self.on_reregistered is not None:
                try:
                    self.on_reregistered()
                except Exception as exc:  # noqa: BLE001 - never undo a registration
                    log.warning("re-register callback failed: %s", exc)
            return True
        return False

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

    def _note_daemon_shutdown(self) -> None:
        """The daemon is going away. Treat it as a restart, not as an exit.

        osquery sends ``Extension.shutdown()`` to every registered extension as part
        of its own shutdown, so a clean ``osqueryctl restart`` would otherwise take
        the agent down with it - and a deployment with ``--extensions_require=opamp``
        then has a daemon exiting because nothing registered. Prompting the
        supervisor to act on the next tick is better than waiting for two failed
        pings, and much better than exiting.

        If the daemon never comes back, :meth:`_reregister` gives up after
        ``reregister_wait`` and the extension stops, which is the honest end state.
        """
        if self._stopping.is_set():
            return
        log.warning(
            "osqueryd asked the extension to shut down (a restart, normally); "
            "staying up so the daemon finds its config plugin when it returns"
        )
        self._ping_failures = PING_FAILURES_BEFORE_REREGISTER

    @property
    def shutdown_requested(self) -> bool:
        """True once *this* process has decided to stop.

        Deliberately not the daemon's ``Extension.shutdown()``: that arrives on every
        ordinary ``osqueryctl restart``, and exiting on it is what left a
        ``--extensions_require`` daemon with no config plugin. :attr:`_stopping` is
        set by a signal, by :meth:`request_stop`, or by a re-registration that ran out
        of time.
        """
        return self._stopping.is_set()

    def _poke_socket(self) -> None:
        """Kept for callers; delegates to the platform-aware poke."""
        poke_extension_socket(self.socket_path)

    # -- convenience -------------------------------------------------------

    def push_config(self, source: str, config: Dict[str, Any]) -> Any:
        """Push config to the daemon and remember it for ``genConfig``.

        Only used by callers that have a config but no OpAMP hash (tests, one-off
        tooling). The agent's own apply path uses ``push_config_raw`` on the core
        and :meth:`ExtensionService.set_config_body`, so the body persisted for the
        next boot is the byte-for-byte text the daemon accepted, hash included.
        """
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
