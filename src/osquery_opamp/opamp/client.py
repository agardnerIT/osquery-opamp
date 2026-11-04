"""The connection loop: connect, exchange, reconnect.

Deliberately boring. The spec's hard requirements that shape it:

* the first message after (re)connect is a full state report
* heartbeats at ``heartbeat_interval_seconds`` (30s default) when idle
* retries no faster than 30s, with exponential backoff and jitter
* a graceful shutdown sends ``agent_disconnect`` before closing

Everything about *what* to say lives in ``OpampAgent``; this module only moves
bytes and manages the socket lifecycle.
"""

from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Callable, List, Optional

from .agent import OpampAgent
from .constants import DEFAULT_HEARTBEAT_SECONDS, MIN_RETRY_SECONDS
from .pb import opamp
from .transport import Transport, TransportError

log = logging.getLogger(__name__)


class OpampClient:
    """Runs one agent over one transport, reconnecting as needed."""

    def __init__(
        self,
        agent: OpampAgent,
        transport_factory: Callable[[], Transport],
        *,
        heartbeat_interval: float = DEFAULT_HEARTBEAT_SECONDS,
        retry_interval: float = MIN_RETRY_SECONDS,
        max_retry_interval: float = 300.0,
        jitter: float = 0.2,
        on_message: Optional[Callable[[Any], None]] = None,
        sleep: Callable[[float], None] = time.sleep,
        rng: Optional[random.Random] = None,
    ) -> None:
        self.agent = agent
        self.transport_factory = transport_factory
        self.heartbeat_interval = heartbeat_interval
        # The spec's 30s floor is applied by the caller (see cli), not here, so
        # tests can drive the reconnect path at millisecond scale.
        self.retry_interval = retry_interval
        self.max_retry_interval = max_retry_interval
        self.jitter = jitter
        self.on_message = on_message
        self._sleep = sleep
        self._rng = rng or random.Random()

        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._transport: Optional[Transport] = None
        self.connected = threading.Event()
        self.connection_count = 0
        self.last_error: str = ""

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("client already started")
        self._thread = threading.Thread(target=self._run, name="opamp-client", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10.0) -> None:
        # Spec: the last message an agent sends is agent_disconnect.
        self.send_disconnect()
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # -- main loop ---------------------------------------------------------

    def _run(self) -> None:
        backoff = self.retry_interval
        while not self._stop.is_set():
            transport = None
            try:
                transport = self.transport_factory()
                transport.connect()
                self._transport = transport
                self.connection_count += 1
                self.connected.set()
                self.last_error = ""
                backoff = self.retry_interval

                # Spec: first message after connecting is a full state report.
                self.agent.request_full_state()
                self._send(transport, self.agent.next_message())

                started = time.monotonic()
                self._receive_loop(transport)
                # A connection that survived a while resets the backoff, so a
                # flapping server does not push us into long waits.
                if time.monotonic() - started > 60:
                    backoff = self.retry_interval
            except TransportError as exc:
                self.last_error = str(exc)
                log.warning("opamp transport error: %s", exc)
            except Exception as exc:  # noqa: BLE001 - never let the loop die
                self.last_error = str(exc)
                log.exception("unexpected error in opamp client: %s", exc)
            finally:
                self.connected.clear()
                if transport is not None:
                    transport.close()
                self._transport = None

            if self._stop.is_set():
                break

            delay = self._next_delay(backoff)
            log.info("reconnecting in %.1fs", delay)
            self._stop.wait(delay)
            backoff = min(backoff * 2, self.max_retry_interval)

    def _receive_loop(self, transport: Transport) -> None:
        while not self._stop.is_set():
            payload = transport.receive(self.heartbeat_interval)
            if payload is None:
                # Idle: heartbeat, which is just the current state.
                self._send(transport, self.agent.next_message())
                continue

            message = opamp.ServerToAgent()
            try:
                message.ParseFromString(payload)
            except Exception as exc:  # noqa: BLE001 - a bad frame must not drop us
                log.warning("dropping unparseable ServerToAgent (%d bytes): %s", len(payload), exc)
                continue

            if self.on_message is not None:
                try:
                    self.on_message(message)
                except Exception:  # noqa: BLE001
                    log.exception("on_message callback failed")

            replies: List[Any] = self.agent.handle(message)
            for reply in replies:
                self._send(transport, reply)

    def _send(self, transport: Transport, message: Any) -> None:
        transport.send(message.SerializeToString())

    def _next_delay(self, base: float) -> float:
        spread = base * self.jitter
        return max(MIN_RETRY_SECONDS * 0.0, base + self._rng.uniform(-spread, spread))

    def send_disconnect(self) -> None:
        """Best-effort ``agent_disconnect`` on a live connection."""
        transport = self._transport
        if transport is None:
            return
        try:
            transport.send(self.agent.disconnect_message().SerializeToString())
        except Exception as exc:  # noqa: BLE001
            log.debug("could not send agent_disconnect: %s", exc)


__all__ = ["OpampClient"]
