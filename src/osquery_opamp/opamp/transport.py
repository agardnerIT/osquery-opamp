"""OpAMP transports.

Only WebSocket is implemented. The spec's plain-HTTP fallback is deliberately
left out for now: it needs the same state machine, so it can be added behind this
interface later without touching the agent.

``Transport`` is a blocking, deadline-based interface on purpose. osquery is a
thread-per-concern program and the extension already owns threads; pulling an
asyncio event loop in would buy nothing and complicate shutdown.
"""

from __future__ import annotations

import logging
import ssl
from typing import List, Optional, Protocol

log = logging.getLogger(__name__)


class TransportError(RuntimeError):
    pass


class Transport(Protocol):
    def connect(self) -> None: ...
    def send(self, payload: bytes) -> None: ...
    def receive(self, timeout: float) -> Optional[bytes]:
        """Return the next message, or None on timeout (a heartbeat tick)."""
        ...

    def close(self) -> None: ...


class WebSocketTransport:
    """WebSocket transport built on ``websocket-client``.

    ``timeout`` bounds both the handshake and each ``receive``; a receive timeout
    is normal (it is how the agent paces heartbeats) and returns ``None``.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: Optional[List[str]] = None,
        ca_file: Optional[str] = None,
        hostname: Optional[str] = None,
        timeout: float = 10.0,
        insecure_skip_verify: bool = False,
        subprotocols: Optional[List[str]] = None,
    ) -> None:
        if insecure_skip_verify:
            # Not configurable on purpose: a management channel must not be
            # downgradable, and the spec's own connection settings say so.
            raise ValueError("insecure_skip_verify is not supported")
        if not url.startswith(("ws://", "wss://")):
            raise ValueError(f"expected a ws:// or wss:// URL, got {url!r}")

        self.url = url
        self.headers = headers or []
        self.ca_file = ca_file
        self.hostname = hostname
        self.timeout = timeout
        self.subprotocols = subprotocols
        self._ws = None

    def connect(self) -> None:
        import websocket  # imported lazily so the module imports without the dep

        sslopt = None
        if self.url.startswith("wss://"):
            sslopt = {}
            if self.ca_file:
                sslopt["ca_certs"] = self.ca_file
            if self.hostname:
                # Verification stays on; this only overrides the name checked.
                sslopt["server_hostname"] = self.hostname
            sslopt["cert_reqs"] = ssl.CERT_REQUIRED
            sslopt["check_hostname"] = True

        try:
            self._ws = websocket.create_connection(
                self.url,
                timeout=self.timeout,
                header=self.headers,
                sslopt=sslopt,
                subprotocols=self.subprotocols,
            )
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed error
            raise TransportError(f"websocket connect failed: {exc}") from exc
        log.info("connected to %s", self.url)

    def send(self, payload: bytes) -> None:
        if self._ws is None:
            raise TransportError("send() before connect()")
        import websocket

        try:
            self._ws.send_binary(payload)
        except websocket.WebSocketTimeoutException as exc:
            raise TransportError(f"send timed out: {exc}") from exc
        except Exception as exc:  # noqa: BLE001
            raise TransportError(f"send failed: {exc}") from exc

    def receive(self, timeout: float) -> Optional[bytes]:
        if self._ws is None:
            raise TransportError("receive() before connect()")
        import websocket

        self._ws.settimeout(timeout)
        try:
            opcode, data = self._ws.recv_data(control_frame=True)
        except websocket.WebSocketTimeoutException:
            return None
        except Exception as exc:  # noqa: BLE001
            raise TransportError(f"receive failed: {exc}") from exc

        if opcode in (websocket.ABNF.OPCODE_CLOSE, websocket.ABNF.OPCODE_PING, websocket.ABNF.OPCODE_PONG):
            if opcode == websocket.ABNF.OPCODE_CLOSE:
                raise TransportError("server closed the connection")
            # websocket-client answers pings itself; ignore control frames here.
            return None
        if isinstance(data, str):
            data = data.encode("utf-8")
        return data

    def close(self) -> None:
        if self._ws is None:
            return
        try:
            self._ws.close()
        except Exception as exc:  # noqa: BLE001 - shutdown is best effort
            log.debug("websocket close failed: %s", exc)
        finally:
            self._ws = None


__all__ = ["Transport", "TransportError", "WebSocketTransport"]
