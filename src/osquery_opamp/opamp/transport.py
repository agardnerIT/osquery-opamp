"""OpAMP transports: plain HTTP (the default) and WebSocket.

Both are first-class. The spec defines them as alternatives with identical
semantics, and ``transport_for_url`` picks one from the endpoint scheme, so an
agent is configured with a URL and nothing else. HTTP needs no server-side
opt-in (every OpAMP server speaks it); WebSocket needs the server to accept the
upgrade, so it is the *less* portable of the two and should not be a
prerequisite for connecting.

The difference is who initiates a message. On WebSocket the server can push at
any time; on HTTP it can only answer, so a pushed message waits for the agent's
next poll. ``OpampClient`` already polls on its heartbeat interval, so this costs
latency, not correctness.

``Transport`` is a blocking, deadline-based interface on purpose. osquery is a
thread-per-concern program and the extension already owns threads; pulling an
asyncio event loop in would buy nothing and complicate shutdown.
"""

from __future__ import annotations

import logging
import queue
import ssl
import urllib.error
import urllib.request
import uuid
import zlib
from typing import Callable, List, Optional, Protocol

log = logging.getLogger(__name__)

#: Hard ceiling on a reply body, before and after decompression. Mirrors the
#: server's own default (``OPAMP_MAX_MESSAGE_BYTES``); a reply over it is refused
#: rather than buffered, so a broken or hostile server cannot exhaust the agent.
MAX_REPLY_BYTES = 64 * 1024 * 1024

#: Statuses the server answers with a ``ServerToAgent`` body that the agent must
#: still read, rather than with nothing at all.
_WITH_PROTOCOL_BODY = frozenset({400})


class TransportError(RuntimeError):
    """A failed exchange.

    ``status`` and ``retry_after`` carry what the server said, when it said
    anything. ``retry_after`` is the server's own pacing instruction (HTTP
    ``Retry-After`` on a 429/503); ``OpampClient`` prefers it over its own
    exponential backoff, which is the only way overload shedding works: the
    server is asking to be left alone for a specific interval, and guessing at
    that interval hammers it.
    """

    def __init__(
        self,
        message: str,
        *,
        status: Optional[int] = None,
        retry_after: Optional[float] = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def encode_header(value: int = 0) -> bytes:
    """Encode the WebSocket message header (spec: varint, currently always 0)."""
    if value < 0:
        raise ValueError("header must be unsigned")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_header(data: bytes) -> int:
    """Decode the leading varint header, raising on a malformed one.

    Per the spec a compliant decoder SHOULD verify the header is 0 and treat
    anything else as a malformed message, which is what this does.
    """
    value = 0
    shift = 0
    for index, byte in enumerate(data[:10]):
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            if value != 0:
                raise TransportError(f"unsupported OpAMP websocket header {value}")
            return index + 1
        shift += 7
    raise TransportError("truncated OpAMP websocket header")


class Transport(Protocol):
    def connect(self) -> None: ...
    def send(self, payload: bytes) -> None: ...
    def receive(self, timeout: float) -> Optional[bytes]:
        """Return the next message, or None on timeout (a heartbeat tick)."""
        ...

    def close(self) -> None: ...


def _parse_headers(headers: List[str]) -> dict:
    """Turn ``['Name: Value', ...]`` into a dict.

    Same shape ``websocket-client`` takes, so ``--header`` means one thing across
    both transports. The first colon is the separator: bearer tokens and URLs
    both contain colons, header names do not.
    """
    parsed = {}
    for entry in headers:
        name, sep, value = entry.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"expected 'Name: Value', got {entry!r}")
        parsed[name.strip()] = value.strip()
    return parsed


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """``Retry-After`` as seconds, or None when absent/unreadable.

    Only the delta-seconds form is honoured. The HTTP-date form is valid but a
    clock skew between agent and server makes it worse than no answer, and the
    server this has to interoperate with sends seconds.
    """
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None


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
            # Every frame is a varint header (0) followed by the protobuf.
            self._ws.send_binary(encode_header(0) + payload)
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
        if not data:
            return None
        header_len = decode_header(data)
        return data[header_len:]

    def close(self) -> None:
        if self._ws is None:
            return
        try:
            self._ws.close()
        except Exception as exc:  # noqa: BLE001 - shutdown is best effort
            log.debug("websocket close failed: %s", exc)
        finally:
            self._ws = None


class HttpTransport:
    """OpAMP over plain HTTP: one POST per ``AgentToServer``, one reply each.

    The spec's request/reply transport, and the one every OpAMP server supports
    without being asked to. There is no session, so ``connect()`` does no I/O:
    the first POST is the connection, and its failure is already reported as a
    ``TransportError`` by ``send()``.

    Replies are queued rather than returned from ``send()`` because the
    ``Transport`` interface separates the two, and because one ``send`` can be
    followed by several ``receive`` calls in the client's loop. Nothing is lost
    by the split: a reply is available the moment the POST returns.
    """

    def __init__(
        self,
        url: str,
        *,
        headers: Optional[List[str]] = None,
        ca_file: Optional[str] = None,
        hostname: Optional[str] = None,
        timeout: float = 10.0,
        instance_uid: Optional[Callable[[], bytes]] = None,
    ) -> None:
        if hostname:
            raise ValueError(
                "hostname override is only supported for wss:// endpoints; over https://"
                " the certificate must match the URL host"
            )
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"expected an http:// or https:// URL, got {url!r}")

        self.url = url
        self.headers = _parse_headers(headers or [])
        self.ca_file = ca_file
        self.timeout = timeout
        # A callable, not a value: the server may replace the uid mid-run via
        # AgentIdentification, and the header must follow it (spec #76).
        self.instance_uid = instance_uid
        self._replies: "queue.Queue[bytes]" = queue.Queue()
        self._ssl_context: Optional[ssl.SSLContext] = None
        if url.startswith("https://"):
            self._ssl_context = ssl.create_default_context(cafile=ca_file)
            # Never configurable: a management channel must not be downgradable.
            self._ssl_context.check_hostname = True
            self._ssl_context.verify_mode = ssl.CERT_REQUIRED

    # -- lifecycle ---------------------------------------------------------

    def connect(self) -> None:
        """No handshake to perform. Kept for interface parity with WebSocket."""
        log.info("using plain HTTP transport at %s", self.url)

    def close(self) -> None:
        """Drop undelivered replies so a reconnect cannot replay a stale one."""
        while True:
            try:
                self._replies.get_nowait()
            except queue.Empty:
                return

    # -- exchange ----------------------------------------------------------

    def send(self, payload: bytes) -> None:
        headers = dict(self.headers)
        headers["Content-Type"] = "application/x-protobuf"
        headers.setdefault("Accept", "application/x-protobuf")
        # The server gzips large replies when the client says it can read them.
        headers.setdefault("Accept-Encoding", "gzip")
        if self.instance_uid is not None:
            uid = self.instance_uid()
            if uid:
                # Canonical text form, so the server's cross-check (#76) can
                # compare it with the body instead of logging a mismatch.
                headers["OpAMP-Instance-UID"] = str(uuid.UUID(bytes=uid))

        request = urllib.request.Request(self.url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self._ssl_context
            ) as response:
                self._queue(response.read(MAX_REPLY_BYTES + 1), response.headers)
        except urllib.error.HTTPError as exc:
            if exc.code in _WITH_PROTOCOL_BODY:
                # The server explains a refused message in a ServerToAgent
                # (error_response). Losing it would replace "your config is
                # malformed" with "HTTP 400".
                body = exc.read(MAX_REPLY_BYTES + 1)
                if body:
                    self._queue(body, exc.headers)
                    return
            raise self._error(exc) from exc
        except urllib.error.URLError as exc:
            raise TransportError(f"http request failed: {exc.reason}") from exc
        except TimeoutError as exc:
            raise TransportError(f"http request timed out after {self.timeout:.0f}s") from exc
        except OSError as exc:
            raise TransportError(f"http request failed: {exc}") from exc

    def receive(self, timeout: float) -> Optional[bytes]:
        try:
            return self._replies.get(timeout=max(0.0, timeout))
        except queue.Empty:
            # Idle. The client answers this by sending a heartbeat, which is also
            # this transport's poll: one POST per heartbeat_interval.
            return None

    # -- replies -----------------------------------------------------------

    def _queue(self, body: bytes, headers) -> None:
        if not body:
            return
        if len(body) > MAX_REPLY_BYTES:
            raise TransportError(
                f"reply exceeds {MAX_REPLY_BYTES} bytes; refusing to buffer it"
            )
        if (headers.get("Content-Encoding") or "").lower() == "gzip":
            body = _gunzip(body)
        self._replies.put(body)

    def _error(self, exc: urllib.error.HTTPError) -> TransportError:
        status = exc.code
        retry_after = _parse_retry_after(exc.headers.get("Retry-After") if exc.headers else None)
        if status == 401:
            message = (
                "server refused the agent credential (401); pass"
                " --header 'Authorization: Bearer <token>'"
            )
        elif status == 403:
            message = "server refused this agent (403): the credential is not valid for its instance_uid"
        elif status == 413:
            message = "server refused the message as too large (413)"
        elif status == 415:
            message = "server refused an unsupported Content-Encoding (415)"
        elif status in (429, 503):
            message = f"server is unavailable ({status})"
            if retry_after is not None:
                message += f", retry after {retry_after:.0f}s"
        else:
            message = f"http {status}: {exc.reason}"
        return TransportError(message, status=status, retry_after=retry_after)


def _gunzip(body: bytes) -> bytes:
    """Inflate a gzipped reply, bounded at ``MAX_REPLY_BYTES``.

    Bounded because the limit has to hold *after* decompression, and a small
    body that expands to gigabytes is the one way a reply could outgrow the
    ceiling. ``decompress(..., max_length)`` stops at the cap and leaves the
    remainder unread, so a bomb costs a fixed buffer instead of the heap.
    """
    try:
        inflated = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(
            body, MAX_REPLY_BYTES + 1
        )
    except zlib.error as exc:
        raise TransportError(f"reply was not valid gzip: {exc}") from exc
    if len(inflated) > MAX_REPLY_BYTES:
        raise TransportError(
            f"decompressed reply exceeds {MAX_REPLY_BYTES} bytes; refusing to buffer it"
        )
    return inflated


def transport_for_url(
    url: str,
    *,
    headers: Optional[List[str]] = None,
    ca_file: Optional[str] = None,
    hostname: Optional[str] = None,
    timeout: float = 10.0,
    instance_uid: Optional[Callable[[], bytes]] = None,
) -> Transport:
    """Build the transport the endpoint scheme names.

    ``http(s)`` is the spec's default and needs nothing from the server, so it is
    the one to reach for when connecting is more important than push latency.
    ``ws(s)`` is selected only when asked for by scheme: a server that has not
    enabled the upgrade refuses the handshake, so guessing it would turn a
    working configuration into a 403.
    """
    if url.startswith(("http://", "https://")):
        return HttpTransport(
            url,
            headers=headers,
            ca_file=ca_file,
            hostname=hostname,
            timeout=timeout,
            instance_uid=instance_uid,
        )
    return WebSocketTransport(
        url, headers=headers, ca_file=ca_file, hostname=hostname, timeout=timeout
    )


__all__ = [
    "HttpTransport",
    "MAX_REPLY_BYTES",
    "Transport",
    "TransportError",
    "WebSocketTransport",
    "decode_header",
    "encode_header",
    "transport_for_url",
]
