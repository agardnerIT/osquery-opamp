"""Minimal OpAMP servers for tests: one WebSocket, one plain HTTP.

Both use the same vendored protobuf stubs as the agent, so a schema mistake shows
up on both sides rather than being hidden by a hand-rolled encoder. Both run in a
background thread, which keeps the tests plain synchronous code.

They differ in exactly the way the transports differ: ``FakeOpampServer`` pushes
the moment ``send()`` is called, while ``FakeHttpOpampServer`` can only answer a
request, so ``send()`` queues the message for the agent's next poll.
"""

from __future__ import annotations

import gzip
import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

from websockets.exceptions import ConnectionClosed
from websockets.sync.server import serve

from osquery_opamp.opamp.pb import opamp
from osquery_opamp.opamp.transport import decode_header, encode_header

log = logging.getLogger(__name__)

Predicate = Callable[[Any], bool]

#: What a fake server advertises unless a test says otherwise.
DEFAULT_CAPABILITIES = (
    opamp.ServerCapabilities_AcceptsStatus
    | opamp.ServerCapabilities_OffersRemoteConfig
    | opamp.ServerCapabilities_AcceptsEffectiveConfig
)


class _RecordingServer:
    """Bookkeeping and the ``ServerToAgent`` builders, shared by both fakes."""

    def __init__(self, *, server_capabilities: int = DEFAULT_CAPABILITIES) -> None:
        self.server_capabilities = server_capabilities
        self._messages: List[Any] = []
        self._lock = threading.Lock()
        self._connected = threading.Event()

    # Every concrete server records inbound messages and knows when one arrives.
    def _record(self, message: Any) -> None:
        with self._lock:
            self._messages.append(message)
        self._connected.set()

    def connect(self) -> None:
        self._connected.set()

    def wait_for_connection(self, timeout: float = 15.0) -> None:
        if not self._connected.wait(timeout):
            raise TimeoutError("agent never connected")

    def wait_for(self, predicate: Predicate, timeout: float = 15.0, description: str = "") -> Any:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for message in self.messages():
                if predicate(message):
                    return message
            time.sleep(0.02)
        raise AssertionError(f"no matching AgentToServer within {timeout}s: {description}")

    def messages(self) -> List[Any]:
        with self._lock:
            return list(self._messages)

    def clear(self) -> None:
        with self._lock:
            self._messages.clear()

    # -- ServerToAgent builders -------------------------------------------

    def server_state(self, **kwargs: Any) -> Any:
        return opamp.ServerToAgent(
            capabilities=self.server_capabilities,
            instance_uid=kwargs.pop("instance_uid", b""),
            **kwargs,
        )

    def push_config(
        self,
        config: Dict[str, Any],
        *,
        name: str = "osquery.json",
        content_type: str = "application/json",
        config_hash: Optional[bytes] = None,
    ) -> bytes:
        body = json.dumps(config).encode("utf-8")
        return self.push_raw_config(
            body, name=name, content_type=content_type, config_hash=config_hash
        )

    def push_raw_config(
        self,
        body: bytes,
        *,
        name: str = "osquery.json",
        content_type: str = "application/json",
        config_hash: Optional[bytes] = None,
    ) -> bytes:
        remote = opamp.AgentRemoteConfig(
            config=opamp.AgentConfigMap(
                config_map={name: opamp.AgentConfigObject(body=body, content_type=content_type)}
            ),
            config_hash=config_hash or b"",
        )
        self.send(self.server_state(remote_config=remote))
        return body

    def push_withdrawal(self, config_hash: bytes = b"withdrawn") -> bytes:
        """Withdraw the remote config: an empty `config_map`, which is the spec's
        "run your own config" (the reference server sends exactly this)."""
        remote = opamp.AgentRemoteConfig(
            config=opamp.AgentConfigMap(), config_hash=config_hash
        )
        self.send(self.server_state(remote_config=remote))
        return config_hash

    def send_query(self, sql: str, request_id: str = "q-1") -> None:
        self.send(
            self.server_state(
                custom_message=opamp.CustomMessage(
                    capability="com.osquery.query",
                    type="run",
                    data=json.dumps({"id": request_id, "sql": sql}).encode("utf-8"),
                )
            )
        )

    def request_full_state(self) -> None:
        self.send(self.server_state(flags=opamp.ServerToAgentFlags_ReportFullState))

    def send_restart(self) -> None:
        self.send(self.server_state(command=opamp.ServerToAgentCommand(type=opamp.CommandType_Restart)))

    def identify_as(self, uid: bytes) -> None:
        self.send(self.server_state(agent_identification=opamp.AgentIdentification(new_instance_uid=uid)))


class FakeOpampServer(_RecordingServer):
    """WebSocket. ``send()`` writes to the live connection immediately."""

    def __init__(
        self,
        *,
        server_capabilities: int = DEFAULT_CAPABILITIES,
        send_initial_state: bool = True,
    ) -> None:
        super().__init__(server_capabilities=server_capabilities)
        self.send_initial_state = send_initial_state
        self._connection = None
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self.connection_count = 0
        self.url: str = ""

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> str:
        self._server = serve(self._handler, "127.0.0.1", 0)
        port = self._server.socket.getsockname()[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"ws://127.0.0.1:{port}"
        return self.url

    def stop(self) -> None:
        try:
            if self._connection is not None:
                self._connection.close()
        except Exception as exc:  # noqa: BLE001 - shutdown is best effort
            log.debug("closing the agent connection failed: %s", exc)
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "FakeOpampServer":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # -- connection --------------------------------------------------------

    def _handler(self, ws: Any) -> None:
        self._connection = ws
        self.connection_count += 1
        self.connect()
        if self.send_initial_state:
            self._send_framed(ws, self.server_state())
        try:
            for raw in ws:
                # Enforce the spec's framing: a varint header (0) then protobuf.
                header_len = decode_header(raw)
                message = opamp.AgentToServer()
                message.ParseFromString(raw[header_len:])
                self._record(message)
        except ConnectionClosed:
            pass
        finally:
            self._connection = None

    # -- messages ----------------------------------------------------------

    def send(self, message: Any) -> None:
        connection = self._connection
        if connection is None:
            raise RuntimeError("no agent connected")
        self._send_framed(connection, message)

    @staticmethod
    def _send_framed(connection: Any, message: Any) -> None:
        connection.send(encode_header(0) + message.SerializeToString())

    def drop_connection(self) -> None:
        connection = self._connection
        if connection is not None:
            connection.close()


class FakeHttpOpampServer(_RecordingServer):
    """Plain HTTP. ``send()`` queues a message for the agent's next poll.

    The server can only speak when spoken to, so a queued ``ServerToAgent`` is
    merged into the reply to the next ``POST /v1/opamp`` — which is what the real
    server does with a config push, and the reason a push over HTTP lands one
    heartbeat later than it would over a socket.
    """

    def __init__(
        self,
        *,
        server_capabilities: int = DEFAULT_CAPABILITIES,
        gzip_replies: bool = False,
    ) -> None:
        super().__init__(server_capabilities=server_capabilities)
        self.gzip_replies = gzip_replies
        self._pending: List[Any] = []
        self._pending_lock = threading.Lock()
        self._requests: List[Dict[str, str]] = []
        self._failure: Optional[Tuple[int, Dict[str, str], bytes]] = None
        self._httpd: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self.request_count = 0
        self.url = ""

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> str:
        server = self

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_POST(self) -> None:  # noqa: N802 - stdlib naming
                length = int(self.headers.get("Content-Length") or 0)
                server._handle(self, self.rfile.read(length))

            def log_message(self, *args: Any) -> None:
                log.debug("fake opamp server: %s", args)

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.daemon_threads = True
        port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://127.0.0.1:{port}/v1/opamp"
        return self.url

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def __enter__(self) -> "FakeHttpOpampServer":
        self.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.stop()

    # -- request handling --------------------------------------------------

    def _handle(self, handler: BaseHTTPRequestHandler, body: bytes) -> None:
        if handler.path != "/v1/opamp":
            handler.send_response(404)
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return

        with self._lock:
            self._requests.append(dict(handler.headers.items()))
            self.request_count += 1

        failure = self._failure
        if failure is not None:
            # One-shot: the next request is refused, and the one after it is
            # served normally, which is what makes "recovered" testable.
            self._failure = None
            status, headers, payload = failure
            handler.send_response(status)
            for name, value in headers.items():
                handler.send_header(name, value)
            handler.send_header("Content-Length", str(len(payload)))
            handler.end_headers()
            handler.wfile.write(payload)
            return

        message = opamp.AgentToServer()
        message.ParseFromString(body)
        self._record(message)

        reply = self.server_state()
        with self._pending_lock:
            pending, self._pending = self._pending, []
        for queued in pending:
            # protobuf merge: singular sub-messages merge, repeated fields append.
            reply.MergeFromString(queued.SerializeToString())

        payload = reply.SerializeToString()
        encoding = {}
        if self.gzip_replies:
            # The real server does this for large replies when the client says it
            # accepts gzip, which the agent always does.
            payload = gzip.compress(payload)
            encoding["Content-Encoding"] = "gzip"
        handler.send_response(200)
        handler.send_header("Content-Type", "application/x-protobuf")
        handler.send_header("Content-Length", str(len(payload)))
        for name, value in encoding.items():
            handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(payload)

    # -- messages ----------------------------------------------------------

    def send(self, message: Any) -> None:
        with self._pending_lock:
            self._pending.append(message)

    def fail_next(
        self,
        status: int = 503,
        headers: Optional[Dict[str, str]] = None,
        body: bytes = b"",
    ) -> None:
        """Refuse the *next* request, the way the real server sheds load (#78).

        ``body`` is what a 400 carries: a ``ServerToAgent`` explaining the refusal.
        """
        self._failure = (status, dict(headers or {}), body)

    def clear_failure(self) -> None:
        self._failure = None

    def requests(self) -> List[Dict[str, str]]:
        with self._lock:
            return list(self._requests)

    def header_of(self, name: str) -> Optional[str]:
        """The last value seen for a request header, case-insensitively."""
        for headers in reversed(self.requests()):
            for key, value in headers.items():
                if key.lower() == name.lower():
                    return value
        return None


def decode_query_result(message: Any) -> Dict[str, Any]:
    return json.loads(message.custom_message.data.decode("utf-8"))
