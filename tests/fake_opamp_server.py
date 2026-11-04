"""A minimal OpAMP server for tests.

Uses the same vendored protobuf stubs as the agent, so a schema mistake shows up
on both sides rather than being hidden by a hand-rolled encoder. The sync
``websockets`` server runs in a background thread, which keeps the tests plain
synchronous code.
"""

from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Dict, List, Optional

from websockets.exceptions import ConnectionClosed
from websockets.sync.server import serve

from osquery_opamp.opamp.pb import opamp

Predicate = Callable[[Any], bool]


class FakeOpampServer:
    def __init__(
        self,
        *,
        server_capabilities: int = (
            opamp.ServerCapabilities_AcceptsStatus
            | opamp.ServerCapabilities_OffersRemoteConfig
            | opamp.ServerCapabilities_AcceptsEffectiveConfig
        ),
        send_initial_state: bool = True,
    ) -> None:
        self.server_capabilities = server_capabilities
        self.send_initial_state = send_initial_state

        self._messages: List[Any] = []
        self._lock = threading.Lock()
        self._connection = None
        self._server = None
        self._thread: Optional[threading.Thread] = None
        self._connected = threading.Event()
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
        except Exception:  # noqa: BLE001
            pass
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
        self._connected.set()
        if self.send_initial_state:
            ws.send(self.server_state().SerializeToString())
        try:
            for raw in ws:
                message = opamp.AgentToServer()
                message.ParseFromString(raw)
                with self._lock:
                    self._messages.append(message)
        except ConnectionClosed:
            pass
        finally:
            self._connection = None

    def server_state(self, **kwargs: Any) -> Any:
        return opamp.ServerToAgent(
            capabilities=self.server_capabilities,
            instance_uid=kwargs.pop("instance_uid", b""),
            **kwargs,
        )

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

    # -- messages ----------------------------------------------------------

    def messages(self) -> List[Any]:
        with self._lock:
            return list(self._messages)

    def clear(self) -> None:
        with self._lock:
            self._messages.clear()

    def send(self, message: Any) -> None:
        connection = self._connection
        if connection is None:
            raise RuntimeError("no agent connected")
        connection.send(message.SerializeToString())

    def drop_connection(self) -> None:
        connection = self._connection
        if connection is not None:
            connection.close()

    # -- conveniences ------------------------------------------------------

    def push_config(
        self,
        config: Dict[str, Any],
        *,
        name: str = "osquery.json",
        content_type: str = "application/json",
        config_hash: Optional[bytes] = None,
    ) -> bytes:
        body = json.dumps(config).encode("utf-8")
        return self.push_raw_config(body, name=name, content_type=content_type, config_hash=config_hash)

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


def decode_query_result(message: Any) -> Dict[str, Any]:
    return json.loads(message.custom_message.data.decode("utf-8"))
