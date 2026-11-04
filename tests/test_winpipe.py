"""The Windows named-pipe transport, tested off-Windows.

``winpipe.WinPipeApi`` is the seam: the transport never touches kernel32
directly. These tests substitute an in-memory API with the same nine methods,
which lets the real Thrift stack (processor, binary protocol, buffered
transport, `TThreadedServer`) run over the pipe transport on any platform.

What this cannot prove is the ctypes bindings - ``tests/test_windows_daemon.py``
covers those, on Windows only, against a real ``osqueryd``.
"""

from __future__ import annotations

import threading
import time

import pytest
from thriftpy2.protocol import TBinaryProtocolFactory
from thriftpy2.server import TThreadedServer
from thriftpy2.thrift import TClient, TProcessor
from thriftpy2.transport import TBufferedTransportFactory
from thriftpy2.transport.base import TTransportException

from osquery_opamp import osquery_thrift
from osquery_opamp.osquery_thrift import ExtensionStatus
from osquery_opamp.winpipe import (
    PipeClientTransport,
    WinPipeError,
    WinPipeServerSocket,
    WinPipeSocket,
    poke_pipe,
)

_DEADLINE = 3.0


# -- an in-memory kernel32 -------------------------------------------------


class _End:
    """One end of a duplex pipe."""

    def __init__(self) -> None:
        self.cond = threading.Condition()
        self.inbox = bytearray()
        self.peer: "_End | None" = None
        self.closed = False
        self.read_closed = False  # the peer closed: no more data will arrive
        self.listening = False


class _Handle:
    def __init__(self, end: _End) -> None:
        self.end = end


class FakePipeApi:
    """The nine ``WinPipeApi`` methods, over Python objects.

    Semantics deliberately match Win32 for the cases the transport depends on:
    ``CreateFileW`` only finds an *instance* that is listening, ``ConnectNamedPipe``
    blocks until a client opens that instance, and a closed handle makes the peer
    read end-of-stream.
    """

    def __init__(self) -> None:
        self.fds: dict[int, _Handle] = {}
        self.listening: dict[str, list[_End]] = {}
        self._next = 100
        self.max_write = None  # set to an int to force partial writes

    # -- helpers -----------------------------------------------------------

    def _add(self, end: _End) -> int:
        self._next += 1
        self.fds[self._next] = _Handle(end)
        return self._next

    def _handle(self, fd: int) -> _Handle:
        if fd not in self.fds:
            raise WinPipeError(9, "bad file descriptor")
        return self.fds[fd]

    def _wait(self, predicate, what: str) -> None:
        deadline = time.monotonic() + _DEADLINE
        while not predicate():
            if time.monotonic() > deadline:
                raise AssertionError(f"fake pipe timed out waiting for {what}")
            time.sleep(0.002)

    # -- the nine calls ----------------------------------------------------

    def create_pipe(self, name: str) -> int:
        end = _End()
        end.listening = True
        self.listening.setdefault(name, []).append(end)
        return self._add(end)

    def open_pipe(self, name: str, timeout_ms=None) -> int:
        deadline = None if timeout_ms is None else time.monotonic() + timeout_ms / 1000.0

        def available():
            for end in self.listening.get(name, []):
                if end.listening and not end.closed and end.peer is None:
                    return end
            return None

        while True:
            end = available()
            if end is not None:
                break
            if deadline is not None and time.monotonic() > deadline:
                raise WinPipeError(16, "all pipe instances are busy")
            if deadline is None:
                raise WinPipeError(2, f"no pipe named {name}")
            time.sleep(0.002)

        client = _End()
        with end.cond, client.cond:
            end.peer, client.peer = client, end
            end.listening = False
            end.cond.notify_all()
        return self._add(client)

    def connect_pipe(self, handle: int) -> None:
        end = self._handle(handle).end
        self._wait(lambda: end.peer is not None or end.closed, "ConnectNamedPipe")
        if end.closed and end.peer is None:
            raise WinPipeError(22, "pipe instance closed")

    def disconnect_pipe(self, handle: int) -> None:
        self.close_handle(handle)

    def peek(self, handle: int) -> int:
        end = self._handle(handle).end
        with end.cond:
            if end.inbox:
                return len(end.inbox)
            if end.read_closed or end.closed:
                raise WinPipeError(32, "pipe closed by peer")
            return 0

    def read(self, handle: int, size: int) -> bytes:
        end = self._handle(handle).end
        self._wait(lambda: end.inbox or end.read_closed or end.closed, "ReadFile")
        with end.cond:
            if end.inbox:
                data = bytes(end.inbox[:size])
                del end.inbox[:size]
                return data
            return b""

    def write(self, handle: int, data: bytes) -> int:
        end = self._handle(handle).end
        if end.peer is None:
            raise WinPipeError(32, "pipe is not connected")
        with end.peer.cond:
            if end.peer.closed:
                raise WinPipeError(32, "pipe closed by peer")
            chunk = data if self.max_write is None else data[: self.max_write]
            end.peer.inbox.extend(chunk)
            end.peer.cond.notify_all()
            return len(chunk)

    def close_handle(self, handle: int) -> None:
        entry = self.fds.pop(handle, None)
        if entry is None:
            return
        end = entry.end
        with end.cond:
            end.closed = True
            if end.listening:
                for ends in self.listening.values():
                    if end in ends:
                        ends.remove(end)
            peer = end.peer
            end.cond.notify_all()
        if peer is not None:
            with peer.cond:
                peer.read_closed = True
                peer.cond.notify_all()


# -- transport -------------------------------------------------------------


def test_sendall_handles_partial_writes():
    api = FakePipeApi()
    server_fd = api.create_pipe(r"\\.\pipe\t")
    sock = WinPipeSocket(r"\\.\pipe\t", api=api, timeout=2.0)
    sock.connect()

    api.max_write = 3  # a real pipe may accept less than asked for
    sock.sendall(b"0123456789" * 4)

    assert api.read(server_fd, 100) == b"0123456789" * 4
    sock.close()
    api.close_handle(server_fd)


def test_recv_returns_end_of_stream_when_the_peer_closes():
    api = FakePipeApi()
    server_fd = api.create_pipe(r"\\.\pipe\t")
    sock = WinPipeSocket(r"\\.\pipe\t", api=api, timeout=2.0)
    sock.connect()
    sock.sendall(b"hi")
    api.close_handle(server_fd)

    assert sock.recv(16) == b""  # EOF, not an exception: TSocket semantics


def test_recv_times_out_instead_of_blocking_forever():
    api = FakePipeApi()
    api.create_pipe(r"\\.\pipe\t")
    sock = WinPipeSocket(r"\\.\pipe\t", api=api, timeout=0.05)
    sock.connect()

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        sock.recv(16)
    assert time.monotonic() - started < 2.0
    sock.close()


def test_transport_read_raises_end_of_file():
    api = FakePipeApi()
    server_fd = api.create_pipe(r"\\.\pipe\t")
    sock = WinPipeSocket(r"\\.\pipe\t", api=api, timeout=2.0)
    sock.connect()
    trans = PipeClientTransport(sock)
    api.close_handle(server_fd)

    with pytest.raises(TTransportException) as excinfo:
        trans.read(1)
    assert excinfo.value.type == TTransportException.END_OF_FILE


def test_transport_open_connects_lazily():
    api = FakePipeApi()
    api.create_pipe(r"\\.\pipe\t")
    sock = WinPipeSocket(r"\\.\pipe\t", api=api, timeout=2.0)
    trans = PipeClientTransport(sock)
    assert not trans.is_open()

    trans.open()
    assert trans.is_open()
    trans.close()
    assert not trans.is_open()


def test_server_accept_returns_a_connected_transport():
    api = FakePipeApi()
    server = WinPipeServerSocket(r"\\.\pipe\s", api=api)
    server.listen()

    client = WinPipeSocket(r"\\.\pipe\s", api=api, timeout=2.0)
    client.connect()
    transport = server.accept()

    transport.write(b"hello")
    transport.flush()
    assert client.recv(16) == b"hello"

    transport.close()
    client.close()
    server.close()


def test_server_close_unblocks_a_pending_accept():
    api = FakePipeApi()
    server = WinPipeServerSocket(r"\\.\pipe\s", api=api)
    server.listen()

    def accept_forever():
        try:
            server.accept()
        except OSError:
            pass

    thread = threading.Thread(target=accept_forever, daemon=True)
    thread.start()
    time.sleep(0.05)  # let it park in ConnectNamedPipe
    server.close()
    thread.join(timeout=_DEADLINE)
    assert not thread.is_alive(), "close() must unblock accept()"


def test_poke_pipe_connects_and_disconnects():
    api = FakePipeApi()
    api.create_pipe(r"\\.\pipe\p")
    poke_pipe(r"\\.\pipe\p", api=api, timeout=1.0)


# -- the whole Thrift stack over the fake pipe -----------------------------


class _Handler:
    def __init__(self) -> None:
        self.pings = 0
        self.shutdowns = 0

    def ping(self):
        self.pings += 1
        return ExtensionStatus(code=0, message="pong", uuid=42)

    def call(self, registry, item, request):
        return osquery_thrift.ExtensionResponse(
            status=ExtensionStatus(code=0, message=f"{registry}/{item}", uuid=42),
            response=[dict(request)],
        )

    def shutdown(self):
        self.shutdowns += 1


@pytest.fixture
def thrift_over_pipe():
    api = FakePipeApi()
    handler = _Handler()
    pipe = WinPipeServerSocket(r"\\.\pipe\ext", api=api)
    server = TThreadedServer(
        TProcessor(osquery_thrift.Extension, handler),
        pipe,
        iprot_factory=TBinaryProtocolFactory(),
        itrans_factory=TBufferedTransportFactory(),
        daemon=True,
    )
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    try:
        yield api, handler
    finally:
        server.close()
        pipe.close()  # unblocks a serve loop parked in ConnectNamedPipe
        thread.join(timeout=_DEADLINE)


def _client(api, timeout=2.0):
    sock = WinPipeSocket(r"\\.\pipe\ext", api=api, timeout=timeout)
    transport = TBufferedTransportFactory().get_transport(PipeClientTransport(sock))
    transport.open()
    return TClient(osquery_thrift.Extension, TBinaryProtocolFactory().get_protocol(transport))


def test_thrift_rpc_over_a_named_pipe(thrift_over_pipe):
    api, handler = thrift_over_pipe
    client = _client(api)

    status = client.ping()
    assert status.message == "pong"
    assert status.uuid == 42
    assert handler.pings == 1


def test_thrift_round_trip_carries_a_large_payload(thrift_over_pipe):
    """Exercises framing: 64 KiB does not fit in one pipe read or write."""
    api, _ = thrift_over_pipe
    client = _client(api)
    payload = "x" * 65536

    response = client.call("config", "opamp", {"action": "genConfig", "blob": payload})
    assert response.status.code == 0
    assert response.response[0]["blob"] == payload


def test_thrift_handles_several_sequential_connections(thrift_over_pipe):
    """Each accept consumes one instance; a second client must not be refused."""
    api, handler = thrift_over_pipe
    for expected in (1, 2, 3):
        client = _client(api)
        assert client.ping().message == "pong"
        assert handler.pings == expected
        client._oprot.trans.close()
