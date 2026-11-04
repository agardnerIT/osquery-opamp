"""Windows named-pipe transport for osquery's extension Thrift API.

osquery's extension API is a Unix domain socket on POSIX and a **named pipe** on
Windows: ``--extensions_socket`` defaults to ``\\\\.\\pipe\\osquery.em``
(``OSQUERY_SOCKET "osquery.em"`` in ``utils/config/default_paths.h``) and each
extension must serve ``<that>.<uuid>`` (``getExtensionSocket()`` concatenates
with a dot on every platform). Nothing about the wire protocol changes, so only
the transport is platform-specific.

thriftpy2 has no pipe transport (``TSocket`` wraps ``socket.socket`` only), so
this module supplies the two shapes the rest of the stack expects:

* ``WinPipeSocket`` - a socket-shaped object (``connect``/``recv``/``sendall``/
  ``settimeout``) over a pipe HANDLE.
* ``WinPipeServerSocket`` - a ``TServerSocket``-shaped object with
  ``listen``/``accept``/``close``, which ``thriftpy2.server.TThreadedServer``
  accepts because it only ever calls those three methods.

All kernel32 calls go through ``WinPipeApi``. That seam is deliberate: it is
what lets the transport be tested off-Windows, by substituting an in-memory API
with the same nine methods (see ``tests/test_winpipe.py``, which runs a real
Thrift server and client over it). What that cannot cover is the ctypes
bindings themselves, so ``tests/test_windows_daemon.py`` is a real-daemon test
that only runs on Windows.
"""

from __future__ import annotations

import ctypes
import errno
import logging
import time
from typing import Optional

from thriftpy2.transport.base import TTransportBase, TTransportException

log = logging.getLogger(__name__)

# -- Win32 constants (winerror.h) -----------------------------------------

ERROR_FILE_NOT_FOUND = 2
ERROR_ACCESS_DENIED = 5
ERROR_BROKEN_PIPE = 109
ERROR_PIPE_BUSY = 231
ERROR_NO_DATA = 232
ERROR_PIPE_NOT_CONNECTED = 233
ERROR_PIPE_CONNECTED = 535
ERROR_OPERATION_ABORTED = 995

PIPE_ACCESS_DUPLEX = 0x00000003
PIPE_TYPE_BYTE = 0x00000000
PIPE_READMODE_BYTE = 0x00000000
PIPE_WAIT = 0x00000000
PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
PIPE_UNLIMITED_INSTANCES = 255

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
OPEN_EXISTING = 3
NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF

DEFAULT_PIPE_SIZE = 64 * 1024

#: Granularity of the timeout poll. Pipe reads cannot carry a deadline, so a
#: timed read is a ``PeekNamedPipe`` spin. 5ms is cheap next to osquery's
#: 3s ping interval and keeps the handshake responsive.
_POLL_SECONDS = 0.005

_ERRNO = {
    ERROR_FILE_NOT_FOUND: errno.ENOENT,
    ERROR_ACCESS_DENIED: errno.EACCES,
    ERROR_BROKEN_PIPE: errno.EPIPE,
    ERROR_PIPE_BUSY: errno.EBUSY,
    ERROR_NO_DATA: errno.EPIPE,
    ERROR_PIPE_NOT_CONNECTED: errno.EPIPE,
    ERROR_OPERATION_ABORTED: errno.EINTR,
}

#: Errors that mean "the other end is gone" rather than "something is wrong".
_EOF_ERRORS = (ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED)


class WinPipeError(OSError):
    """A kernel32 call failed."""


class WinPipeApi:
    """The nine kernel32 calls the transport needs, via ctypes.

    ``kernel32`` may be injected; when it is, the caller owns the signatures.
    Tests inject a pure-Python double rather than a real DLL.
    """

    def __init__(self, kernel32: Optional[object] = None) -> None:
        if kernel32 is None:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            self._configure(kernel32)
        self._k = kernel32
        self._ctypes = ctypes

    # -- plumbing ----------------------------------------------------------

    def _configure(self, kernel32: object) -> None:
        """Pin argtypes/restypes.

        Without these, ``CreateFileW``'s HANDLE is truncated to a 32-bit int on
        x64 and every subsequent call fails with ERROR_INVALID_HANDLE.
        """
        from ctypes import c_ulong, c_void_p, c_wchar_p

        kernel32.CreateFileW.restype = c_void_p
        kernel32.CreateFileW.argtypes = [
            c_wchar_p, c_ulong, c_ulong, c_void_p, c_ulong, c_ulong, c_void_p
        ]
        kernel32.CreateNamedPipeW.restype = c_void_p
        kernel32.CreateNamedPipeW.argtypes = [
            c_wchar_p, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_void_p
        ]
        kernel32.WaitNamedPipeW.restype = c_ulong
        kernel32.WaitNamedPipeW.argtypes = [c_wchar_p, c_ulong]
        kernel32.ConnectNamedPipe.restype = c_ulong
        kernel32.ConnectNamedPipe.argtypes = [c_void_p, c_void_p]
        kernel32.DisconnectNamedPipe.restype = c_ulong
        kernel32.DisconnectNamedPipe.argtypes = [c_void_p]
        kernel32.ReadFile.restype = c_ulong
        kernel32.ReadFile.argtypes = [c_void_p, c_void_p, c_ulong, c_void_p, c_void_p]
        kernel32.WriteFile.restype = c_ulong
        kernel32.WriteFile.argtypes = [c_void_p, c_void_p, c_ulong, c_void_p, c_void_p]
        kernel32.PeekNamedPipe.restype = c_ulong
        kernel32.PeekNamedPipe.argtypes = [
            c_void_p, c_void_p, c_ulong, c_void_p, c_void_p, c_void_p
        ]
        kernel32.CloseHandle.restype = c_ulong
        kernel32.CloseHandle.argtypes = [c_void_p]

    def _invalid(self) -> int:
        return (1 << (8 * self._ctypes.sizeof(self._ctypes.c_void_p))) - 1

    def _error(self, code: int, what: str) -> WinPipeError:
        return WinPipeError(_ERRNO.get(code, errno.EIO), f"{what} failed (win32 error {code})")

    def _last_error(self, what: str) -> WinPipeError:
        return self._error(self._ctypes.get_last_error(), what)

    # -- the nine calls ----------------------------------------------------

    def create_pipe(self, name: str) -> int:
        """Create a listening instance of ``name``."""
        handle = self._k.CreateNamedPipeW(
            name,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            DEFAULT_PIPE_SIZE,
            DEFAULT_PIPE_SIZE,
            0,
            None,
        )
        if handle in (None, 0, self._invalid()):
            raise self._last_error(f"CreateNamedPipeW({name})")
        return int(handle)

    def open_pipe(self, name: str, timeout_ms: Optional[int] = None) -> int:
        """Connect to ``name`` as a client, waiting for an instance if busy."""
        deadline = None
        if timeout_ms is not None:
            deadline = time.monotonic() + timeout_ms / 1000.0
        while True:
            handle = self._k.CreateFileW(
                name, GENERIC_READ | GENERIC_WRITE, 0, None, OPEN_EXISTING, 0, None
            )
            if handle not in (None, 0, self._invalid()):
                return int(handle)
            err = self._ctypes.get_last_error()
            if err != ERROR_PIPE_BUSY:
                raise self._error(err, f"CreateFileW({name})")
            if deadline is not None and time.monotonic() >= deadline:
                raise self._error(ERROR_PIPE_BUSY, f"CreateFileW({name})")
            wait = NMPWAIT_WAIT_FOREVER
            if deadline is not None:
                wait = max(0, int((deadline - time.monotonic()) * 1000))
            self._k.WaitNamedPipeW(name, wait)

    def connect_pipe(self, handle: int) -> None:
        """Block until a client connects to a listening instance."""
        ok = self._k.ConnectNamedPipe(handle, None)
        if ok:
            return
        err = self._ctypes.get_last_error()
        # A client that connected between CreateNamedPipe and here, or one that
        # has already gone away, both leave us with a connected instance.
        if err in (ERROR_PIPE_CONNECTED, ERROR_NO_DATA):
            return
        raise self._error(err, "ConnectNamedPipe")

    def disconnect_pipe(self, handle: int) -> None:
        self._k.DisconnectNamedPipe(handle)

    def peek(self, handle: int) -> int:
        """Bytes available to read. Raises EPIPE when the peer has closed."""
        avail = self._ctypes.c_ulong(0)
        ok = self._k.PeekNamedPipe(handle, None, 0, None, self._ctypes.byref(avail), None)
        if not ok:
            err = self._ctypes.get_last_error()
            if err in _EOF_ERRORS:
                raise WinPipeError(errno.EPIPE, "pipe closed by peer")
            raise self._error(err, "PeekNamedPipe")
        return int(avail.value)

    def read(self, handle: int, size: int) -> bytes:
        """Read up to ``size`` bytes; b"" means end of stream."""
        buf = self._ctypes.create_string_buffer(size)
        nread = self._ctypes.c_ulong(0)
        ok = self._k.ReadFile(
            handle, buf, size, self._ctypes.byref(nread), None
        )
        if not ok:
            err = self._ctypes.get_last_error()
            if err in _EOF_ERRORS:
                return b""
            raise self._error(err, "ReadFile")
        return buf.raw[: nread.value]

    def write(self, handle: int, data: bytes) -> int:
        written = self._ctypes.c_ulong(0)
        ok = self._k.WriteFile(
            handle, data, len(data), self._ctypes.byref(written), None
        )
        if not ok:
            err = self._ctypes.get_last_error()
            if err in _EOF_ERRORS:
                raise WinPipeError(errno.EPIPE, "pipe closed by peer")
            raise self._error(err, "WriteFile")
        return int(written.value)

    def close_handle(self, handle: int) -> None:
        self._k.CloseHandle(handle)


class WinPipeSocket:
    """A socket-shaped view of a named pipe.

    Only the methods this package uses are implemented: ``connect``,
    ``recv``, ``sendall``, ``settimeout``, ``shutdown``, ``close``, plus
    ``is_open``.
    """

    def __init__(
        self,
        path: Optional[str] = None,
        *,
        handle: Optional[int] = None,
        api: Optional[WinPipeApi] = None,
        timeout: Optional[float] = None,
    ) -> None:
        if path is None and handle is None:
            raise ValueError("WinPipeSocket needs a pipe path or an open handle")
        self.path = path
        self.timeout = timeout
        self._api = api if api is not None else WinPipeApi()
        self._handle = handle

    # -- lifecycle ---------------------------------------------------------

    def connect(self, address: Optional[str] = None) -> None:
        if self._handle is not None:
            return
        name = address or self.path
        if name is None:
            raise ValueError("no pipe path to connect to")
        timeout_ms = None if self.timeout is None else int(self.timeout * 1000)
        self._handle = self._api.open_pipe(name, timeout_ms)

    def is_open(self) -> bool:
        return self._handle is not None

    def settimeout(self, value: Optional[float]) -> None:
        self.timeout = value

    def gettimeout(self) -> Optional[float]:
        return self.timeout

    def shutdown(self, how: int = 0) -> None:  # noqa: ARG002 - socket API shape
        """No-op: a pipe is closed, not half-closed."""

    def close(self) -> None:
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                self._api.close_handle(handle)
            except OSError as exc:  # pragma: no cover - shutdown is best effort
                log.debug("CloseHandle failed: %s", exc)

    # -- data --------------------------------------------------------------

    def recv(self, size: int, flags: int = 0) -> bytes:  # noqa: ARG002
        handle = self._require()
        if size <= 0:
            return b""
        if self.timeout is None:
            return self._api.read(handle, size)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                if self._api.peek(handle):
                    return self._api.read(handle, size)
            except WinPipeError as exc:
                # A closed peer is end-of-stream, not an error: TSocket.read
                # turns b"" into TTransportException(END_OF_FILE) and the
                # Thrift server thread exits cleanly.
                if exc.errno == errno.EPIPE:
                    return b""
                raise
            if time.monotonic() >= deadline:
                raise TimeoutError("timed out waiting for pipe data")
            time.sleep(_POLL_SECONDS)

    def sendall(self, data: bytes) -> None:
        handle = self._require()
        view = memoryview(data)
        while view:
            written = self._api.write(handle, bytes(view))
            if written <= 0:
                raise WinPipeError(errno.EPIPE, "pipe stopped accepting data")
            view = view[written:]

    def _require(self) -> int:
        if self._handle is None:
            raise WinPipeError(errno.EBADF, "pipe is not connected")
        return self._handle


class PipeClientTransport(TTransportBase):
    """thriftpy2 transport over a ``WinPipeSocket``.

    ``read`` returns short reads (the buffered transport above it asks for
    exactly what the protocol needs) and raises ``END_OF_FILE`` when the peer
    closes, which is what ``TSocket`` does.
    """

    def __init__(self, sock: WinPipeSocket) -> None:
        self._sock = sock

    # -- TTransportBase ----------------------------------------------------

    def is_open(self) -> bool:
        return self._sock.is_open()

    def open(self) -> None:
        if not self._sock.is_open():
            self._sock.connect()

    def close(self) -> None:
        self._sock.close()

    def read(self, size: int) -> bytes:
        try:
            data = self._sock.recv(size)
        except TimeoutError as exc:
            raise TTransportException(
                type=TTransportException.TIMED_OUT, message=str(exc)
            ) from exc
        if not data:
            raise TTransportException(
                type=TTransportException.END_OF_FILE, message="pipe closed by peer"
            )
        return data

    def write(self, buf: bytes) -> None:
        try:
            self._sock.sendall(buf)
        except WinPipeError as exc:
            raise TTransportException(
                type=TTransportException.UNKNOWN, message=str(exc)
            ) from exc

    def flush(self) -> None:
        # Byte-mode pipes are unbuffered at this layer; every write is sent.
        pass


class WinPipeServerSocket:
    """The ``TServerSocket`` subset ``TThreadedServer`` uses.

    ``listen`` creates the first instance, ``accept`` blocks in
    ``ConnectNamedPipe`` and returns a connected transport, and the *next*
    instance is created immediately after so a second client is not refused
    while the first is being served.
    """

    def __init__(self, path: str, *, api: Optional[WinPipeApi] = None) -> None:
        self.path = path
        self.closed = False
        self._api = api if api is not None else WinPipeApi()
        self._pending: Optional[int] = None

    def listen(self) -> None:
        if self._pending is None:
            self._pending = self._api.create_pipe(self.path)

    def accept(self) -> PipeClientTransport:
        if self.closed:
            raise WinPipeError(errno.EBADF, "server socket is closed")
        handle = self._pending if self._pending is not None else self._api.create_pipe(self.path)
        self._pending = None
        self._api.connect_pipe(handle)
        try:
            self._pending = self._api.create_pipe(self.path)
        except OSError as exc:  # pragma: no cover - happens iff the pipe name is gone
            log.debug("could not pre-create the next pipe instance: %s", exc)
        if self.closed and self._pending is not None:
            # close() ran while we were in ConnectNamedPipe; do not leak the
            # instance we just created.
            try:
                self._api.close_handle(self._pending)
            finally:
                self._pending = None
        sock = WinPipeSocket(handle=handle, api=self._api)
        return PipeClientTransport(sock)

    def close(self) -> None:
        self.closed = True
        pending, self._pending = self._pending, None
        if pending is not None:
            try:
                self._api.close_handle(pending)
            except OSError as exc:  # pragma: no cover
                log.debug("CloseHandle on the pending instance failed: %s", exc)
        # A thread parked in ConnectNamedPipe does not notice `closed`; connect
        # to ourselves so it returns and the serve loop can exit. Same trick as
        # the Unix socket poke in extension.py.
        try:
            poke_pipe(self.path, api=self._api, timeout=0.2)
        except OSError as exc:
            log.debug("could not unblock ConnectNamedPipe: %s", exc)


def poke_pipe(path: str, *, api: Optional[WinPipeApi] = None, timeout: float = 0.5) -> None:
    """Connect once and disconnect, to wake a blocked ``ConnectNamedPipe``."""
    sock = WinPipeSocket(path, api=api, timeout=timeout)
    try:
        sock.connect()
    finally:
        sock.close()


__all__ = [
    "PipeClientTransport",
    "WinPipeApi",
    "WinPipeError",
    "WinPipeServerSocket",
    "WinPipeSocket",
    "poke_pipe",
]
