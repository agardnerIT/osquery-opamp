"""Typed access to osquery's extension Thrift API.

osquery extensions talk to the daemon over a Unix domain socket - a named pipe
on Windows - using the service definitions in ``vendor/osquery.thrift``. The
daemon exposes ``ExtensionManager`` (which extends ``Extension``) at
``--extensions_socket``, and *pings each registered extension* at
``<extensions_socket>.<uuid>``, so an extension must also serve the
``Extension`` service on that path or it will be deregistered after two failed
pings.

The path arithmetic is platform-independent (``getExtensionSocket()`` in
``osquery/extensions/extensions.h`` is just string concatenation), but the
transport is not: POSIX uses ``AF_UNIX``, Windows uses named pipes. See
``winpipe.py`` for the latter.

The IDL is vendored rather than referenced from an osquery checkout so this
package has no build-time dependency on the osquery source tree.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import thriftpy2
from thriftpy2.rpc import make_client, make_server

VENDOR_DIR = Path(__file__).resolve().parent.parent.parent / "vendor"
IDL_PATH = VENDOR_DIR / "osquery.thrift"

#: Minimum SDK version the daemon enforces (osquery/extensions/interface.cpp
#: kSDKVersionChanges). Any version >= this is accepted; the daemon does not
#: check for an upper bound.
MIN_SDK_VERSION = "1.7.7"

#: The name this package reports to the daemon.
EXTENSION_NAME = "opamp"

osquery_thrift = thriftpy2.load(str(IDL_PATH), module_name="osquery_ext_thrift")

Extension = osquery_thrift.Extension
ExtensionManager = osquery_thrift.ExtensionManager
ExtensionStatus = osquery_thrift.ExtensionStatus
ExtensionResponse = osquery_thrift.ExtensionResponse
InternalExtensionInfo = osquery_thrift.InternalExtensionInfo

#: ExtensionCode values, mirroring the IDL enum.
EXT_SUCCESS = 0
EXT_FAILED = 1
EXT_FATAL = 2


def is_windows() -> bool:
    """True on Windows, where osquery's extension API is a named pipe."""
    return sys.platform.startswith("win") or os.name == "nt"


def default_manager_socket() -> str:
    """The daemon's extension socket path, matching osquery's own default.

    ``OSQUERY_SOCKET`` (``utils/config/default_paths.h``) is ``/var/osquery/``
    on macOS, ``/run/osquery/`` or ``/var/osquery/`` on Linux depending on the
    package, and ``\\\\.\\pipe\\`` on Windows. Callers should pass
    ``--extensions_socket`` explicitly in almost every case.
    """
    env = os.environ.get("OSQUERY_EXTENSIONS_SOCKET")
    if env:
        return env
    if is_windows():
        # OSQUERY_SOCKET "osquery.em" on Windows: \\.\pipe\osquery.em
        return r"\\.\pipe\osquery.em"
    return "/var/osquery/osquery.em"


def extension_socket_path(manager_socket: str, uuid: int) -> str:
    """Where the daemon expects *this* extension to listen.

    Mirrors ``getExtensionSocket()`` in ``osquery/extensions/extensions.h``:
    ``(uuid == 0) ? path : path + "." + uuid``.
    """
    return manager_socket if uuid == 0 else f"{manager_socket}.{uuid}"


def make_manager_client(manager_socket: str, timeout_ms: int = 5000) -> Any:
    """Create a client for the daemon's ``ExtensionManager`` service.

    Raises ``thriftpy2.transport.base.TTransportException`` when the socket is
    missing or the daemon is not listening.
    """
    if not is_windows():
        return make_client(
            ExtensionManager, unix_socket=manager_socket, timeout=timeout_ms
        )

    # Windows: the same client over a named pipe. Connection happens in
    # transport.open(), mirroring thriftpy2.rpc.make_client.
    from thriftpy2.protocol import TBinaryProtocolFactory
    from thriftpy2.thrift import TClient
    from thriftpy2.transport import TBufferedTransportFactory

    from .winpipe import PipeClientTransport, WinPipeSocket

    sock = WinPipeSocket(manager_socket, timeout=timeout_ms / 1000.0 if timeout_ms else None)
    transport = TBufferedTransportFactory().get_transport(PipeClientTransport(sock))
    protocol = TBinaryProtocolFactory().get_protocol(transport)
    transport.open()
    return TClient(ExtensionManager, protocol)


def make_extension_server(socket_path: str, handler: Any) -> Any:
    """Serve the ``Extension`` service on ``socket_path``.

    The returned object has a blocking ``serve()`` method and a ``close()`` that
    is advisory - see ``OsqueryExtension.stop``.
    """
    if is_windows():
        from thriftpy2.protocol import TBinaryProtocolFactory
        from thriftpy2.server import TThreadedServer
        from thriftpy2.thrift import TProcessor
        from thriftpy2.transport import TBufferedTransportFactory

        from .winpipe import WinPipeServerSocket

        pipe = WinPipeServerSocket(socket_path)
        server = TThreadedServer(
            TProcessor(Extension, handler),
            pipe,
            iprot_factory=TBinaryProtocolFactory(),
            itrans_factory=TBufferedTransportFactory(),
        )
        return _PipeExtensionServer(server, pipe)

    # thriftpy2 refuses to bind if the path exists; stale sockets are common
    # after a hard kill, so clear it first.
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    return make_server(Extension, handler, unix_socket=socket_path)


class _PipeExtensionServer:
    """`TThreadedServer` plus the pipe socket it listens on.

    `TThreadedServer.close()` only sets a flag; the serve loop stays parked in
    `ConnectNamedPipe` until a client connects. Closing the pipe socket is what
    actually unblocks it, so `close()` has to do both - otherwise every shutdown
    costs a full thread-join timeout.
    """

    def __init__(self, server: Any, pipe: Any) -> None:
        self._server = server
        self._pipe = pipe

    def serve(self) -> None:
        self._server.serve()

    def close(self) -> None:
        try:
            self._server.close()
        finally:
            self._pipe.close()


def close_extension_socket(socket_path: str) -> None:
    """Remove the socket path, if this platform has one.

    Named pipes disappear with their last handle; there is nothing to unlink.
    """
    if is_windows():
        return
    if os.path.exists(socket_path):
        try:
            os.unlink(socket_path)
        except OSError:
            pass


def poke_extension_socket(socket_path: str) -> None:
    """Connect once and disconnect, to unblock an ``accept()`` in the serve loop.

    ``TThreadedServer.close()`` only sets a flag; the serve loop is parked in
    ``accept()`` and will not notice until something connects.
    """
    if is_windows():
        from .winpipe import poke_pipe

        try:
            poke_pipe(socket_path)
        except OSError:
            pass
        return

    import socket as _socket

    try:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            sock.connect(socket_path)
    except OSError:
        pass


def rows_to_dicts(response: ExtensionResponse) -> List[Dict[str, str]]:
    """Normalise an ``ExtensionResponse`` into a list of dicts."""
    return [dict(row) for row in response.response]


__all__ = [
    "osquery_thrift",
    "ExtensionStatus",
    "ExtensionResponse",
    "InternalExtensionInfo",
    "EXT_SUCCESS",
    "EXT_FAILED",
    "EXT_FATAL",
    "MIN_SDK_VERSION",
    "EXTENSION_NAME",
    "close_extension_socket",
    "default_manager_socket",
    "extension_socket_path",
    "is_windows",
    "make_manager_client",
    "make_extension_server",
    "poke_extension_socket",
    "rows_to_dicts",
    "Optional",
]
