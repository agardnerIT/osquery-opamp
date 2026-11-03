"""Typed access to osquery's extension Thrift API.

osquery extensions talk to the daemon over a Unix domain socket using the
service definitions in ``vendor/osquery.thrift``. The daemon exposes
``ExtensionManager`` (which extends ``Extension``) at ``--extensions_socket``,
and *pings each registered extension* at ``<extensions_socket>.<uuid>``, so an
extension must also serve the ``Extension`` service on that path or it will be
deregistered after two failed pings.

The IDL is vendored rather than referenced from an osquery checkout so this
package has no build-time dependency on the osquery source tree.
"""

from __future__ import annotations

import os
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

ExtensionStatus = osquery_thrift.ExtensionStatus
ExtensionResponse = osquery_thrift.ExtensionResponse
InternalExtensionInfo = osquery_thrift.InternalExtensionInfo

#: ExtensionCode values, mirroring the IDL enum.
EXT_SUCCESS = 0
EXT_FAILED = 1
EXT_FATAL = 2


def default_manager_socket() -> str:
    """The daemon's extension socket path, matching osquery's own default.

    ``OSQUERY_SOCKET`` is ``/var/osquery/`` on macOS and ``/var/osquery/`` or
    ``/run/osquery/`` on Linux depending on the package; callers should pass
    ``--extensions_socket`` explicitly in almost every case.
    """
    env = os.environ.get("OSQUERY_EXTENSIONS_SOCKET")
    if env:
        return env
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
    return make_client(
        osquery_thrift.ExtensionManager, unix_socket=manager_socket, timeout=timeout_ms
    )


def make_extension_server(socket_path: str, handler: Any) -> Any:
    """Serve the ``Extension`` service on ``socket_path``.

    The returned object has a blocking ``serve()`` method.
    """
    # thriftpy2 refuses to bind if the path exists; stale sockets are common
    # after a hard kill, so clear it first.
    if os.path.exists(socket_path):
        os.unlink(socket_path)
    return make_server(osquery_thrift.Extension, handler, unix_socket=socket_path)


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
    "default_manager_socket",
    "extension_socket_path",
    "make_manager_client",
    "make_extension_server",
    "rows_to_dicts",
    "Optional",
]
