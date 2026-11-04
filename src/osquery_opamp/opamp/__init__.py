"""OpAMP protocol support for the osquery agent.

Modules are split so each can be tested on its own:

``pb``           vendored v0.20.0 protobuf stubs
``constants``    capability bitmask and names, with a sanity check
``identity``     durable 16-byte instance_uid
``description``  AgentDescription built from osquery_info
``agent``        the state machine (no I/O)
``transport``    WebSocket transport behind a blocking interface
``client``       connect/heartbeat/backoff/reconnect loop
"""

from .agent import OpampAgent
from .client import OpampClient
from .identity import IdentityStore

__all__ = ["OpampAgent", "OpampClient", "IdentityStore"]
