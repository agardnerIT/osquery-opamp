"""Durable agent identity.

The spec wants an ``instance_uid`` that is stable for the lifetime of the
installation, 16 bytes, regenerated on reinstall, and replaceable by the server
via ``AgentIdentification``.

An osquery *extension* cannot use the daemon's RocksDB (that would mean talking
to the database directly), so identity lives in a small file with 0600
permissions. Writes are atomic: a torn write would change the agent's identity on
the next start, which is the one failure mode that breaks server-side inventory.
"""

from __future__ import annotations

import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Optional

log = logging.getLogger(__name__)

UID_LEN = 16


class IdentityError(RuntimeError):
    pass


def default_identity_path() -> Path:
    """Where to keep the instance UID when the caller does not say.

    Deliberately *not* under ``/var/osquery``: that directory belongs to the
    daemon's package and mixing our state into it invites permission surprises
    and package-upgrade conflicts.
    """
    env = os.environ.get("OSQUERY_OPAMP_IDENTITY")
    if env:
        return Path(env)
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "osquery-opamp" / "instance_uid"


class IdentityStore:
    """Loads, creates and replaces the 16-byte agent instance UID."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path is not None else default_identity_path()

    def load_or_create(self) -> bytes:
        existing = self._read()
        if existing is not None:
            return existing
        uid = uuid.uuid4().bytes
        self.write(uid)
        log.info("generated new instance_uid %s at %s", uid.hex(), self.path)
        return uid

    def write(self, uid: bytes) -> None:
        if len(uid) != UID_LEN:
            raise IdentityError(f"instance_uid must be {UID_LEN} bytes, got {len(uid)}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Atomic replace: a partial write must never become the stored identity.
        fd, tmp_name = tempfile.mkstemp(dir=str(self.path.parent), prefix=".instance_uid.")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(uid.hex().encode("ascii"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
        except BaseException:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def _read(self) -> Optional[bytes]:
        if not self.path.exists():
            return None
        try:
            raw = self.path.read_text(encoding="ascii").strip()
        except OSError as exc:
            log.warning("could not read %s: %s", self.path, exc)
            return None
        try:
            uid = bytes.fromhex(raw)
        except ValueError:
            log.warning("%s does not contain a hex instance_uid; regenerating", self.path)
            return None
        if len(uid) != UID_LEN:
            log.warning("%s has a %d-byte instance_uid; regenerating", self.path, len(uid))
            return None
        return uid


__all__ = ["IdentityStore", "IdentityError", "default_identity_path", "UID_LEN"]
