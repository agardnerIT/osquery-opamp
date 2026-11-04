"""The last config the daemon accepted, kept somewhere it survives a restart.

Why this file exists
--------------------

Until now the extension held the applied config in RAM (``ExtensionService``)
and pushed a merged *config source* (``config/update``). Two consequences, both
of which look like a server bug from the outside:

* ``osqueryd`` restart -> the in-memory source is gone, the daemon re-reads
  ``--config_path``, and the fleet silently reverts to whatever was in that file
  - possibly years old - while the OpAMP server still shows ``APPLIED``;
* extension restart -> ``genConfig`` (``--config_plugin=opamp``) has nothing to
  answer with, so the daemon boots with no config at all.

osquery has a native answer to the first half: ``--config_enable_backup`` makes
``Config::update()`` copy every source into the daemon's own database and restore
them when the first config refresh of a process *fails*
(``Config::restoreConfigBackup``, ``osquery/config/config.cpp``). That is the
right backstop, but it is a fallback for a broken boot, not a policy: with the
``filesystem`` plugin the first refresh succeeds, so the backup is never read.
And the extension cannot write to that database - it would have to speak
RocksDB - which is why identity already lives in a file (see
:mod:`osquery_opamp.opamp.identity`).

So the agent persists the one thing only it knows: the body the daemon accepted,
plus the OpAMP ``config_hash`` it was acknowledged under. On the next boot
``genConfig`` serves that body immediately, before the OpAMP server is even
contacted, and the first status report re-states ``APPLIED`` with the same hash -
so the server neither re-delivers the config nor counts it as unconfirmed.

Three rules this module enforces:

1. **A cache read never raises.** A corrupt, truncated, future-versioned or
   unreadable file is ``None`` with a log line: the server will re-deliver, which
   is the correct recovery, and a daemon boot must not fail over an optimisation.
2. **A cache write never raises.** Durability is best effort; an applied config
   is not rolled back because a disk was full or a directory was read-only.
3. **A write is atomic and private.** Temp file in the same directory, ``fsync``,
   ``0600``, then ``os.replace``. A torn file would be read on the next boot as
   "no cache" at best; at worst it would serve the daemon half a config.

The body is stored as **text**, byte for byte, never re-serialised: osquery
hashes the source content it parses, and the whole point of the cache is that the
next boot serves the bytes the previous one accepted.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

log = logging.getLogger(__name__)

#: Envelope version. Bumped when the on-disk shape changes; an entry written by a
#: newer agent is ignored rather than guessed at.
SCHEMA_VERSION = 1

#: Refuse to persist anything larger than this. osquery caps a config document at
#: 4 MiB (``kMaxConfigSize``); the extra headroom is for JSON escaping, and the
#: real point is that a runaway body must not fill a state directory.
MAX_BODY_BYTES = 8 * 1024 * 1024

DEFAULT_CONTENT_TYPE = "application/json"

_HEX = frozenset("0123456789abcdef")


def default_config_path() -> Path:
    """Where to keep the cache when the caller does not say.

    Beside the identity file, for the same reason it is not under
    ``/var/osquery``: that directory belongs to the daemon's package, and mixing
    our state into it invites permission surprises and upgrade conflicts.
    """
    env = os.environ.get("OSQUERY_OPAMP_CONFIG_CACHE")
    if env:
        return Path(env)
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "osquery-opamp" / "config.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_hash(value: str) -> bool:
    """True for our hex digest form (any length, lowercase, even length)."""
    return bool(value) and len(value) % 2 == 0 and set(value.lower()) <= _HEX


@dataclass(frozen=True)
class CachedConfig:
    """One applied config, as the daemon accepted it.

    ``config_hash`` is the **server's** value, echoed back verbatim (the spec
    treats it as opaque), stored as hex because that is what the rest of this
    codebase compares and reports. Empty means "we never heard a hash", which is
    different from "unknown": an empty hash is not reported to the server, so the
    cache still serves the daemon at boot while the agent stays quiet about
    having applied it.
    """

    source: str
    body: str
    content_type: str = DEFAULT_CONTENT_TYPE
    config_hash: str = ""
    applied_at: str = ""
    agent_version: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": SCHEMA_VERSION,
            "source": self.source,
            "content_type": self.content_type,
            "config_hash": self.config_hash,
            "body": self.body,
            "applied_at": self.applied_at or _now(),
            "agent_version": self.agent_version,
        }

    @classmethod
    def from_dict(cls, raw: Any) -> Optional["CachedConfig"]:
        """Parse and validate an on-disk entry. ``None`` means "ignore this file"."""
        if not isinstance(raw, Mapping):
            log.warning("config cache is not a JSON object; ignoring it")
            return None
        version = raw.get("version")
        if version != SCHEMA_VERSION:
            log.warning(
                "config cache has version %r, this agent writes %s; ignoring it "
                "(the server will re-deliver)",
                version,
                SCHEMA_VERSION,
            )
            return None

        body = raw.get("body")
        if not isinstance(body, str) or not body.strip():
            log.warning("config cache has no body; ignoring it")
            return None
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            log.warning("config cache body is larger than %d bytes; ignoring it", MAX_BODY_BYTES)
            return None
        # osquery rejects a non-object root (``Config::validateConfig``), so a body
        # that does not parse as a JSON object is not something the daemon ever
        # accepted - it is a damaged file, not a config.
        try:
            parsed = json.loads(body)
        except ValueError as exc:
            log.warning("config cache body is not valid JSON (%s); ignoring it", exc)
            return None
        if not isinstance(parsed, dict):
            log.warning("config cache body is not a JSON object; ignoring it")
            return None

        source = raw.get("source")
        content_type = raw.get("content_type") or DEFAULT_CONTENT_TYPE
        config_hash = str(raw.get("config_hash") or "")
        if config_hash and not _is_hash(config_hash):
            log.warning("config cache holds a malformed config_hash; serving the body without it")
            config_hash = ""

        return cls(
            source=source if isinstance(source, str) and source else "opamp",
            body=body,
            content_type=str(content_type),
            config_hash=config_hash,
            applied_at=str(raw.get("applied_at") or ""),
            agent_version=str(raw.get("agent_version") or ""),
        )


class ConfigCache:
    """Load and store the last applied config. Never raises, on either path.

    ``path=None`` disables the cache entirely (``--config-cache ''``), which is
    the right choice for an ephemeral host: better to admit there is no durable
    state than to write one into a directory that is wiped on reboot.
    """

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = Path(path) if path is not None else None

    @property
    def enabled(self) -> bool:
        return self.path is not None

    def load(self) -> Optional[CachedConfig]:
        """The cached entry, or ``None`` if absent, unreadable or unusable."""
        if self.path is None:
            return None
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None
        except OSError as exc:
            log.warning("could not read the config cache at %s: %s", self.path, exc)
            return None
        try:
            data = json.loads(raw)
        except ValueError as exc:
            log.warning(
                "config cache at %s is not valid JSON (%s); ignoring it "
                "(the OpAMP server will re-deliver the config)",
                self.path,
                exc,
            )
            return None
        return CachedConfig.from_dict(data)

    def save(self, entry: CachedConfig) -> bool:
        """Write ``entry`` atomically. Returns False (with a log) on any failure."""
        if self.path is None:
            return False
        body_bytes = len(entry.body.encode("utf-8"))
        if body_bytes > MAX_BODY_BYTES:
            log.warning(
                "refusing to cache a %d-byte config; it exceeds the %d-byte limit",
                body_bytes,
                MAX_BODY_BYTES,
            )
            return False
        try:
            payload = json.dumps(entry.to_dict(), ensure_ascii=False) + "\n"
        except (TypeError, ValueError) as exc:  # pragma: no cover - dataclass of str
            log.warning("could not encode the config cache: %s", exc)
            return False
        if len(payload.encode("utf-8")) > MAX_BODY_BYTES + 4096:
            log.warning(
                "refusing to cache a %d-byte config; it exceeds the %d-byte limit",
                len(payload),
                MAX_BODY_BYTES,
            )
            return False

        tmp_name = ""
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            # Same directory as the target: os.replace is only atomic within one
            # filesystem. 0600 because the body is fleet configuration and can
            # hold credentials (the daemon's own config file is often 0640 root).
            fd, tmp_name = tempfile.mkstemp(
                dir=str(self.path.parent), prefix=".config.", suffix=".tmp"
            )
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
            return True
        except OSError as exc:
            log.warning("could not write the config cache at %s: %s", self.path, exc)
            return False
        finally:
            if tmp_name:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
                except OSError as exc:  # pragma: no cover - cleanup is best effort
                    log.debug("could not remove the cache temp file %s: %s", tmp_name, exc)

    def clear(self) -> None:
        """Forget the cached config. Best effort, for tests and hard resets."""
        if self.path is None:
            return
        try:
            self.path.unlink()
        except FileNotFoundError:
            return
        except OSError as exc:
            log.debug("could not remove the config cache at %s: %s", self.path, exc)


__all__ = [
    "CachedConfig",
    "ConfigCache",
    "DEFAULT_CONTENT_TYPE",
    "MAX_BODY_BYTES",
    "SCHEMA_VERSION",
    "default_config_path",
]
