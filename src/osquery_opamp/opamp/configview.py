"""Turning config sources into ``AgentConfigMap`` object names.

OpAMP identifies a config document by its key in ``AgentConfigMap``. osquery
identifies a config *source* by the name its config plugin gave it, which for
the ``filesystem`` plugin is the file path (``/var/osquery/osquery.conf``, plus
any ``/var/osquery/osquery.conf.d/*.conf``).

The two vocabularies have to be bridged somewhere, so this module does it in one
place and with one rule:

* the source the agent itself pushes keeps the canonical ``osquery.json`` key,
  which is what a v1 server already understands;
* every other source becomes ``osquery.<basename>.json``, e.g.
  ``osquery.osquery.conf.json``, with anything that is not
  ``[A-Za-z0-9._-]`` replaced and duplicates disambiguated by a counter.

Basenames rather than full paths on purpose: the key ends up in a UI, and
``osquery./private/var/osquery/osquery.conf.json`` is noise. Collisions are
possible in principle (``osquery.conf.d`` files with the same name in two
directories) and are handled explicitly rather than silently, because two
documents under one key would be a data loss bug.
"""

from __future__ import annotations

import re
from typing import Dict, Mapping

from .constants import CONFIG_OBJECT_NAME

#: The canonical key for the config the agent pushes, kept from the v1 contract.
PRIMARY_OBJECT_NAME = CONFIG_OBJECT_NAME

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")

#: Both separators, on every platform: a config source arrives from the daemon,
#: and a POSIX host can still be asked to name a Windows path (or vice versa).
_SEPARATORS = re.compile(r"[\\/]+")


def config_object_name(source: str) -> str:
    """Map one config source name (usually a path) to an object key."""
    parts = _SEPARATORS.split(source.rstrip("/\\"))
    base = parts[-1] if parts else source
    safe = _UNSAFE.sub("_", base or source).strip("._") or "source"
    if safe.lower().endswith(".json"):
        # config.json -> osquery.config.json, not osquery.config.json.json
        safe = safe[: -len(".json")]
    return f"osquery.{safe}.json"


def source_documents(sources: Mapping[str, str]) -> Dict[str, str]:
    """Map ``{source: body}`` to ``{object key: body}``, disambiguating clashes."""
    documents: Dict[str, str] = {}
    for source in sorted(sources):
        key = config_object_name(source)
        base, suffix = key[: -len(".json")], 2
        while key in documents or key == PRIMARY_OBJECT_NAME:
            key = f"{base}-{suffix}.json"
            suffix += 1
        documents[key] = sources[source]
    return documents


__all__ = ["PRIMARY_OBJECT_NAME", "config_object_name", "source_documents"]
