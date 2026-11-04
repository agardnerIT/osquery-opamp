"""The durable config cache: the file that survives a restart.

These are filesystem tests - no daemon, no sockets, no threads. The cache is the
part that decides whether a ``--config_plugin=opamp`` daemon boots on the fleet's
config or on whatever its own ``--config_path`` last held, so every way it can be
wrong is exercised here: absent, corrupt, future-versioned, too big, truncated by
a crash, and unwritable.
"""

from __future__ import annotations

import json
import os
import stat
import sys

import pytest

from osquery_opamp.configcache import (
    MAX_BODY_BYTES,
    SCHEMA_VERSION,
    CachedConfig,
    ConfigCache,
    default_config_path,
)

BODY = json.dumps(
    {"schedule": {"battery_stats": {"query": "SELECT percent_remaining FROM battery;", "interval": 30}}},
    indent=4,
)
HASH = "22aa53ff9c3b270753bf4cb01d23ccc7593fbf4e8436ccb4a516cbf35742d576"


def entry(**overrides) -> CachedConfig:
    fields = {
        "source": "opamp",
        "body": BODY,
        "content_type": "application/json",
        "config_hash": HASH,
        "applied_at": "2026-11-04T08:03:36+00:00",
        "agent_version": "0.1.0",
    }
    fields.update(overrides)
    return CachedConfig(**fields)


def write_raw(path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) if not isinstance(payload, str) else payload)


# ------------------------------------------------------------------ round trip


def test_round_trip_keeps_the_body_byte_for_byte(tmp_path):
    """A re-serialised body is a different config to osquery's content hash."""
    cache = ConfigCache(tmp_path / "config.json")
    assert cache.save(entry())

    loaded = cache.load()
    assert loaded is not None
    assert loaded.body == BODY, "the cached body must be the exact text the daemon accepted"
    assert loaded.config_hash == HASH
    assert loaded.source == "opamp"
    assert loaded.content_type == "application/json"
    assert loaded.applied_at == "2026-11-04T08:03:36+00:00"


def test_missing_file_is_not_an_error(tmp_path):
    assert ConfigCache(tmp_path / "nothing-here.json").load() is None


def test_disabled_cache_is_inert(tmp_path):
    cache = ConfigCache(None)
    assert cache.enabled is False
    assert cache.load() is None
    assert cache.save(entry()) is False
    assert list(tmp_path.iterdir()) == []


def test_default_path_can_be_overridden_by_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("OSQUERY_OPAMP_CONFIG_CACHE", str(tmp_path / "explicit.json"))
    assert default_config_path() == tmp_path / "explicit.json"


# ------------------------------------------------------------- damaged entries


@pytest.mark.parametrize(
    "payload",
    [
        "{not json at all",
        "[]",
        json.dumps({"version": SCHEMA_VERSION}),
        json.dumps({"version": SCHEMA_VERSION, "body": ""}),
        json.dumps({"version": SCHEMA_VERSION, "body": "{not json"}),
        json.dumps({"version": SCHEMA_VERSION, "body": "[1, 2, 3]"}),
        json.dumps({"version": SCHEMA_VERSION + 1, "body": BODY}),
    ],
    ids=[
        "not-json",
        "not-an-object",
        "no-body",
        "empty-body",
        "body-not-json",
        "body-not-a-config-object",
        "future-version",
    ],
)
def test_a_damaged_entry_is_ignored_not_fatal(tmp_path, payload):
    """The recovery is "let the server re-deliver", never an exception at boot."""
    path = tmp_path / "config.json"
    write_raw(path, payload)
    assert ConfigCache(path).load() is None


def test_a_truncated_file_from_a_crash_is_ignored(tmp_path):
    path = tmp_path / "config.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": SCHEMA_VERSION, "body": BODY})[:40])
    assert ConfigCache(path).load() is None


def test_a_malformed_hash_still_serves_the_body(tmp_path):
    """The body is what the daemon needs; a bad hash only costs a re-delivery."""
    path = tmp_path / "config.json"
    write_raw(
        path,
        {"version": SCHEMA_VERSION, "source": "opamp", "body": BODY, "config_hash": "zzz"},
    )
    loaded = ConfigCache(path).load()
    assert loaded is not None
    assert loaded.body == BODY
    assert loaded.config_hash == ""


def test_a_missing_source_defaults_to_opamp(tmp_path):
    path = tmp_path / "config.json"
    write_raw(path, {"version": SCHEMA_VERSION, "body": BODY})
    assert ConfigCache(path).load().source == "opamp"


# ----------------------------------------------------------------- write safety


def test_write_is_atomic_private_and_leaves_no_temp_files(tmp_path):
    path = tmp_path / "nested" / "config.json"
    assert ConfigCache(path).save(entry())

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"fleet config must not be world readable, got {oct(mode)}"
    assert sorted(p.name for p in path.parent.iterdir()) == ["config.json"]


def test_a_failed_write_is_reported_not_raised(tmp_path):
    """A read-only directory must not take the agent down with it."""
    if os.geteuid() == 0:
        pytest.skip("root ignores directory permissions")
    directory = tmp_path / "ro"
    directory.mkdir()
    os.chmod(directory, 0o500)
    try:
        assert ConfigCache(directory / "config.json").save(entry()) is False
    finally:
        os.chmod(directory, 0o700)


def test_an_oversized_body_is_refused(tmp_path):
    path = tmp_path / "config.json"
    cache = ConfigCache(path)
    assert cache.save(entry(body="{" + " " * (MAX_BODY_BYTES + 1) + "}")) is False
    assert not path.exists()


def test_an_unreadable_file_is_not_fatal(tmp_path):
    if os.geteuid() == 0 or sys.platform == "win32":
        pytest.skip("permissions are not enforced for root on POSIX")
    path = tmp_path / "config.json"
    assert ConfigCache(path).save(entry())
    os.chmod(path, 0o000)
    try:
        assert ConfigCache(path).load() is None
    finally:
        os.chmod(path, 0o600)


def test_clear_removes_the_file_and_is_idempotent(tmp_path):
    path = tmp_path / "config.json"
    cache = ConfigCache(path)
    cache.save(entry())
    cache.clear()
    assert not path.exists()
    cache.clear()
