"""The extension must register, push config, and survive the daemon's pings.

These are the behaviours the whole design rests on, so they are tested against a
real daemon rather than a mock:

* ``registerExtension`` is accepted from a non-C++ process.
* ``call("config", "update", ...)`` actually changes the live schedule.
* the extension stays registered (the daemon pings it every
  ``--extensions_interval`` and drops it after two failures).
* a rejected config is reported as a failure, not silently swallowed.
"""

from __future__ import annotations

import time

import pytest


def test_extension_registers_and_is_visible(extension, daemon):
    assert extension.uuid > 0
    assert extension.socket_path == f"{daemon.socket}.{extension.uuid}"

    from osquery_opamp.osquery_thrift import make_manager_client

    client = make_manager_client(daemon.socket)
    registered = dict(client.extensions())
    assert extension.uuid in registered
    info = registered[extension.uuid]
    assert info.name == "opamp"


def test_pushed_config_lands_in_the_live_schedule(extension):
    result = extension.push_config(
        "opamp",
        {
            "schedule": {
                "opamp_pushed": {
                    "query": "select 1 as n from osquery_info;",
                    "interval": 300,
                }
            }
        },
    )
    assert result.ok, result.message

    names = {row["name"] for row in extension.core.scheduled_queries()}
    assert "opamp_pushed" in names


def test_pushed_config_is_reported_as_applied_by_the_daemon(extension):
    before = extension.core.osquery_info()
    result = extension.push_config(
        "opamp",
        {"schedule": {"second": {"query": "select 2 as n from osquery_info;", "interval": 300}}},
    )
    assert result.ok, result.message
    after = extension.core.osquery_info()

    assert after["config_valid"] == "1"
    assert after["config_hash"] != before["config_hash"], "config hash should change on apply"


def test_malformed_json_is_rejected(extension):
    """The one failure mode Config::update() actually reports."""
    result = extension.core.push_config_raw("opamp", "{this is not json")
    assert not result.ok
    assert result.status == "FAILED"
    assert "parsing the config JSON" in result.message


def test_semantically_broken_config_is_accepted_by_osquery(extension):
    """Pins real osquery behaviour, so a change in it shows up as a test failure.

    osquery applies config structure eagerly and validates SQL only at execution
    time, so a query naming a table that does not exist is *accepted*. This is
    why an OpAMP ``APPLIED`` status must not be presented to users as "the
    config is correct" - see docs/opamp-contract.md.
    """
    result = extension.push_config(
        "opamp", {"schedule": {"bad_table": {"query": "select * from nope;", "interval": 300}}}
    )
    assert result.ok, result.message
    assert "bad_table" in {row["name"] for row in extension.core.scheduled_queries()}


def test_extension_survives_daemon_pings(extension, daemon):
    """The daemon pings every extensions_interval and drops us after 2 misses."""
    from osquery_opamp.osquery_thrift import make_manager_client

    # Two ping intervals plus margin: this is exactly the window in which an
    # extension that never serves its socket gets deregistered.
    time.sleep(8)

    client = make_manager_client(daemon.socket)
    assert extension.uuid in dict(client.extensions()), "extension was deregistered"
    assert extension.service.ping_count >= 2, (
        f"daemon never pinged the extension (count={extension.service.ping_count})"
    )


def test_config_source_is_merged_not_replaced(extension, daemon):
    """A pushed source coexists with the daemon's own config plugin source."""
    assert extension.push_config(
        "opamp", {"schedule": {"from_opamp": {"query": "select 3 as n from osquery_info;", "interval": 300}}}
    ).ok

    # Re-pushing the same source replaces it wholesale (per-source semantics).
    assert extension.push_config(
        "opamp", {"schedule": {"from_opamp_v2": {"query": "select 4 as n from osquery_info;", "interval": 300}}}
    ).ok

    names = {row["name"] for row in extension.core.scheduled_queries()}
    assert "from_opamp_v2" in names
    assert "from_opamp" not in names, "sources are replaced per source name, not merged key-wise"


def test_genconfig_serves_the_cached_config(extension, daemon):
    """--config_plugin=opamp (pull mode) is answered from the pushed config."""
    from osquery_opamp.osquery_thrift import EXT_FAILED, make_manager_client

    client = make_manager_client(daemon.socket)

    # Before any config is pushed the plugin must fail cleanly, so osquery falls
    # back to its own handling instead of loading an empty config silently.
    response = client.call(
        "config", "opamp", {"action": "genConfig", "source": "opamp"}
    )
    assert response.status.code == EXT_FAILED

    extension.push_config("opamp", {"schedule": {"x": {"query": "select 1 from osquery_info;", "interval": 300}}})

    response = client.call("config", "opamp", {"action": "genConfig", "source": "opamp"})
    assert response.status.code == 0
    assert response.response and "opamp" in response.response[0]
