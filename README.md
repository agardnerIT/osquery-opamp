# osquery-opamp

An OpAMP agent for osquery, delivered as an **osquery extension**.

No changes to osquery's core. The extension registers with the daemon over the
documented Thrift API (`osquery/extensions/thrift/osquery.thrift`) and uses
registry calls that already exist:

| OpAMP need | osquery mechanism |
| --- | --- |
| deliver remote config | `call("config", "update", ...)` → `Config::update()` merges a config source |
| report what is actually running | `query("select ... from osquery_info / osquery_schedule")` |
| answer `--config_plugin=opamp` (pull mode) | the `config/opamp` registry item we advertise |

## Status

Working and tested against a real `osqueryd` 5.24.0:

- extension registration, liveness (the daemon pings us and drops us after two
  misses, so the extension serves its own Thrift socket)
- config push into the live schedule, per-source replacement semantics
- config hash / validity read-back, scheduled-query read-back
- pull mode (`genConfig` served from the last pushed config)

Not yet implemented: the OpAMP protocol side (WebSocket transport, agent
description, status reporting, commands). That is the next milestone; see
`../osquery/opamp-plans/`.

## Requirements

- osqueryd (tested with 5.24.0; the macOS `.pkg` only symlinks `osqueryi` and
  `osqueryctl` into `/usr/local/bin`, so point `OSQUERYD` at the bundle path)
- Python 3.10+ with `thriftpy2`, `protobuf>=7.34.1,<8`, `websocket-client`

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[test]'
.venv/bin/python -m pytest tests/ -q          # boots real osqueryd instances
```

Tests run the daemon unprivileged with `--ephemeral --disable_database` and
temporary paths, so they need no root and leave no state behind. Set
`OSQUERYD=/path/to/osqueryd` to override the binary.

## Layout

```
src/osquery_opamp/osquery_thrift.py   vendored IDL loader, socket paths, client/server factories
src/osquery_opamp/core.py             typed wrapper over the daemon's registry calls
src/osquery_opamp/extension.py        registration, liveness, Thrift Extension service
vendor/osquery.thrift                 copied from osquery (Apache-2.0)
vendor/opamp.proto, proto/*_pb2.py    OpAMP v0.20.0 definitions
tests/                                real-daemon integration tests
```

## Behaviour worth knowing

`Config::update()` only rejects **unparseable JSON** (and the size limit).
Verified against 5.24.0: `{"schedule": []}`, unknown top-level keys, and
scheduled queries naming tables that do not exist all return OK. osquery applies
config structure eagerly and validates SQL at execution time.

So an OpAMP `APPLIED` status means "accepted and merged", **not** "the queries
work". Per-query failures show up in `osquery_schedule` and the status logs. See
`docs/opamp-contract.md`.
