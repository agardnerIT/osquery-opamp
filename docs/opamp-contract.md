# osquery ↔ OpAMP contract (implementation notes)

What the server sees, and what it must not assume. Verified against osquery
5.24.0 on macOS arm64 with the tests in `tests/`.

## Version drift

`osquery_info` and `osquery_schedule` are read with `select *` and projected to
the columns OpAMP reports, so a daemon that drops or renames a column produces a
missing attribute rather than a failed query. The SDK version reported at
registration is the daemon's real version; when it cannot be read, the minimum
the daemon accepts is reported and `osquery.sdk_version_source` is set to
`unknown`, rather than inventing a plausible number.

## What `APPLIED` actually means

`Config::update()` returns OK when the JSON **parses** and is merged. It does
not validate the contents. Measured behaviour (see
`tests/test_extension.py::test_semantically_broken_config_is_accepted_by_osquery`):

| Config sent | `Config::update()` |
| --- | --- |
| `{"schedule": {"q": {"query": "select * from nope;", "interval": 300}}}` | **OK** |
| `{"schedule": []}` | **OK** |
| `{"packs": "nope"}` | **OK** |
| `{"schedule": {"q": {"query": "...", "interval": "abc"}}}` | **OK** |
| `{"nonsense": {"a": 1}}` | **OK** |
| `{}` | **OK** (clears the source) |
| `{this is not json` | **FAILED**: `Error parsing the config JSON` |

Consequences for the server and its UI:

- `RemoteConfigStatus.APPLIED` means *accepted and merged*. Do not render it as
  "config valid" or "queries working".
- Query-level problems surface later: `osquery_schedule` carries per-query
  performance and failure state, and osquery's status logs carry the errors.
- A future improvement is to validate each scheduled query after applying, via
  the `getQueryColumns` RPC, and report failures as non-identifying attributes or
  as a `ComponentHealth.last_error`. Not implemented yet; it would turn a weak
  `APPLIED` into a useful one.

## Config is per source

`config/update` merges by **source name**. Pushing source `opamp` twice replaces
that source wholesale; it does not merge keys. Other sources (the daemon's own
config plugin output) are untouched, so a pushed config coexists with a
filesystem config.

On a daemon restart the pushed source is gone until the extension re-pushes it.
There is a window at boot where the daemon runs on its own config only.

## Pull mode requires `--extensions_require`

`--config_plugin=opamp` is not a drop-in replacement for `--config_plugin=tls`.
osquery resolves the active config plugin during `Initializer::init()`, *before*
`Config::load()`, and the plugin has to exist in the registry at that moment.
An extension can only register once the daemon's manager socket exists, so the
daemon has to wait for it:

```bash
osqueryd --config_plugin=opamp --extensions_require=opamp --extensions_timeout=30
```

Measured on 5.24.0 without `--extensions_require`:

```
E shutdown.cpp:80] Cannot activate opamp config plugin: Unknown registry plugin: opamp
```

followed by `requestShutdown`. osqueryd exits during startup - it does not run
with an empty config, and `--config_refresh` defaults to 0, so there is no
retry. Treat the two flags as a unit.

Once registered in time, the daemon calls `genConfig` once (no `source` key in
the request; the extension answers from `--source`, default `opamp`) and caches
the result. `--pull-wait` bounds how long that call may block waiting for the
first OpAMP config. Returning `EXT_FAILED` there is honest but not fatal: the
first `config/update` push repairs the daemon without a restart.

## Identity

The transport differs by platform - a Unix domain socket on POSIX, a named pipe
(`\\.\pipe\osquery.em.<uuid>`) on Windows - but the routing is identical:
`getExtensionSocket()` is string concatenation on both, so the extension and the
daemon agree on the path without any Windows-specific logic beyond the socket
type itself.

The daemon does not authenticate the extension beyond the socket's filesystem
permissions, and the extension is registered under a name that must be unique per
daemon (a duplicate name is rejected: `Duplicate extension registered`). A
restarted extension that the daemon still believes is alive will hit this, so the
extension should deregister on clean shutdown (it does) and treat the duplicate
error as "retry after the daemon drops the stale route".
