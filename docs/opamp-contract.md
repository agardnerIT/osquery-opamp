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
- **The agent narrows this itself.** Before pushing, it compiles every statement
  in `schedule` and in inline pack `queries` with the `getQueryColumns` RPC and
  refuses the config if one does not compile:

  ```
  FAILED: scheduled query 'battery' does not compile: no such table: batteries
  ```

  So `APPLIED` from *this* agent means "compiled and merged". The check is
  capped at `MAX_QUERIES_VALIDATED` (200) statements per push so a pathological
  config cannot stall heartbeats, degrades to "no opinion" when the daemon cannot
  answer, and can be switched off with `--no-validate-queries`. It rejects only
  what would fail at execution time anyway: it is a compile check, not a schema
  validator, and `{"schedule": []}` is still accepted because osquery accepts it.

## Effective config: what is reported and what is not

No osquery RPC returns the **merged** config, so the agent never claims to
report it. It reports *sources*, which is the honest unit:

| Object key | Content |
| --- | --- |
| `osquery.json` | the last config this agent pushed, byte for byte |
| `osquery.<basename>.json` | other sources the daemon is running, read back from the active config plugin |

`--config_plugin=filesystem` is read back with
`call("config", "filesystem", {"action": "genConfig"})`, so a packaged
`/var/osquery/osquery.conf` appears as `osquery.osquery.conf.json`, including its
`options`, `decorators` and `file_paths`. The read is gated on a plugin allowlist
(`SIDE_EFFECT_FREE_CONFIG_PLUGINS`): calling `genConfig` on `tls` would perform an
HTTP fetch and answer "config unchanged" with no body, so it is never called.
For a TLS- or OpAMP-managed daemon the server already authored the config and
there is nothing to discover.

Reported only when the server advertises `AcceptsEffectiveConfig`, refreshed on
`--state-interval` (default 60s), after every applied config, and on
`ReportFullState`. Note for strict v1 servers: more than one object can appear in
`config_map`; `osquery.json` is always present when the agent has pushed, and is
the object to read if only one is handled.

## The daemon's own state goes out with health

`ComponentHealth.attributes` carries what the daemon is *actually* running, read
on `--state-interval`:

| Attribute | Source |
| --- | --- |
| `osquery.config_plugin` | the daemon's active config plugin |
| `osquery.schedule_query_count` | `osquery_schedule` row count |
| `osquery.pack_count` | `osquery_packs` row count |
| `osquery.schedule` | `name@interval` for each live scheduled query |
| `osquery.schedule_duplicates` | query names present more than once (omitted when empty) |

The schedule listing is the ground truth a server UI should render next to the
config: it comes from the scheduler, so it cannot be stale in the way a cached
config document can, and `osquery_schedule.executions` distinguishes "pushed and
running" from "pushed and failing to run".

## Duplicate query names are reported, not prevented

Config sources are merged additively. A pushed `battery_stats` and a local file's
`battery_stats` produce **two** live schedules under one name, sharing counter and
diff state, and osquery logs nothing about it:

```
before: [{'interval': '30', 'name': 'battery_stats'}]
after : [{'interval': '30', 'name': 'battery_stats'}, {'interval': '5', 'name': 'battery_stats'}]
```

The agent cannot prevent it (the source merge is osquery's), so it detects it and
reports `ComponentHealth.status = config_conflict` with the offending names in
`last_error` and in `osquery.schedule_duplicates`. The pushed config still
applies - refusing it would not remove the local schedule. The fix is
operational: manage the query in one place, usually by running the daemon with
`--config_plugin=opamp` so the agent is the only source.

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
