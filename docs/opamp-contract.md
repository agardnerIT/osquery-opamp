# osquery ↔ OpAMP contract (implementation notes)

What the server sees, and what it must not assume. Verified against osquery
5.24.0 on macOS arm64 with the tests in `tests/`.

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

## Identity

The daemon does not authenticate the extension beyond the socket's filesystem
permissions, and the extension is registered under a name that must be unique per
daemon (a duplicate name is rejected: `Duplicate extension registered`). A
restarted extension that the daemon still believes is alive will hit this, so the
extension should deregister on clean shutdown (it does) and treat the duplicate
error as "retry after the daemon drops the stale route".
