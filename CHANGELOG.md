# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Until 1.0, a minor version may change the API.

## [0.1.1] - 2026-11-11

### Fixed

- `AdmittedSlot.session` raises `PoolExhausted` (a safe-retry refusal) again for a checkout
  that times out before any session under the slot has opened, when nothing has run. Once one
  has opened, a later checkout timeout still raises the pool's own `TimeoutError`, because an
  earlier session may have committed. In 0.1.0 every slot checkout timeout raised
  `TimeoutError`, so a request whose first session could not get a connection was reported
  as a failure instead of a refusal it could retry.
- `SecuredDatabase.admitted` applies its `refusals` text to a slot's `PoolExhausted` too.

## [0.1.0] - 2026-11-11

First release.

- `TenancyModel`: a tenant column (the hard wall), an optional workspace column (the soft
  wall), the settings namespace, and an opt-in `GucBypass` or `RoleBypass` across the workspace
  wall only.
- `policy_sql` / `policy_statements`: forced row-level security policies, per command for a
  model with a workspace (reads span the readable set, writes bind the active workspace) and a
  single policy for a single-key model. Idempotent, and names are validated before they reach
  DDL.
- `SecurityContext`, `context_from_claims`: the verified identity, failing closed on a missing
  tenant or workspace.
- `scoped_session`, `system_session`, `transaction`, `bind_context`: transaction-local binding
  with a cancel-safe exit.
- `SecuredDatabase`, `PoolSettings`, `WorkspaceLimiter`: per-workspace admission sized together
  with the pool, with `Overloaded` refusals whose text a server can replace.

[0.1.1]: https://github.com/NimbleBrainInc/pgbulkhead/releases/tag/v0.1.1
[0.1.0]: https://github.com/NimbleBrainInc/pgbulkhead/releases/tag/v0.1.0
