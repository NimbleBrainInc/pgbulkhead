# pgbulkhead

Tenant isolation for multi-tenant MCP servers on Postgres. One database, many tenants and
workspaces: Postgres enforces the walls, and no agent can talk its way through them.

- **Identity no prompt can steer.** Tenant and workspace come only from a verified context
  (a token your server checked, or headers a gateway set), never from tool arguments. Row-level
  security does the filtering, so a query that forgets its `WHERE tenant_id = ...` still sees
  only its own tenant.
- **Fair sharing under agent fan-out.** Calls are admitted per workspace before they take a
  connection, so one agent loop firing fifty calls queues behind its own workspace's slots
  instead of taking the pool from everyone else.
- **Cancel-safe sessions.** Host timeouts and dropped clients cancel calls mid-transaction. Each
  session rolls back and returns its connection under a shield, so cancellations don't leak
  connections.
- **Errors an agent can act on.** An overloaded call is refused before it runs anything, with a
  message that says so, so the agent knows a retry is safe.

It is for Python MCP servers (FastMCP or any other, on async SQLAlchemy) that serve more than
one customer from one Postgres database. It needs nothing else.

**What it is not.** Not a Postgres extension: it renders ordinary row-level security policies
and sets ordinary settings. Not an ORM: you write your queries with SQLAlchemy as usual. Not for
Django or sync SQLAlchemy. Not for a database per tenant. Not proof against arbitrary SQL run as
your app role; see [the threat model](#threat-model).

```sh
pip install pgbulkhead        # or: uv add pgbulkhead
```

Python 3.12+, SQLAlchemy 2 (asyncio), any async Postgres driver (tested with asyncpg), Postgres
14+.

## How it works

You describe your walls once, as a `TenancyModel`. A migration renders its policies onto each
table. Every request opens a session with its verified context bound, and Postgres filters every
row it reads or writes.

```python
from pgbulkhead import TenancyModel, policy_statements

# tenant_id is the hard wall; workspace_id is a soft wall inside it.
MODEL = TenancyModel(namespace="notes")

# In an alembic migration, after creating the table:
for statement in policy_statements(MODEL, "note"):
    op.execute(statement)
```

That table now admits a row only when its `tenant_id` matches the session's tenant. Reads span
the workspaces the session may read; writes go to its active workspace only. A session that
bound nothing sees no rows and can write none.

At request time, build the context from what you verified and open a session:

```python
from pgbulkhead import SecuredDatabase, SecurityContext, context_from_claims

db = SecuredDatabase(model=MODEL, url_env="NOTES_DATABASE_URL", prefix="NOTES")
db.check()  # at startup: settings validated, so a bad value fails the deploy, not a call

@mcp.tool()
async def list_notes() -> list[dict]:
    ctx = context_from_claims(verified_claims())  # from your auth layer, never from arguments
    async with db.session(ctx) as conn:
        rows = await conn.execute(select(note))    # only this tenant's readable workspaces
        return [dict(r._mapping) for r in rows]
```

`db.session` admits the call against its workspace's concurrency limit, checks out a connection,
binds the context inside a transaction, and commits or rolls back on the way out.

## Threat model

**The guarantee.** Isolation holds against query bugs and against identity taken from untrusted
input. It does not hold against arbitrary SQL execution in the app role.

What that means in practice:

- **Query bugs.** A missing `WHERE`, a wrong join, an unscoped `UPDATE`: Postgres applies the
  policy to every statement, so the mistake returns or touches only rows the session's context
  allows.
- **Identity from untrusted input.** The context is built from a verified source, so text an
  agent writes (tool arguments, a request body, anything a prompt can steer) cannot choose the
  tenant. Never build a `SecurityContext` from tool arguments: the model writes them, and anyone
  who can put text in front of the model can steer what it writes.
- **Arbitrary SQL in the app role: not covered.** The context lives in Postgres settings the
  session sets with `set_config`. The app role can set any of them, `<namespace>.tenant_id`
  included, so SQL that runs as the app role without going through your code (SQL injection, or
  a tool that executes model-written SQL) can move its own session to another tenant.
  `tests/test_isolation.py::test_arbitrary_sql_in_the_app_role_is_outside_the_guarantee`
  demonstrates it. If you run model-written SQL, run it as a separate role with no access to
  these tables, or give each tenant its own role or database.

What the guarantee rests on, all of which is yours to provision:

1. **The app role is not a superuser and not `BYPASSRLS`.** Either one silently voids every
   policy. Create it with `NOSUPERUSER NOBYPASSRLS`.
2. **The app role does not own the tables**, or the policies are `FORCE`d. The rendered DDL
   forces them, so the owner is bound too, but keep migrations and serving on separate roles
   anyway.
3. **Every table holding tenant data has the policy.** Row-level security is per table and does
   not follow foreign keys, so a child table carries the tenant (and workspace) columns and its
   own policy. A table without one is unprotected.
4. **The context comes from a verified source.** Everything above is moot if the tenant is read
   from a tool argument.

Settings are bound with `set_config(name, value, true)` inside a transaction, as bound
parameters, so they end with the transaction and a pooled connection never carries one request's
tenant into the next.

## Policy shapes

**Per-command** (the default: a tenant column and a workspace column). Four policies, one per
command, because a single `FOR ALL` policy cannot keep a read grant from deleting: Postgres
never applies `WITH CHECK` to `DELETE`, and `USING` picks the rows an `UPDATE` or `DELETE` may
touch. Split, the read predicate governs `SELECT` only, and every write is bound to the active
workspace both on the row it selects and on the row it writes.

**Single-key** (`workspace_column=None`). One policy scoping reads and writes on the tenant
alone. Use it for a tenant-wide fact (an opt-out list, an audit log) that every workspace of the
tenant shares, or for a service whose only wall is one key:

```python
LEDGER = TenancyModel(workspace_column=None, namespace="notes")
ORGS = TenancyModel(tenant_column="org_id", workspace_column=None, namespace="notes")
```

**Mixing shapes fails closed.** Each policy reads only its own settings, and an unset setting
reads as NULL, so a session bound for one model matches no row of a table under another. Getting
it wrong returns nothing, never the wrong rows.

Re-rendering is idempotent: the DDL drops its own policy names (and, by default, the other
shape's) before creating them, so a migration can switch a table between shapes.

## Crossing the workspace wall

Some jobs (a reconciler, a nightly sweep) must read every workspace of a tenant. A model can
allow that with a bypass. **It is off unless you set one, and no bypass crosses the tenant
wall.**

| Bypass | How a session takes it | Who can take it |
|---|---|---|
| `GucBypass()` | `system_session(engine, model, tenant_id)` sets `<namespace>.role = 'system'` | anything that can run SQL as the app role, so it has the same exposure as the tenant setting |
| `RoleBypass("reconciler")` | connect as a login role that is a member of `reconciler` | only that role; SQL running as the app role cannot take it |

Prefer `RoleBypass` when the privileged path should be out of the app role's reach. Never grant
the bypass role to the app role.

```python
SWEEP = TenancyModel(namespace="notes", bypass=RoleBypass("notes_reconciler"))
# The job uses its own engine, logging in as a member of notes_reconciler, and binds a tenant:
async with scoped_session(job_engine, SWEEP, SecurityContext("tenant-a", "any")) as conn:
    ...  # every workspace of tenant-a, and nothing of any other tenant
```

## Admission and the pool

A server serving many workspaces from one pool sizes the pool and admits calls per workspace,
so a burst from one workspace waits for its own slots. Settings are read once from
`<PREFIX>_…`:

| Setting | Default | Meaning |
|---|---|---|
| `DB_POOL_SIZE` | 5 | connections the pool keeps open |
| `DB_POOL_MAX_OVERFLOW` | 5 | connections it may open past that under load |
| `DB_POOL_TIMEOUT_SECONDS` | 10 | how long a checkout waits; past it, `PoolExhausted` |
| `WORKSPACE_CONCURRENCY` | 2 | calls one workspace runs at once per process |
| `WORKSPACE_WAIT_SECONDS` | 15 | how long a call over that waits for a slot; past it, `WorkspaceBusy` |

A call holds at most two connections (its session, and one write committed apart from it), so
`2 × WORKSPACE_CONCURRENCY` must stay below `DB_POOL_SIZE + DB_POOL_MAX_OVERFLOW`, or one
workspace could hold every connection. `PoolSettings` refuses settings that break that, so call
`db.check()` at startup and a bad value fails the deploy rather than a user's call. A server
with more traffic passes its own `defaults=PoolSettings(...)`; the environment still overrides
them.

Admit a call's own session only (`db.session`). A second session it opens while holding a slot
(`db.unadmitted_session`) is not admitted, or a workspace whose every slot waits on a second
session would deadlock. To run several sessions in turn under one slot, use
`async with db.admitted(ctx) as slot:` and `slot.session()`.

**Overload errors.** `WorkspaceBusy` and `PoolExhausted` are both `Overloaded`, and the call ran
nothing. Each carries `message` and `next_step` text you can return to the agent as they are;
map them onto your error surface as a rate limit. Replace the text per server:

```python
from pgbulkhead import Overloaded, RefusalText, WorkspaceBusy

db = SecuredDatabase(
    model=MODEL, url_env="NOTES_DATABASE_URL", prefix="NOTES",
    refusals={
        WorkspaceBusy: RefusalText("This notebook has too many requests running.", "Retry in a few seconds."),
        Overloaded: RefusalText("The notes service is busy.", "Retry in a few seconds."),
    },
)
```

## Cancellation

An MCP call runs under a cancel scope, and a cancelled scope raises again at every await inside
it, including the session's own rollback. Unshielded, SQLAlchemy then terminates the connection
instead of returning it, and every cancelled call costs the pool one. Each session here ends its
transaction and returns its connection inside a shielded scope bounded by
`CLEANUP_TIMEOUT_SECONDS` (10s) per step. Past the bound, a rollback is abandoned and the
connection discarded, and a commit raises `TimeoutError`, because its writes may or may not
have landed.

A query interrupted in flight is the one loss left: the driver discards that connection itself,
because its protocol state is unknown. Nothing stays checked out either way.
`tests/test_session_cancel.py` proves both against a real Postgres.

## API

| Name | What it is |
|---|---|
| `TenancyModel` | the walls: tenant column, optional workspace column, settings namespace, bypass |
| `GucBypass`, `RoleBypass` | the two ways to let a session cross the workspace wall |
| `policy_sql`, `policy_statements` | a table's policy DDL, as one string or one statement each |
| `SecurityContext` | one request's verified tenant, workspace, read grants and scopes |
| `context_from_claims`, `ClaimNames` | a context from verified token claims, fail closed |
| `scoped_session` | a transaction with a context bound, refusing an empty identity |
| `system_session` | a transaction through a `GucBypass`, optionally bound to one tenant |
| `transaction`, `bind_context` | the shielded transaction alone, and the binding alone |
| `SecuredDatabase` | one server's model, engine, pool settings and limiter |
| `PoolSettings`, `create_pooled_engine` | pool and admission settings, validated together |
| `WorkspaceLimiter`, `admitted_session` | per-workspace admission, for a server not using `SecuredDatabase` |
| `Overloaded`, `WorkspaceBusy`, `PoolExhausted`, `RefusalText` | refusals, and replacement text |
| `pgbulkhead.testing.use_limiter` | run a database's sessions under a small limiter in tests |

## Development

```sh
docker run -d --rm -p 127.0.0.1:5432:5432 -e POSTGRES_HOST_AUTH_METHOD=trust postgres:16-alpine
make verify     # ruff format check, ruff lint, ty, pytest
```

The database suites need a disposable Postgres with a superuser at `PGBULKHEAD_TEST_URL`
(default `postgresql+asyncpg://postgres@127.0.0.1:5432/postgres`); they create and drop their
own roles and tables. Without one they skip locally and fail under CI.

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE). Security reports: [SECURITY.md](SECURITY.md).
