# Security policy

## Reporting a vulnerability

Report it privately through GitHub: **Security → Report a vulnerability** on this repository.
Please do not open a public issue for it. We aim to acknowledge a report within three business
days and to agree a disclosure date with you once we understand the issue.

## Supported versions

The latest minor release gets security fixes. Before 1.0, that is the only supported line.

## What counts

pgbulkhead's guarantee is that **isolation holds against query bugs and against identity taken
from untrusted input**. A way to read or write another tenant's rows, or another workspace's
rows without a grant, through code that uses the library as documented, is a vulnerability.
So is a rendered policy that admits more than its documentation says, a session whose binding
outlives its transaction, or a bypass that crosses the tenant wall.

Out of scope, because the guarantee does not claim them (the README's threat model explains
each):

- SQL that runs as the app role outside your code (SQL injection, model-written SQL). The app
  role can set any context setting, including the tenant.
- An app role that is a superuser or has `BYPASSRLS`, a table without a policy, or a context
  built from tool arguments or a request body.
- Taking a `GucBypass` through SQL in the app role. That is its documented cost; `RoleBypass`
  exists for when it is too much.
