"""Fixtures for the suites that need a real Postgres.

``PGBULKHEAD_TEST_URL`` is an async URL for a superuser on a disposable database; the suites
create roles and tables there. Without one reachable the database tests **skip**, except under
CI, where a skip would report success having run nothing, so they fail instead. The unit suites
ask for no database.
"""

from __future__ import annotations

import os
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
from sqlalchemy import make_url, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pgbulkhead import PoolSettings, create_pooled_engine

URL = os.environ.get(
    "PGBULKHEAD_TEST_URL",
    # 127.0.0.1, not `localhost`: where the resolver prefers ::1, asyncpg can stall its connect
    # timeout before the skip.
    "postgresql+asyncpg://postgres@127.0.0.1:5432/postgres",
)


def url_for(role: str) -> str:
    """The test database's URL, logging in as ``role`` (the test server trusts local logins)."""
    return make_url(URL).set(username=role, password=None).render_as_string(hide_password=False)


async def _reachable(engine: AsyncEngine) -> None:
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except (SQLAlchemyError, OSError):
        await engine.dispose()
        if os.environ.get("CI"):
            pytest.fail(f"no Postgres reachable at {URL!r} (PGBULKHEAD_TEST_URL)")
        pytest.skip(f"no Postgres reachable at {URL!r}; set PGBULKHEAD_TEST_URL")


@pytest_asyncio.fixture
async def admin_engine() -> AsyncIterator[AsyncEngine]:
    """A superuser engine, for setup only: a superuser bypasses row-level security."""
    engine = create_async_engine(URL)
    await _reachable(engine)
    try:
        yield engine
    finally:
        await engine.dispose()


#: The role the pooled fixtures connect as: neither superuser nor BYPASSRLS, as a server's own
#: role must be, since a pooled engine refuses any other (see ``install_role_guard``).
SERVER_ROLE = "pgbulkhead_server"


@pytest_asyncio.fixture
async def pg_url(admin_engine: AsyncEngine) -> str:
    """The test Postgres URL, logging in as :data:`SERVER_ROLE` (skips like ``admin_engine``
    without a database). The role may create tables in ``public``, as the suites need."""
    async with admin_engine.begin() as conn:
        exists = await conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": SERVER_ROLE}
        )
        if exists.scalar() is None:
            await conn.execute(text(f"CREATE ROLE {SERVER_ROLE} LOGIN NOSUPERUSER NOBYPASSRLS"))
        await conn.execute(text(f"GRANT CREATE ON SCHEMA public TO {SERVER_ROLE}"))
    return url_for(SERVER_ROLE)


@pytest_asyncio.fixture
async def pg_engine(pg_url: str) -> AsyncIterator[AsyncEngine]:
    """A one-connection pooled engine, as a server builds it, so a terminated connection shows."""
    engine = create_pooled_engine(
        pg_url, PoolSettings(pool_size=1, max_overflow=2, workspace_concurrency=1)
    )
    try:
        yield engine
    finally:
        await engine.dispose()
