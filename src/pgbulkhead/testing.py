"""Test helpers for a server built on :class:`~pgbulkhead.SecuredDatabase`."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager

from .admission import WorkspaceLimiter
from .database import SecuredDatabase

__all__ = ["use_limiter"]


@contextmanager
def use_limiter(
    db: SecuredDatabase, limiter: WorkspaceLimiter
) -> Generator[WorkspaceLimiter, None, None]:
    """Run ``db``'s sessions under ``limiter`` (a small cap, a short wait) for the block."""
    previous = db._limiter
    db._limiter = limiter
    try:
        yield limiter
    finally:
        db._limiter = previous
