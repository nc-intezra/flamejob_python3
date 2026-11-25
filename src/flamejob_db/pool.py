"""asyncpg connection pool. Port of ``flamejob-db`` (the sqlx ``PgPool``)."""

from __future__ import annotations

import asyncpg


async def create_pool(dsn: str, max_connections: int = 10) -> asyncpg.Pool:
    """Open an asyncpg pool.

    ``dsn`` is the same ``postgres://...`` string the Rust server uses
    (``[database].dsn``); asyncpg accepts the ``postgres://`` scheme directly.
    """
    return await asyncpg.create_pool(dsn=dsn, min_size=1, max_size=max_connections)
