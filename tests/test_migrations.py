"""Migration-runner tests.

The pure test (no DB) confirms the 12 shipped migrations load in contiguous
ascending order. The ``postgres``-marked test applies them to a live database
and re-runs idempotently; it is skipped unless ``FLAMEJOB_TEST_DSN`` is set
(CI wires this to a Postgres testcontainer).
"""

from __future__ import annotations

import os
import uuid

import asyncpg
import pytest

from flamejob_db import apply, load_migrations
from flamejob_db.pool import create_pool
from helpers import MIGRATIONS_DIR as _MIGRATIONS
from helpers import swap_db as _swap_db


def test_migrations_load_in_order() -> None:
    migs = load_migrations(_MIGRATIONS)
    versions = [m.version for m in migs]
    assert versions == list(range(1, 13))  # 0001..0012, contiguous
    assert migs[0].description == "init"
    assert all(m.checksum for m in migs)


@pytest.mark.postgres
async def test_apply_is_idempotent_and_ledger_aware() -> None:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")

    # Run against a fresh throwaway database so the test is re-runnable and the
    # "fresh apply" assertion holds regardless of prior state.
    testdb = f"flamejob_mig_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=_swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()

    pool = await create_pool(_swap_db(dsn, testdb))
    try:
        first = await apply(pool, _MIGRATIONS)
        assert first == list(range(1, 13))  # fresh DB: all 12 applied in order
        second = await apply(pool, _MIGRATIONS)
        assert second == []  # ledger-aware: nothing re-applied
        async with pool.acquire() as conn:
            n = await conn.fetchval("SELECT count(*) FROM _sqlx_migrations WHERE success")
            assert n == 12
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn=_swap_db(dsn, "postgres"))
        await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
        await admin.close()
