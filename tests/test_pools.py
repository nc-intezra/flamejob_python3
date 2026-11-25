"""Pool eligibility tests — ports of the pools.rs summarize tests + eligibility cases."""

from __future__ import annotations

import os
import uuid

import asyncpg
import pytest

from flamejob_db import apply
from flamejob_server.errors import Forbidden
from flamejob_server.pools import compute_eligibility, summarize_grants
from helpers import MIGRATIONS_DIR, swap_db


def test_summarize_picks_min_group_and_distinct_pools() -> None:
    p1, p2 = uuid.UUID(int=1), uuid.UUID(int=2)
    pairs = [
        ("S-1-5-21-ops", p1),
        ("S-1-5-21-admins", p2),
        ("S-1-5-21-ops", p2),  # duplicate pool via another path
    ]
    owner, pools = summarize_grants(pairs)
    assert owner == "S-1-5-21-admins"  # lexicographically smallest
    assert pools == [p1, p2]  # distinct, first-seen order


def test_summarize_empty() -> None:
    owner, pools = summarize_grants([])
    assert owner is None
    assert pools == []


@pytest.mark.postgres
async def test_compute_eligibility_cases() -> None:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")
    testdb = f"flamejob_pools_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()
    pool = await asyncpg.create_pool(dsn=swap_db(dsn, testdb))
    assert pool is not None
    try:
        await apply(pool, MIGRATIONS_DIR)
        local_id = uuid.uuid4()
        dir_id = uuid.uuid4()
        async with pool.acquire() as conn:
            # No pools yet → unrestricted even for a directory user.
            await conn.execute(
                "INSERT INTO users (id, username, source, external_sid) "
                "VALUES ($1,'loc','local',NULL), ($2,'dir','directory','S-1-5-21-x')",
                local_id,
                dir_id,
            )
            assert await compute_eligibility(conn, dir_id) == (None, [])

            # A pool now exists. Local user stays unrestricted (FJ-011).
            pool_id = await conn.fetchval(
                "INSERT INTO agent_pools (name) VALUES ('p1') RETURNING id"
            )
            assert await compute_eligibility(conn, local_id) == (None, [])

            # Directory user with groups but no grant → Forbidden.
            with pytest.raises(Forbidden):
                await compute_eligibility(conn, dir_id)

            # Grant the user's group a pool → restricted to that pool.
            await conn.execute(
                "INSERT INTO user_dir_groups (user_id, group_sid) VALUES ($1, 'S-1-5-21-g')",
                dir_id,
            )
            await conn.execute(
                "INSERT INTO directory_agent_grants (group_sid, pool_id) VALUES ('S-1-5-21-g', $1)",
                pool_id,
            )
            owner, pools = await compute_eligibility(conn, dir_id)
            assert owner == "S-1-5-21-g"
            assert pools == [pool_id]
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
        await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
        await admin.close()
