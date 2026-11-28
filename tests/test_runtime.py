"""Phase 2e-1: scheduler runtime + singular-brain guard (live Postgres).

Asserts the advisory lock makes the scheduler singular: the first supervisor on a
database wins the lock and starts the scheduler; a second on the same database
serves API-only; releasing the first frees the lock; and the config toggle keeps
the scheduler off entirely.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from collections.abc import AsyncIterator

import asyncpg
import pytest

from flamejob_db import apply
from flamejob_server.config import AuthCfg, Config, DatabaseCfg, HashcatCfg, SchedulerCfg
from flamejob_server.crypto import Cipher, key_from_config
from flamejob_server.hub import AgentHub
from flamejob_server.runtime import _LOCK_KEY, SchedulerSupervisor
from helpers import MIGRATIONS_DIR, swap_db

pytestmark = pytest.mark.postgres


def _cfg(dsn: str, data_dir: str, *, enabled: bool = True) -> Config:
    return Config(
        database=DatabaseCfg(dsn=dsn),
        auth=AuthCfg(jwt_secret="phase2e-secret-0123456789abcdef-0123456789"),
        hashcat=HashcatCfg(data_dir=data_dir),
        scheduler=SchedulerCfg(enabled=enabled),
    )


@pytest.fixture
async def db() -> AsyncIterator[tuple[asyncpg.Pool, str]]:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")
    testdb = f"flamejob_rt_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()
    test_dsn = swap_db(dsn, testdb)
    pool = await asyncpg.create_pool(dsn=test_dsn)
    assert pool is not None
    await apply(pool, MIGRATIONS_DIR)
    try:
        yield pool, test_dsn
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
        await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
        await admin.close()


def _sup(cfg: Config) -> SchedulerSupervisor:
    return SchedulerSupervisor(cfg)


async def test_single_brain_wins_lock_and_starts(db: tuple[asyncpg.Pool, str]) -> None:
    pool, dsn = db
    with tempfile.TemporaryDirectory() as data_dir:
        cfg = _cfg(dsn, data_dir)
        sup = _sup(cfg)
        await sup.start(pool, AgentHub(), Cipher(key_from_config(cfg)))
        try:
            assert sup.active is True
            assert sup.scheduler is not None
            # The lock is genuinely held: an independent connection can't take it.
            other = await asyncpg.connect(dsn=dsn)
            try:
                got = await other.fetchval("SELECT pg_try_advisory_lock($1)", _LOCK_KEY)
                assert got is False
            finally:
                await other.close()
        finally:
            await sup.stop()
        assert sup.active is False


async def test_second_supervisor_serves_api_only(db: tuple[asyncpg.Pool, str]) -> None:
    pool, dsn = db
    with tempfile.TemporaryDirectory() as data_dir:
        cfg = _cfg(dsn, data_dir)
        first = _sup(cfg)
        second = _sup(cfg)
        await first.start(pool, AgentHub(), Cipher(key_from_config(cfg)))
        try:
            assert first.active is True
            # Same database → the second brain loses the lock and runs API-only.
            await second.start(pool, AgentHub(), Cipher(key_from_config(cfg)))
            assert second.active is False
            assert second.scheduler is None
        finally:
            await second.stop()
            await first.stop()
        # With the first released, the lock is now free for a new brain.
        third = _sup(cfg)
        await third.start(pool, AgentHub(), Cipher(key_from_config(cfg)))
        try:
            assert third.active is True
        finally:
            await third.stop()


async def test_disabled_toggle_keeps_scheduler_off(db: tuple[asyncpg.Pool, str]) -> None:
    pool, dsn = db
    with tempfile.TemporaryDirectory() as data_dir:
        cfg = _cfg(dsn, data_dir, enabled=False)
        sup = _sup(cfg)
        await sup.start(pool, AgentHub(), Cipher(key_from_config(cfg)))
        try:
            assert sup.active is False
            assert sup.scheduler is None
            # Lock was never taken → freely acquirable.
            other = await asyncpg.connect(dsn=dsn)
            try:
                assert await other.fetchval("SELECT pg_try_advisory_lock($1)", _LOCK_KEY) is True
            finally:
                await other.close()
        finally:
            await sup.stop()
