"""Phase 2d preemption integration (live Postgres).

Two surfaces:
- the HTTP handlers (ASGI): priority override + preempt (cancel / requeue guards /
  requeue+force), authz, and 404/400 paths;
- the scheduler-side handoff: _resume_preempted_jobs splits a paused chunk at its
  offset and flips the job back to running; _requeue_orphaned_running recovers a
  running job whose inputs were lost.
"""

from __future__ import annotations

import os
import tempfile
import uuid
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient

from flamejob_core import Role
from flamejob_db import apply
from flamejob_server.app import create_app
from flamejob_server.auth import issue_token
from flamejob_server.config import AuthCfg, Config, DatabaseCfg, HashcatCfg
from flamejob_server.crypto import Cipher, key_from_config
from flamejob_server.hub import AgentHub
from flamejob_server.scheduler import Scheduler
from helpers import MIGRATIONS_DIR, swap_db

pytestmark = pytest.mark.postgres

OP = uuid.UUID("dadadada-0000-0000-0000-000000000001")  # operator (owner)
SUP = uuid.UUID("dadadada-0000-0000-0000-000000000002")  # superadmin (ManageScheduling)
HL = uuid.UUID("dadadada-0000-0000-0000-00000000000a")


async def _seed(conn: asyncpg.Connection) -> None:
    await conn.execute(
        "INSERT INTO users (id, username, source) VALUES ($1,'op','local'), ($2,'sup','local')",
        OP, SUP,
    )
    await conn.execute(
        "INSERT INTO user_roles (user_id, role) VALUES ($1,'operator'), ($2,'superadmin')",
        OP, SUP,
    )
    await conn.execute(
        "INSERT INTO hashlists (id, name, hash_type, total, cracked) VALUES ($1,'hl',1000,2,0)",
        HL,
    )
    await conn.execute(
        "INSERT INTO hashes (hashlist_id, hash, salt, plain) VALUES ($1,'h1',NULL,NULL)",
        HL,
    )


async def _make_db() -> tuple[asyncpg.Pool, str, str]:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")
    testdb = f"flamejob_pre_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()
    pool = await asyncpg.create_pool(dsn=swap_db(dsn, testdb))
    assert pool is not None
    await apply(pool, MIGRATIONS_DIR)
    async with pool.acquire() as conn:
        await _seed(conn)
    return pool, dsn, testdb


async def _drop_db(pool: asyncpg.Pool, dsn: str, testdb: str) -> None:
    await pool.close()
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
    await admin.close()


def _auth(cfg: Config, uid: uuid.UUID, roles: list[Role]) -> dict[str, str]:
    token, _ = issue_token(cfg, uid, "u", roles)
    return {"Authorization": f"Bearer {token}"}


def _ago(minutes: float) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


async def _insert_running_job(pool: asyncpg.Pool, job_id: uuid.UUID, *, started: datetime) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO jobs (id, name, owner_user_id, hashlist_id, attack_mode, config, "
            "priority, state, started_at) "
            "VALUES ($1,'j',$2,$3,3,'{\"mask\":\"?d?d\"}'::jsonb,100,'running',$4)",
            job_id, OP, HL, started,
        )


@pytest.fixture
async def ctx() -> AsyncIterator[tuple[AsyncClient, Config, asyncpg.Pool]]:
    pool, dsn, testdb = await _make_db()
    with tempfile.TemporaryDirectory() as data_dir:
        cfg = Config(
            database=DatabaseCfg(dsn=swap_db(dsn, testdb)),
            auth=AuthCfg(jwt_secret="phase2d-secret-0123456789abcdef-0123456789"),
            hashcat=HashcatCfg(data_dir=data_dir),
        )
        app = create_app(cfg)
        app.state.pool = pool
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
                yield c, cfg, pool
        finally:
            await _drop_db(pool, dsn, testdb)


# ---- HTTP: priority override ----

async def test_priority_override_requires_manage_scheduling(
    ctx: tuple[AsyncClient, Config, asyncpg.Pool],
) -> None:
    c, cfg, pool = ctx
    job = uuid.uuid4()
    await _insert_running_job(pool, job, started=_ago(5))
    # Operator lacks ManageScheduling → 403.
    r = await c.post(
        f"/jobs/{job}/priority",
        json={"priority_override": 1},
        headers=_auth(cfg, OP, [Role.OPERATOR]),
    )
    assert r.status_code == 403
    # Superadmin → 202, and the override lands.
    r = await c.post(
        f"/jobs/{job}/priority",
        json={"priority_override": 1, "reason": "rush"},
        headers=_auth(cfg, SUP, [Role.SUPERADMIN]),
    )
    assert r.status_code == 202, r.text
    async with pool.acquire() as conn:
        ov = await conn.fetchval("SELECT priority_override FROM jobs WHERE id = $1", job)
    assert ov == 1


async def test_priority_override_missing_job_404(
    ctx: tuple[AsyncClient, Config, asyncpg.Pool],
) -> None:
    c, cfg, _ = ctx
    r = await c.post(
        f"/jobs/{uuid.uuid4()}/priority",
        json={"priority_override": 5},
        headers=_auth(cfg, SUP, [Role.SUPERADMIN]),
    )
    assert r.status_code == 404


# ---- HTTP: preempt ----

async def test_preempt_cancel(ctx: tuple[AsyncClient, Config, asyncpg.Pool]) -> None:
    c, cfg, pool = ctx
    job = uuid.uuid4()
    await _insert_running_job(pool, job, started=_ago(5))
    r = await c.post(
        f"/jobs/{job}/preempt",
        json={"mode": "cancel", "reason": "stop it"},
        headers=_auth(cfg, SUP, [Role.SUPERADMIN]),
    )
    assert r.status_code == 202, r.text
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT state::text AS s, preempt_state FROM jobs WHERE id = $1", job
        )
    assert row["s"] == "cancelled"
    assert row["preempt_state"] == "cancelled"


async def test_preempt_requeue_guarded_then_forced(
    ctx: tuple[AsyncClient, Config, asyncpg.Pool],
) -> None:
    c, cfg, pool = ctx
    job = uuid.uuid4()
    # Just started → the guard rejects a plain requeue.
    await _insert_running_job(pool, job, started=_ago(0))
    r = await c.post(
        f"/jobs/{job}/preempt", json={"mode": "requeue"}, headers=_auth(cfg, SUP, [Role.SUPERADMIN])
    )
    assert r.status_code == 400
    # force bypasses the guard → 202, job paused + flagged for resume.
    r = await c.post(
        f"/jobs/{job}/preempt",
        json={"mode": "requeue", "force": True, "reason": "decree"},
        headers=_auth(cfg, SUP, [Role.SUPERADMIN]),
    )
    assert r.status_code == 202, r.text
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT state::text AS s, preempt_state FROM jobs WHERE id = $1", job
        )
    assert row["s"] == "paused"
    assert row["preempt_state"] == "requeued"


async def test_preempt_non_running_400(ctx: tuple[AsyncClient, Config, asyncpg.Pool]) -> None:
    c, cfg, pool = ctx
    job = uuid.uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO jobs (id, name, owner_user_id, hashlist_id, attack_mode, config, "
            "priority, state) VALUES ($1,'j',$2,$3,3,'{\"mask\":\"?d\"}'::jsonb,100,'queued')",
            job, OP, HL,
        )
    r = await c.post(
        f"/jobs/{job}/preempt", json={"mode": "cancel"}, headers=_auth(cfg, SUP, [Role.SUPERADMIN])
    )
    assert r.status_code == 400


async def test_preempt_bad_mode_400(ctx: tuple[AsyncClient, Config, asyncpg.Pool]) -> None:
    c, cfg, pool = ctx
    job = uuid.uuid4()
    await _insert_running_job(pool, job, started=_ago(5))
    r = await c.post(
        f"/jobs/{job}/preempt", json={"mode": "nope"}, headers=_auth(cfg, SUP, [Role.SUPERADMIN])
    )
    assert r.status_code == 400


# ---- scheduler: keyspace handoff + restart recovery ----

def _sched(pool: asyncpg.Pool, cfg: Config) -> Scheduler:
    return Scheduler(pool, cfg, AgentHub(), Cipher(key_from_config(cfg)))


async def test_resume_preempted_splits_and_runs(
    ctx: tuple[AsyncClient, Config, asyncpg.Pool],
) -> None:
    _c, cfg, pool = ctx
    job = uuid.uuid4()
    t_half = uuid.uuid4()
    t_done = uuid.uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO jobs (id, name, owner_user_id, hashlist_id, attack_mode, config, "
            "priority, state, preempt_state, resume_after) "
            "VALUES ($1,'j',$2,$3,3,'{\"mask\":\"?d?d\"}'::jsonb,100,'paused','requeued',now())",
            job, OP, HL,
        )
        # One half-done chunk (→ split) and one fully consumed (→ done).
        await conn.execute(
            "INSERT INTO tasks (id, job_id, runner_id, keyspace_offset, keyspace_len, state, "
            "progress) VALUES ($1,$2,'local',2000,1000,'paused',0.5)",
            t_half, job,
        )
        await conn.execute(
            "INSERT INTO tasks (id, job_id, runner_id, keyspace_offset, keyspace_len, state, "
            "progress) VALUES ($1,$2,'local',0,100,'paused',1.0)",
            t_done, job,
        )

    await _sched(pool, cfg)._resume_preempted_jobs()

    async with pool.acquire() as conn:
        job_state, preempt_state = await conn.fetchrow(
            "SELECT state::text, preempt_state FROM jobs WHERE id = $1", job
        )
        half = await conn.fetchrow(
            "SELECT state::text AS s, keyspace_offset AS off, keyspace_len AS len, progress "
            "FROM tasks WHERE id = $1",
            t_half,
        )
        done = await conn.fetchval("SELECT state::text FROM tasks WHERE id = $1", t_done)
    assert job_state == "running"
    assert preempt_state is None
    # Half-done chunk resumes from its offset for the remainder, progress reset.
    assert (half["s"], half["off"], half["len"], half["progress"]) == ("pending", 2500, 500, 0.0)
    # Fully consumed chunk is marked done, not re-dispatched.
    assert done == "done"


async def test_requeue_orphaned_running_recovers(
    ctx: tuple[AsyncClient, Config, asyncpg.Pool],
) -> None:
    _c, cfg, pool = ctx
    job = uuid.uuid4()
    await _insert_running_job(pool, job, started=_ago(5))
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO tasks (id, job_id, runner_id, keyspace_offset, keyspace_len, state) "
            "VALUES ($1,$2,'local',0,100,'pending')",
            uuid.uuid4(), job,
        )
    # The scheduler has no in-memory inputs for this job (simulating a restart).
    await _sched(pool, cfg)._requeue_orphaned_running()
    async with pool.acquire() as conn:
        st = await conn.fetchval("SELECT state::text FROM jobs WHERE id = $1", job)
    assert st == "queued"
