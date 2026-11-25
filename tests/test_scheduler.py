"""Phase 2b-2 scheduler integration: a queued job runs to completion.

Drives the Scheduler against a live Postgres with an in-process fake agent wired
through the hub (the WebSocket transport is covered by the Phase-2a test). The
fake agent answers the keyspace probe and completes each dispatched chunk, so
the job is chunked, filled across slots, and finalized.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
import uuid

import asyncpg
import pytest

from flamejob_api.agent import Assign, Cancel, ComputeKeyspace
from flamejob_core import TaskState
from flamejob_core.runner import StatusUpdate
from flamejob_db import apply
from flamejob_server.config import Config, DatabaseCfg, HashcatCfg, SchedulerCfg
from flamejob_server.crypto import Cipher, key_from_config
from flamejob_server.hub import AgentHub
from flamejob_server.scheduler import Scheduler
from helpers import MIGRATIONS_DIR, swap_db

pytestmark = pytest.mark.postgres

OWNER = uuid.UUID("eeeeeeee-0000-0000-0000-000000000001")
HL = uuid.UUID("eeeeeeee-0000-0000-0000-000000000002")
JOB = uuid.UUID("eeeeeeee-0000-0000-0000-000000000003")


async def _fake_agent(
    hub: AgentHub, queue: asyncio.Queue, keyspace: int, stop: asyncio.Event
) -> None:
    """Answer keyspace probes and complete each assigned chunk."""
    while not stop.is_set():
        try:
            msg = await asyncio.wait_for(queue.get(), timeout=0.1)
        except asyncio.TimeoutError:
            continue
        if isinstance(msg, ComputeKeyspace):
            await hub.fulfill_keyspace(msg.req_id, keyspace)
        elif isinstance(msg, Assign):
            tid = msg.task.task_id
            sink = await hub.sink_for(tid)
            if sink is not None:
                await sink.put(
                    StatusUpdate(
                        task_id=tid, progress=0.5, speed=100, recovered=0,
                        eta=None, state=TaskState.RUNNING,
                    )
                )
                await sink.put(
                    StatusUpdate(
                        task_id=tid, progress=1.0, speed=0, recovered=0,
                        eta=None, state=TaskState.DONE,
                    )
                )
            await hub.finish_task(tid)
        elif isinstance(msg, Cancel):
            pass


async def test_queued_job_runs_to_completion() -> None:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")
    testdb = f"flamejob_sched_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()
    pool = await asyncpg.create_pool(dsn=swap_db(dsn, testdb))
    assert pool is not None
    stop = asyncio.Event()
    agent_task: asyncio.Task[None] | None = None
    try:
        await apply(pool, MIGRATIONS_DIR)
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO users (id, username, source) VALUES ($1,'o','local')", OWNER
            )
            await conn.execute(
                "INSERT INTO hashlists (id, name, hash_type, total, cracked) "
                "VALUES ($1,'hl',1000,2,0)",
                HL,
            )
            await conn.execute(
                "INSERT INTO hashes (hashlist_id, hash, salt, plain) "
                "VALUES ($1,'h1',NULL,NULL),($1,'h2',NULL,NULL)",
                HL,
            )
            await conn.execute(
                "INSERT INTO jobs "
                "(id, name, owner_user_id, hashlist_id, attack_mode, config, priority, state) "
                "VALUES ($1,'j',$2,$3,3,'{\"mask\":\"?d?d\"}'::jsonb,100,'queued')",
                JOB, OWNER, HL,
            )

        with tempfile.TemporaryDirectory() as data_dir:
            cfg = Config(
                database=DatabaseCfg(dsn=swap_db(dsn, testdb)),
                hashcat=HashcatCfg(data_dir=data_dir),
                # chunk_size 40 over a 100 keyspace → 3 chunks, exercising fill_fleet.
                scheduler=SchedulerCfg(chunk_size=40, max_chunks=500, runner="remote"),
            )
            hub = AgentHub()
            agent_id = uuid.uuid4()
            agent_q: asyncio.Queue = asyncio.Queue()
            await hub.register(agent_id, "gpu-x", agent_q)
            await hub.set_ready(agent_id, 2)  # 2 slots
            sched = Scheduler(pool, cfg, hub, Cipher(key_from_config(cfg)))

            agent_task = asyncio.create_task(_fake_agent(hub, agent_q, 100, stop))

            state = "queued"
            for _ in range(60):
                await sched.tick()
                async with pool.acquire() as conn:
                    state = await conn.fetchval("SELECT state::text FROM jobs WHERE id = $1", JOB)
                if state in ("completed", "exhausted", "error", "cancelled"):
                    break
                await asyncio.sleep(0.05)

            assert state == "exhausted", f"job ended {state}"
            async with pool.acquire() as conn:
                n_tasks = await conn.fetchval("SELECT count(*) FROM tasks WHERE job_id = $1", JOB)
                n_done = await conn.fetchval(
                    "SELECT count(*) FROM tasks WHERE job_id = $1 AND state = 'done'", JOB
                )
            assert n_tasks == 3  # plan_chunks(100, 40, 500) → 3 chunks
            assert n_done == 3
    finally:
        stop.set()
        if agent_task is not None:
            await agent_task
        await pool.close()
        admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
        await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
        await admin.close()
