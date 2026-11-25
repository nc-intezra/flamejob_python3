"""Phase 2c-1 job-write integration tests (live Postgres via ASGI).

Covers create_job (eligibility + FJ-004 rejection + 429 backpressure) and the
FJ-007 ownership scoping on state changes (operator tenant isolation).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient

from flamejob_core import Role
from flamejob_db import apply
from flamejob_server.app import create_app
from flamejob_server.auth import issue_token
from flamejob_server.config import AuthCfg, Config, DatabaseCfg
from helpers import MIGRATIONS_DIR, swap_db

pytestmark = pytest.mark.postgres

_SECRET = "phase2c-secret-0123456789abcdef-0123456789"
A = uuid.UUID("abababab-0000-0000-0000-000000000001")  # operator A
B = uuid.UUID("abababab-0000-0000-0000-000000000002")  # operator B
SUP = uuid.UUID("abababab-0000-0000-0000-000000000003")  # superadmin
DIR = uuid.UUID("abababab-0000-0000-0000-000000000004")  # directory operator (quota'd)
HL = uuid.UUID("abababab-0000-0000-0000-00000000000a")
POOL = uuid.UUID("abababab-0000-0000-0000-0000000000b0")


async def _seed(conn: asyncpg.Connection) -> None:
    await conn.execute(
        "INSERT INTO users (id, username, source, external_sid) VALUES "
        "($1,'a','local',NULL), ($2,'b','local',NULL), ($3,'sup','local',NULL), "
        "($4,'dir','directory','S-1-5-21-u')",
        A, B, SUP, DIR,
    )
    await conn.execute(
        "INSERT INTO user_roles (user_id, role) VALUES "
        "($1,'operator'), ($2,'operator'), ($3,'superadmin'), ($4,'operator')",
        A, B, SUP, DIR,
    )
    await conn.execute(
        "INSERT INTO hashlists (id, name, hash_type, total, cracked) VALUES ($1,'hl',1000,1,0)", HL
    )
    # Directory operator with a granted pool + a submit cap of 1.
    await conn.execute("INSERT INTO agent_pools (id, name) VALUES ($1,'p')", POOL)
    await conn.execute(
        "INSERT INTO user_dir_groups (user_id, group_sid) VALUES ($1,'S-G')", DIR
    )
    await conn.execute(
        "INSERT INTO directory_agent_grants (group_sid, pool_id) VALUES ('S-G',$1)", POOL
    )
    await conn.execute(
        "INSERT INTO group_quota (group_sid, weight, floor_slots, ceil_slots, max_submit_jobs) "
        "VALUES ('S-G',100,0,NULL,1)"
    )


@pytest.fixture
async def ctx() -> AsyncIterator[tuple[AsyncClient, Config]]:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")
    testdb = f"flamejob_jw_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()
    test_dsn = swap_db(dsn, testdb)
    pool = await asyncpg.create_pool(dsn=test_dsn)
    assert pool is not None
    await apply(pool, MIGRATIONS_DIR)
    async with pool.acquire() as conn:
        await _seed(conn)
    cfg = Config(database=DatabaseCfg(dsn=test_dsn), auth=AuthCfg(jwt_secret=_SECRET))
    app = create_app(cfg)
    app.state.pool = pool
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
            yield c, cfg
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
        await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
        await admin.close()


def _auth(cfg: Config, uid: uuid.UUID, roles: list[Role]) -> dict[str, str]:
    token, _ = issue_token(cfg, uid, "u", roles)
    return {"Authorization": f"Bearer {token}"}


def _job_body() -> dict:
    return {"name": "j", "hashlist_id": str(HL), "attack_mode": 3, "config": {"mask": "?d?d"}}


async def test_create_job_ok(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    r = await c.post("/jobs", json=_job_body(), headers=_auth(cfg, A, [Role.OPERATOR]))
    assert r.status_code == 201, r.text
    assert r.json()["state"] == "queued"


async def test_create_job_rejects_bad_extra_args(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    body = _job_body()
    body["config"]["extra_args"] = ["--outfile=/etc/cron.d/x"]
    r = await c.post("/jobs", json=body, headers=_auth(cfg, A, [Role.OPERATOR]))
    assert r.status_code == 400


async def test_submit_backpressure_429(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    hdr = _auth(cfg, DIR, [Role.OPERATOR])
    r1 = await c.post("/jobs", json=_job_body(), headers=hdr)
    assert r1.status_code == 201
    r2 = await c.post("/jobs", json=_job_body(), headers=hdr)
    assert r2.status_code == 429


async def test_fj007_only_owner_or_privileged_mutates(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    r = await c.post("/jobs", json=_job_body(), headers=_auth(cfg, A, [Role.OPERATOR]))
    job_id = r.json()["id"]

    # Operator B (different user, has SubmitJobs) cannot cancel A's job.
    rb = await c.post(f"/jobs/{job_id}/cancel", headers=_auth(cfg, B, [Role.OPERATOR]))
    assert rb.status_code == 403

    # The owner can.
    ra = await c.post(f"/jobs/{job_id}/cancel", headers=_auth(cfg, A, [Role.OPERATOR]))
    assert ra.status_code == 202

    # A superadmin (ManageScheduling) acts cross-tenant.
    r2 = await c.post("/jobs", json=_job_body(), headers=_auth(cfg, A, [Role.OPERATOR]))
    jid2 = r2.json()["id"]
    rs = await c.post(f"/jobs/{jid2}/cancel", headers=_auth(cfg, SUP, [Role.SUPERADMIN]))
    assert rs.status_code == 202


async def test_cancel_missing_job_404(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    r = await c.post(f"/jobs/{uuid.uuid4()}/cancel", headers=_auth(cfg, A, [Role.OPERATOR]))
    assert r.status_code == 404
