"""Phase 1 read-surface integration tests against a live Postgres.

Seeds a fresh throwaway database, then drives the FastAPI app through an ASGI
client — exercising the auth dependency (JWT + API-key paths), capability gates,
and the jobs/auth read endpoints with their derived fields. Skipped unless
FLAMEJOB_TEST_DSN is set (CI wires a Postgres service).
"""

from __future__ import annotations

import hashlib
import os
import uuid
from collections.abc import AsyncIterator

import asyncpg
import pytest
from httpx import ASGITransport, AsyncClient

from flamejob_core import Role
from flamejob_db import apply
from flamejob_server.app import create_app
from flamejob_server.auth import api_key_hash, issue_token
from flamejob_server.config import AuthCfg, Config, DatabaseCfg, SchedulerCfg
from flamejob_server.crypto import Cipher
from helpers import MIGRATIONS_DIR as _MIGRATIONS
from helpers import swap_db as _swap_db

pytestmark = pytest.mark.postgres

_SECRET = "phase1-test-secret-0123456789abcdef"
_API_KEY = "fj_" + "ab" * 20  # fj_ + 40 hex chars

OWNER = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001")
NOROLE = uuid.UUID("aaaaaaaa-0000-0000-0000-000000000002")
HL = uuid.UUID("bbbbbbbb-0000-0000-0000-000000000001")
JOB = uuid.UUID("cccccccc-0000-0000-0000-000000000001")


async def _seed(conn: asyncpg.Connection) -> None:
    await conn.execute(
        "INSERT INTO users (id, username, source) VALUES "
        "($1, 'op.user', 'local'), ($2, 'norole.user', 'local')",
        OWNER,
        NOROLE,
    )
    await conn.execute("INSERT INTO user_roles (user_id, role) VALUES ($1, 'operator')", OWNER)
    await conn.execute(
        "INSERT INTO api_keys (user_id, name, prefix, key_hash) VALUES ($1, 'ci', $2, $3)",
        OWNER,
        _API_KEY[:10],
        api_key_hash(_API_KEY),
    )
    await conn.execute(
        "INSERT INTO hashlists (id, name, hash_type, total, cracked) "
        "VALUES ($1, 'hl', 1000, 10, 3)",
        HL,
    )
    await conn.execute(
        "INSERT INTO jobs "
        "(id, name, owner_user_id, hashlist_id, attack_mode, config, priority, state) "
        "VALUES ($1, 'job1', $2, $3, 0, '{}'::jsonb, 100, 'running')",
        JOB,
        OWNER,
        HL,
    )
    # One done chunk (len 100) + one running chunk (progress 0.5, len 100, speed 500)
    # => progress = (100 + 0.5*100) / 200 = 0.75 ; speed = 500.
    await conn.execute(
        "INSERT INTO tasks (job_id, keyspace_offset, keyspace_len, state, progress, speed) VALUES "
        "($1, 0, 100, 'done', 1.0, 0), ($1, 100, 100, 'running', 0.5, 500)",
        JOB,
    )
    await conn.execute(
        "INSERT INTO job_history "
        "(id, name, hashlist_id, owner_user_id, attack_mode, state, created_at) "
        "VALUES ($1, 'oldjob', $2, $3, 0, 'completed', now())",
        uuid.uuid4(),
        HL,
        OWNER,
    )
    # Cracked hash: plain is AES-GCM encrypted under SHA-256(jwt_secret) — the
    # dev-derivation key_from_config uses when no key file is set.
    cipher = Cipher(hashlib.sha256(_SECRET.encode()).digest())
    await conn.execute(
        "INSERT INTO hashes (hashlist_id, hash, salt, plain) VALUES "
        "($1, 'deadbeef', 'NaCl', $2), ($1, 'uncracked', NULL, NULL)",
        HL,
        cipher.encrypt(b"s3cr3t-plain"),
    )
    await conn.execute(
        "INSERT INTO files (id, name, kind, path, size_bytes, sha256) "
        "VALUES ($1, 'rockyou.txt', 'wordlist', '/data/files/x', 1234, $2)",
        uuid.uuid4(),
        "a" * 64,
    )
    await conn.execute(
        "INSERT INTO current_devices (name, kind, temp, util, mem_used, mem_total, "
        "pstate, power_w, fan, clock_mhz, mem_clock_mhz, hashrate) "
        "VALUES ('gpu0', 'gpu', 64, 99, 8000, 24000, 'P2', 320, 55, 1800, 9500, 123456)"
    )
    await conn.execute(
        "INSERT INTO metric_samples (name, kind, temp, util, hashrate, ts) VALUES "
        "('gpu0', 'gpu', 60, 90, 120000, now() - interval '1 minute'), "
        "('gpu0', 'gpu', 64, 99, 123456, now())"
    )


@pytest.fixture
async def client() -> AsyncIterator[tuple[AsyncClient, Config]]:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")

    testdb = f"flamejob_api_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=_swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()

    test_dsn = _swap_db(dsn, testdb)
    cfg = Config(
        read_shadow=False,
        database=DatabaseCfg(dsn=test_dsn),
        auth=AuthCfg(jwt_secret=_SECRET),
        scheduler=SchedulerCfg(local_agent_name="test-host"),
    )
    pool = await asyncpg.create_pool(dsn=test_dsn)
    assert pool is not None
    await apply(pool, _MIGRATIONS)
    async with pool.acquire() as conn:
        await _seed(conn)

    app = create_app(cfg)
    app.state.pool = pool
    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            yield c, cfg
    finally:
        await pool.close()
        admin = await asyncpg.connect(dsn=_swap_db(dsn, "postgres"))
        await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
        await admin.close()


def _auth(cfg: Config, roles: list[Role], uid: uuid.UUID = OWNER) -> dict[str, str]:
    token, _ = issue_token(cfg, uid, "op.user", roles)
    return {"Authorization": f"Bearer {token}"}


async def test_healthz(client: tuple[AsyncClient, Config]) -> None:
    c, _ = client
    r = await c.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


async def test_me_jwt_and_apikey(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    r = await c.get("/auth/me", headers=_auth(cfg, [Role.OPERATOR]))
    assert r.status_code == 200
    assert r.json()["username"] == "op.user"
    assert r.json()["roles"] == ["operator"]

    # API-key path: roles are loaded live from the DB (operator).
    r2 = await c.get("/auth/me", headers={"Authorization": f"Bearer {_API_KEY}"})
    assert r2.status_code == 200
    assert str(OWNER) == r2.json()["id"]
    assert r2.json()["roles"] == ["operator"]


async def test_unauthenticated_is_401(client: tuple[AsyncClient, Config]) -> None:
    c, _ = client
    r = await c.get("/auth/me")
    assert r.status_code == 401
    assert r.headers["content-type"].startswith("application/problem+json")


async def test_jobs_requires_view_jobs(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    # No-roles user → 403.
    r = await c.get("/jobs", headers=_auth(cfg, [], uid=NOROLE))
    assert r.status_code == 403


async def test_list_jobs_derived_fields(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    r = await c.get("/jobs", headers=_auth(cfg, [Role.OPERATOR]))
    assert r.status_code == 200
    jobs = r.json()
    assert len(jobs) == 1
    j = jobs[0]
    assert j["id"] == str(JOB)
    assert j["state"] == "running"
    assert j["cracked"] == 3 and j["total"] == 10
    assert abs(j["progress"] - 0.75) < 1e-9
    assert j["speed"] == 500
    assert j["running_agents"] == ["test-host"]  # local-mode fallback


async def test_get_job_and_404(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    r = await c.get(f"/jobs/{JOB}", headers=_auth(cfg, [Role.VIEWER]))
    assert r.status_code == 200
    assert r.json()["name"] == "job1"

    r404 = await c.get(f"/jobs/{uuid.uuid4()}", headers=_auth(cfg, [Role.VIEWER]))
    assert r404.status_code == 404
    assert r404.headers["content-type"].startswith("application/problem+json")


async def test_job_tasks_and_history(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    rt = await c.get(f"/jobs/{JOB}/tasks", headers=_auth(cfg, [Role.OPERATOR]))
    assert rt.status_code == 200
    tasks = rt.json()
    assert len(tasks) == 2
    assert [t["state"] for t in tasks] == ["done", "running"]  # ordered by keyspace_offset

    rh = await c.get("/jobs/history", headers=_auth(cfg, [Role.OPERATOR]))
    assert rh.status_code == 200
    assert any(j["name"] == "oldjob" and j["state"] == "completed" for j in rh.json())


async def test_api_keys_and_capabilities(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    rk = await c.get("/auth/api-keys", headers=_auth(cfg, [Role.OPERATOR]))
    assert rk.status_code == 200
    keys = rk.json()
    assert len(keys) == 1 and keys[0]["prefix"] == _API_KEY[:10]
    assert "key" not in keys[0]  # secret never returned

    rc = await c.get("/auth/capabilities")
    assert rc.status_code == 200
    caps = rc.json()
    assert "manage_directory" in caps["superadmin"]
    assert "submit_jobs" not in caps["admin"]
    assert "view_jobs" in caps["viewer"]


async def test_hashlists_and_cracked_decrypt(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    rh = await c.get("/hashlists", headers=_auth(cfg, [Role.OPERATOR]))
    assert rh.status_code == 200
    assert any(h["id"] == str(HL) and h["total"] == 10 for h in rh.json())

    # ViewPlaintext (operator has it): cracked plain decrypts; the uncracked row is filtered.
    rc = await c.get(f"/hashlists/{HL}/cracked", headers=_auth(cfg, [Role.OPERATOR]))
    assert rc.status_code == 200
    cracked = rc.json()
    assert len(cracked) == 1
    assert cracked[0]["hash"] == "deadbeef"
    assert cracked[0]["salt"] == "NaCl"
    assert cracked[0]["plain"] == "s3cr3t-plain"

    # Viewer lacks ViewPlaintext → 403.
    rv = await c.get(f"/hashlists/{HL}/cracked", headers=_auth(cfg, [Role.VIEWER]))
    assert rv.status_code == 403


async def test_files_and_usage(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    rf = await c.get("/files", headers=_auth(cfg, [Role.OPERATOR]))
    assert rf.status_code == 200
    files = rf.json()
    assert any(f["name"] == "rockyou.txt" and f["kind"] == "wordlist" for f in files)

    ru = await c.get("/files/usage", headers=_auth(cfg, [Role.OPERATOR]))
    assert ru.status_code == 200
    usage = ru.json()
    assert usage["files_bytes"] == 1234
    assert usage["file_count"] == 1
    assert usage["quota_bytes"] == 0  # default unlimited
    assert usage["disk_total_bytes"] >= 0


async def test_devices_and_history(client: tuple[AsyncClient, Config]) -> None:
    c, cfg = client
    rd = await c.get("/devices", headers=_auth(cfg, [Role.VIEWER]))
    assert rd.status_code == 200
    devs = rd.json()
    assert len(devs) == 1
    assert devs[0]["name"] == "gpu0" and devs[0]["temp"] == 64 and devs[0]["hashrate"] == 123456

    rhist = await c.get("/devices/gpu0/history", headers=_auth(cfg, [Role.VIEWER]))
    assert rhist.status_code == 200
    hist = rhist.json()
    assert len(hist) == 2
    # newest first
    assert hist[0]["hashrate"] == 123456


async def test_dashboard_served(client: tuple[AsyncClient, Config]) -> None:
    c, _ = client
    r = await c.get("/")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    body = r.text
    assert '"__FJCFG__"' not in body  # placeholder substituted
    assert '"apiPort"' in body and '"uploadLimit"' in body
