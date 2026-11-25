"""Phase 2c-2 ingest + admin-write integration tests (live Postgres via ASGI).

Covers:
- hashlist create + streaming import (counts recomputed), FJ-007 on import.
- file upload (UUID name, sha256) + the global storage quota → 507, delete
  with FJ-007 scoping.
- api-key create → use the minted key to authenticate → revoke → key rejected.
- create_user with the FJ-005 role-rank ceiling (admin may mint an operator but
  not an admin/superadmin; duplicate username rejected).
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
from flamejob_server.auth import issue_token
from flamejob_server.config import AuthCfg, Config, DatabaseCfg, HashcatCfg
from helpers import MIGRATIONS_DIR, swap_db

pytestmark = pytest.mark.postgres

_SECRET = "phase2c2-secret-0123456789abcdef-0123456789"
A = uuid.UUID("cdcdcdcd-0000-0000-0000-000000000001")  # operator A
B = uuid.UUID("cdcdcdcd-0000-0000-0000-000000000002")  # operator B
ADM = uuid.UUID("cdcdcdcd-0000-0000-0000-000000000003")  # admin (ManageUsers)
SUP = uuid.UUID("cdcdcdcd-0000-0000-0000-000000000004")  # superadmin (cross-tenant)


async def _seed(conn: asyncpg.Connection) -> None:
    await conn.execute(
        "INSERT INTO users (id, username, source) VALUES "
        "($1,'a','local'), ($2,'b','local'), ($3,'adm','local'), ($4,'sup','local')",
        A, B, ADM, SUP,
    )
    await conn.execute(
        "INSERT INTO user_roles (user_id, role) VALUES "
        "($1,'operator'), ($2,'operator'), ($3,'admin'), ($4,'superadmin')",
        A, B, ADM, SUP,
    )


@pytest.fixture
async def ctx(
    tmp_path_factory: pytest.TempPathFactory,
) -> AsyncIterator[tuple[AsyncClient, Config]]:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")
    testdb = f"flamejob_ia_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()
    test_dsn = swap_db(dsn, testdb)
    pool = await asyncpg.create_pool(dsn=test_dsn)
    assert pool is not None
    await apply(pool, MIGRATIONS_DIR)
    async with pool.acquire() as conn:
        await _seed(conn)
    data_dir = tmp_path_factory.mktemp("filestore")
    # A small global quota so one test file is fine and an oversized one trips 507.
    cfg = Config(
        database=DatabaseCfg(dsn=test_dsn),
        auth=AuthCfg(jwt_secret=_SECRET),
        hashcat=HashcatCfg(data_dir=str(data_dir), files_quota_bytes=1024),
    )
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


# ---- hashlists ----

async def test_hashlist_create_and_stream_import(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    hdr = _auth(cfg, A, [Role.OPERATOR])
    r = await c.post("/hashlists", json={"name": "hl", "hash_type": 1000}, headers=hdr)
    assert r.status_code == 201, r.text
    hid = r.json()["id"]

    # Blank lines and whitespace are skipped; the trailing line has no newline.
    body = "aaaa\nbbbb\n\n  cccc  \ndddd"
    r = await c.post(f"/hashlists/{hid}/hashes", content=body, headers=hdr)
    assert r.status_code == 200, r.text
    assert r.json()["total"] == 4


async def test_import_fj007_scoped_to_owner(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    r = await c.post(
        "/hashlists", json={"name": "hl", "hash_type": 1000}, headers=_auth(cfg, A, [Role.OPERATOR])
    )
    hid = r.json()["id"]
    # Operator B does not own the hashlist → 403.
    rb = await c.post(
        f"/hashlists/{hid}/hashes", content="x\n", headers=_auth(cfg, B, [Role.OPERATOR])
    )
    assert rb.status_code == 403
    # Superadmin (ManageScheduling) imports cross-tenant → 200.
    rs = await c.post(
        f"/hashlists/{hid}/hashes", content="x\ny\n", headers=_auth(cfg, SUP, [Role.SUPERADMIN])
    )
    assert rs.status_code == 200
    assert rs.json()["total"] == 2


async def test_import_missing_hashlist_404(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    r = await c.post(
        f"/hashlists/{uuid.uuid4()}/hashes", content="x\n", headers=_auth(cfg, A, [Role.OPERATOR])
    )
    assert r.status_code == 404


# ---- files ----

async def test_file_upload_and_quota_507(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    hdr = _auth(cfg, A, [Role.OPERATOR])
    payload = b"hello wordlist\n"
    r = await c.post("/files", files={"file": ("rockyou.txt", payload)}, data={"kind": "wordlist"})
    # (no auth) → 401
    assert r.status_code == 401

    r = await c.post(
        "/files", files={"file": ("rockyou.txt", payload)}, data={"kind": "wordlist"}, headers=hdr
    )
    assert r.status_code == 201, r.text
    j = r.json()
    assert j["kind"] == "wordlist"
    assert j["size_bytes"] == len(payload)
    assert j["sha256"] == hashlib.sha256(payload).hexdigest()
    # Stored under a server-generated UUID name, never the client filename.
    probe = await asyncpg.connect(dsn=cfg.database.dsn)
    try:
        path = await probe.fetchval("SELECT path FROM files WHERE id = $1", uuid.UUID(j["id"]))
    finally:
        await probe.close()
    assert path.endswith(j["id"])
    assert "rockyou" not in path

    # Second file pushes the corpus past the 1 KiB quota → 507.
    big = b"z" * 2048
    r = await c.post("/files", files={"file": ("big.txt", big)}, headers=hdr)
    assert r.status_code == 507, r.text


async def test_file_delete_fj007(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    up = await c.post(
        "/files", files={"file": ("w.txt", b"abc\n")}, headers=_auth(cfg, A, [Role.OPERATOR])
    )
    fid = up.json()["id"]
    # Operator B is not the uploader → 403.
    rb = await c.delete(f"/files/{fid}", headers=_auth(cfg, B, [Role.OPERATOR]))
    assert rb.status_code == 403
    # Owner deletes → 204.
    ra = await c.delete(f"/files/{fid}", headers=_auth(cfg, A, [Role.OPERATOR]))
    assert ra.status_code == 204
    # Gone → 404.
    r404 = await c.delete(f"/files/{fid}", headers=_auth(cfg, A, [Role.OPERATOR]))
    assert r404.status_code == 404


# ---- api keys ----

async def test_api_key_create_use_revoke(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    hdr = _auth(cfg, A, [Role.OPERATOR])
    r = await c.post("/auth/api-keys", json={"name": "ci"}, headers=hdr)
    assert r.status_code == 201, r.text
    created = r.json()
    secret = created["key"]
    assert secret.startswith("fj_")
    assert created["prefix"] == secret[:10]

    # The minted key authenticates a request.
    key_hdr = {"Authorization": f"Bearer {secret}"}
    me = await c.get("/auth/me", headers=key_hdr)
    assert me.status_code == 200
    assert me.json()["id"] == str(A)

    # Revoke, then the key is rejected.
    rev = await c.delete(f"/auth/api-keys/{created['id']}", headers=hdr)
    assert rev.status_code == 204
    me2 = await c.get("/auth/me", headers=key_hdr)
    assert me2.status_code == 401
    # Double revoke → 404.
    rev2 = await c.delete(f"/auth/api-keys/{created['id']}", headers=hdr)
    assert rev2.status_code == 404


async def test_api_key_blank_name_400(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    r = await c.post("/auth/api-keys", json={"name": "   "}, headers=_auth(cfg, A, [Role.OPERATOR]))
    assert r.status_code == 400


# ---- admin / FJ-005 ----

async def test_create_user_fj005_ceiling(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    adm = _auth(cfg, ADM, [Role.ADMIN])
    # Admin may mint an operator (below admin rank).
    r = await c.post(
        "/admin/users",
        json={"username": "newop", "password": "pw-123456", "roles": ["operator"]},
        headers=adm,
    )
    assert r.status_code == 201, r.text

    # Admin may NOT mint an admin (same rank) or a superadmin (above).
    r = await c.post(
        "/admin/users",
        json={"username": "newadm", "password": "pw-123456", "roles": ["admin"]},
        headers=adm,
    )
    assert r.status_code == 403
    r = await c.post(
        "/admin/users",
        json={"username": "newsup", "password": "pw-123456", "roles": ["superadmin"]},
        headers=adm,
    )
    assert r.status_code == 403

    # Superadmin may mint an admin.
    r = await c.post(
        "/admin/users",
        json={"username": "newadm2", "password": "pw-123456", "roles": ["admin"]},
        headers=_auth(cfg, SUP, [Role.SUPERADMIN]),
    )
    assert r.status_code == 201, r.text


async def test_create_user_duplicate_username_400(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    adm = _auth(cfg, ADM, [Role.ADMIN])
    body = {"username": "dup", "password": "pw-123456", "roles": ["operator"]}
    r1 = await c.post("/admin/users", json=body, headers=adm)
    assert r1.status_code == 201
    r2 = await c.post("/admin/users", json=body, headers=adm)
    assert r2.status_code == 400


async def test_create_user_requires_manage_users(ctx: tuple[AsyncClient, Config]) -> None:
    c, cfg = ctx
    # An operator lacks ManageUsers → 403.
    r = await c.post(
        "/admin/users",
        json={"username": "x", "password": "pw-123456", "roles": ["viewer"]},
        headers=_auth(cfg, A, [Role.OPERATOR]),
    )
    assert r.status_code == 403
