"""Phase 2a end-to-end: enroll → WS connect → telemetry → cracked.

Drives the real app via Starlette's TestClient (HTTP + WebSocket) against a live
Postgres, with a mock agent that enrolls with a generated CSR, connects, and
streams a metrics frame and a cracked result. Skipped unless FLAMEJOB_TEST_DSN.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid

import asyncpg
import pytest
from fastapi.testclient import TestClient

from flamejob_api.agent import AgentMetric, Cracked, CrackedItem, Hello, Metrics, Ready
from flamejob_server.app import create_app
from flamejob_server.config import AuthCfg, Config, DatabaseCfg, HashcatCfg
from flamejob_server.crypto import Cipher
from helpers import MIGRATIONS_DIR, swap_db
from mock_agent import gen_csr

pytestmark = pytest.mark.postgres

_SECRET = "phase2a-secret-0123456789abcdef"
OWNER = uuid.UUID("dddddddd-0000-0000-0000-000000000001")
HL = uuid.UUID("dddddddd-0000-0000-0000-000000000002")
JOB = uuid.UUID("dddddddd-0000-0000-0000-000000000003")
TASK = uuid.UUID("dddddddd-0000-0000-0000-000000000004")
CLAIM = "claimtoken-abcdefghijklmnopqrstuvwx012345"


async def _setup_db(dsn: str, testdb: str) -> None:
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'CREATE DATABASE "{testdb}"')
    await admin.close()
    pool = await asyncpg.create_pool(dsn=swap_db(dsn, testdb))
    assert pool is not None
    from flamejob_db import apply

    await apply(pool, MIGRATIONS_DIR)
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO users (id, username, source) VALUES ($1, 'o', 'local')", OWNER
        )
        await conn.execute(
            "INSERT INTO hashlists (id, name, hash_type, total, cracked) "
            "VALUES ($1,'hl',1000,1,0)",
            HL,
        )
        await conn.execute(
            "INSERT INTO hashes (hashlist_id, hash, salt, plain) "
            "VALUES ($1, 'deadbeef', NULL, NULL)",
            HL,
        )
        await conn.execute(
            "INSERT INTO jobs "
            "(id, name, owner_user_id, hashlist_id, attack_mode, config, priority, state) "
            "VALUES ($1,'j',$2,$3,0,'{}'::jsonb,100,'running')",
            JOB, OWNER, HL,
        )
        await conn.execute(
            "INSERT INTO tasks (id, job_id, keyspace_offset, keyspace_len, state) "
            "VALUES ($1,$2,0,100,'running')",
            TASK, JOB,
        )
        await conn.execute("INSERT INTO agent_claims (token, name) VALUES ($1, 'gpu-x')", CLAIM)
    await pool.close()


async def _drop_db(dsn: str, testdb: str) -> None:
    admin = await asyncpg.connect(dsn=swap_db(dsn, "postgres"))
    await admin.execute(f'DROP DATABASE IF EXISTS "{testdb}"')
    await admin.close()


async def _assert_writes(dsn: str) -> None:
    key = hashlib.sha256(_SECRET.encode()).digest()
    cipher = Cipher(key)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        conn = await asyncpg.connect(dsn=dsn)
        try:
            dev = await conn.fetchrow(
                "SELECT hashrate FROM current_devices WHERE name = 'gpu-x/gpu0'"
            )
            plain = await conn.fetchval(
                "SELECT plain FROM hashes WHERE hashlist_id = $1 AND hash = 'deadbeef'", HL
            )
        finally:
            await conn.close()
        if dev is not None and dev["hashrate"] == 999 and plain is not None:
            assert cipher.decrypt(bytes(plain)) == b"pw"
            return
        await asyncio.sleep(0.2)
    raise AssertionError("telemetry/cracked writes did not land within the deadline")


def test_enroll_connect_telemetry_cracked() -> None:
    dsn = os.environ.get("FLAMEJOB_TEST_DSN")
    if not dsn:
        pytest.skip("FLAMEJOB_TEST_DSN not set")
    import tempfile

    testdb = f"flamejob_ws_{uuid.uuid4().hex[:12]}"
    test_dsn = swap_db(dsn, testdb)
    asyncio.run(_setup_db(dsn, testdb))
    try:
        with tempfile.TemporaryDirectory() as data_dir:
            cfg = Config(
                database=DatabaseCfg(dsn=test_dsn),
                auth=AuthCfg(jwt_secret=_SECRET),
                hashcat=HashcatCfg(data_dir=data_dir),
            )
            app = create_app(cfg)
            with TestClient(app) as client:
                _key, csr_pem = gen_csr("gpu-x")
                r = client.post(
                    "/agent/enroll",
                    json={"claim_token": CLAIM, "name": "gpu-x", "csr_pem": csr_pem},
                )
                assert r.status_code == 200, r.text
                cert_pem = r.json()["cert_pem"]

                # A second enroll with the now-used claim must fail.
                r2 = client.post(
                    "/agent/enroll",
                    json={"claim_token": CLAIM, "name": "gpu-x", "csr_pem": csr_pem},
                )
                assert r2.status_code == 401

                with client.websocket_connect("/agent/stream") as ws:
                    hello = Hello(name="gpu-x", cert_pem=cert_pem, os="linux")
                    ws.send_text(hello.model_dump_json())
                    welcome = json.loads(ws.receive_text())
                    assert welcome["type"] == "welcome"
                    ws.send_text(Ready(slots=1).model_dump_json())
                    ws.send_text(
                        Metrics(
                            samples=[
                                AgentMetric(
                                    name="gpu0", kind="gpu", temp=60, util=90, mem_used=1,
                                    mem_total=2, pstate="P0", power_w=100, fan=40,
                                    clock_mhz=1500, mem_clock_mhz=8000, hashrate=999,
                                )
                            ]
                        ).model_dump_json()
                    )
                    ws.send_text(
                        Cracked(
                            task_id=TASK, items=[CrackedItem(hash="deadbeef", plain="pw")]
                        ).model_dump_json()
                    )
                    # Poll while the connection is open so the server loop keeps
                    # draining frames (and its pool stays alive) as it writes.
                    asyncio.run(_assert_writes(test_dsn))

            # A bad fingerprint is rejected.
            app2 = create_app(cfg)
            with TestClient(app2) as client2, client2.websocket_connect("/agent/stream") as ws2:
                # A self-made cert PEM that was never enrolled → reject frame.
                ws2.send_text(
                    Hello(name="x", cert_pem=_unenrolled_cert_pem(), os="").model_dump_json()
                )
                msg = json.loads(ws2.receive_text())
                assert msg["type"] == "rejected"
    finally:
        asyncio.run(_drop_db(dsn, testdb))


def _unenrolled_cert_pem() -> str:
    """A syntactically valid, self-signed cert whose fingerprint is not enrolled."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ghost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode()
