"""Agent-facing endpoints. Port of the agent.rs WS handler + enrollment.

- ``POST /agent/enroll`` — consume a claim token, sign the CSR, store the
  fingerprint (the claim token is the credential; no bearer auth).
- ``POST /admin/agent-claims`` — mint a one-time enrollment token (ManageAgents).
- ``WS /agent/stream`` — first frame ``Hello`` is authenticated by cert
  fingerprint; then telemetry/results/keyspace frames are dispatched to the hub.
"""

from __future__ import annotations

import asyncio
import secrets
import string
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
from pydantic import TypeAdapter, ValidationError

from flamejob_api.agent import (
    AgentClaim,
    AgentClaimCreate,
    AgentError,
    AgentMsg,
    Cracked,
    EnrollRequest,
    EnrollResponse,
    Hello,
    Keyspace,
    Metrics,
    Progress,
    Ready,
    Rejected,
    ServerMsg,
    TaskDone,
    Welcome,
)
from flamejob_api.schemas import DeviceView
from flamejob_core import Capability, TaskState
from flamejob_core.runner import StatusUpdate

from . import ingest, telemetry
from .auth import AuthUser
from .config import Config
from .crypto import Cipher
from .deps import get_config, get_pool, require
from .errors import Unauthorized
from .hub import AgentHub
from .pki import Pki, fingerprint_of_pem

router = APIRouter(tags=["agents"])

_AGENT_MSG: TypeAdapter[AgentMsg] = TypeAdapter(AgentMsg)
_ALPHANUM = string.ascii_letters + string.digits
_manage_agents = require(Capability.MANAGE_AGENTS)


def _parse_task_state(s: str) -> TaskState:
    # Matches agent.rs parse_task_state: unknown → Running (not Pending).
    try:
        return TaskState(s)
    except ValueError:
        return TaskState.RUNNING


# ---- enrollment (HTTP) ----


@router.post("/agent/enroll")
async def enroll(
    req: EnrollRequest,
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> EnrollResponse:
    async with pool.acquire() as conn:
        claim = await conn.fetchrow(
            "SELECT name FROM agent_claims WHERE token = $1 AND used_at IS NULL", req.claim_token
        )
        if claim is None:
            raise Unauthorized("invalid or used claim token")
        pki: Pki = Pki.load_or_create(cfg.hashcat.data_dir)
        try:
            cert_pem, fingerprint = pki.sign_csr(req.csr_pem)
        except ValueError as exc:
            raise Unauthorized(f"csr: {exc}") from exc
        agent_id = await conn.fetchval(
            "INSERT INTO agents (name, fingerprint, status) "
            "VALUES ($1, $2, 'enrolled') RETURNING id",
            req.name,
            fingerprint,
        )
        await conn.execute(
            "UPDATE agent_claims SET used_at = now() WHERE token = $1", req.claim_token
        )
    return EnrollResponse(agent_id=agent_id, cert_pem=cert_pem, ca_pem=pki.ca_pem)


@router.post("/admin/agent-claims", status_code=status.HTTP_201_CREATED)
async def create_claim(
    body: AgentClaimCreate,
    user: AuthUser = Depends(_manage_agents),
    pool: asyncpg.Pool = Depends(get_pool),
) -> AgentClaim:
    token = "".join(secrets.choice(_ALPHANUM) for _ in range(32))
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO agent_claims (token, name, created_by) VALUES ($1, $2, $3)",
            token,
            body.name,
            user.id,
        )
    return AgentClaim(claim_token=token, name=body.name)


# ---- WebSocket ----


async def _reject(ws: WebSocket, reason: str) -> None:
    try:
        await ws.send_text(Rejected(reason=reason).model_dump_json())
        await ws.close()
    except (WebSocketDisconnect, RuntimeError):
        pass


async def _writer(ws: WebSocket, queue: asyncio.Queue[ServerMsg]) -> None:
    try:
        while True:
            msg = await queue.get()
            await ws.send_text(msg.model_dump_json())
    except (WebSocketDisconnect, RuntimeError, asyncio.CancelledError):
        return


async def _handle(
    hub: AgentHub,
    pool: asyncpg.Pool,
    cipher: Cipher,
    agent_id: UUID,
    agent_name: str,
    msg: AgentMsg,
) -> None:
    if isinstance(msg, Ready):
        await hub.set_ready(agent_id, msg.slots)
    elif isinstance(msg, Keyspace):
        await hub.fulfill_keyspace(msg.req_id, msg.value)
    elif isinstance(msg, Progress):
        sink = await hub.sink_for(msg.task_id)
        if sink is not None:
            await sink.put(
                StatusUpdate(
                    task_id=msg.task_id,
                    progress=msg.progress,
                    speed=msg.speed,
                    recovered=msg.recovered,
                    eta=msg.eta,
                    state=_parse_task_state(msg.state),
                )
            )
    elif isinstance(msg, Cracked):
        await ingest.import_cracked(pool, cipher, msg.task_id, msg.items)
    elif isinstance(msg, Metrics):
        devices = [
            DeviceView(
                name=f"{agent_name}/{m.name}",
                kind=m.kind,
                temp=m.temp,
                util=m.util,
                mem_used=m.mem_used,
                mem_total=m.mem_total,
                pstate=m.pstate,
                power_w=m.power_w,
                fan=m.fan,
                clock_mhz=m.clock_mhz,
                mem_clock_mhz=m.mem_clock_mhz,
                hashrate=m.hashrate,
            )
            for m in msg.samples
        ]
        await telemetry.record(pool, devices)
    elif isinstance(msg, TaskDone):
        ts = _parse_task_state(msg.state)
        sink = await hub.sink_for(msg.task_id)
        if sink is not None:
            await sink.put(
                StatusUpdate(
                    task_id=msg.task_id,
                    progress=1.0 if ts == TaskState.DONE else 0.0,
                    speed=0,
                    recovered=0,
                    eta=None,
                    state=ts,
                )
            )
        await hub.finish_task(msg.task_id)
    elif isinstance(msg, AgentError):
        await hub.mark_error(agent_id)
        if msg.task_id is not None:
            sink = await hub.sink_for(msg.task_id)
            if sink is not None:
                await sink.put(
                    StatusUpdate(
                        task_id=msg.task_id,
                        progress=0.0,
                        speed=0,
                        recovered=0,
                        eta=None,
                        state=TaskState.FAILED,
                    )
                )
            await hub.finish_task(msg.task_id)
    # Hello mid-stream is ignored.


@router.websocket("/agent/stream")
async def agent_stream(ws: WebSocket) -> None:
    await ws.accept()
    pool: asyncpg.Pool = ws.app.state.pool
    hub: AgentHub = ws.app.state.hub
    cipher: Cipher = ws.app.state.cipher

    try:
        first = await ws.receive_text()
    except WebSocketDisconnect:
        return
    try:
        hello = _AGENT_MSG.validate_json(first)
    except ValidationError:
        await _reject(ws, "expected hello frame")
        return
    if not isinstance(hello, Hello):
        await _reject(ws, "expected hello frame")
        return
    try:
        fingerprint = fingerprint_of_pem(hello.cert_pem)
    except (ValueError, TypeError):
        await _reject(ws, "bad certificate")
        return

    async with pool.acquire() as conn:
        agent_id = await conn.fetchval(
            "SELECT id FROM agents WHERE fingerprint = $1 AND status <> 'revoked'", fingerprint
        )
    if agent_id is None:
        await _reject(ws, "certificate not enrolled")
        return

    await ws.send_text(Welcome(agent_id=agent_id).model_dump_json())
    sendq: asyncio.Queue[ServerMsg] = asyncio.Queue(maxsize=64)
    await hub.register(agent_id, hello.name, sendq)
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE agents SET status = 'online', last_seen = now(), "
            "os = COALESCE(NULLIF($2, ''), os) WHERE id = $1",
            agent_id,
            hello.os,
        )
    writer = asyncio.create_task(_writer(ws, sendq))
    try:
        while True:
            text = await ws.receive_text()
            try:
                m = _AGENT_MSG.validate_json(text)
            except ValidationError:
                continue
            await _handle(hub, pool, cipher, agent_id, hello.name, m)
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(agent_id)
        async with pool.acquire() as conn:
            await conn.execute("UPDATE agents SET status = 'offline' WHERE id = $1", agent_id)
        writer.cancel()
