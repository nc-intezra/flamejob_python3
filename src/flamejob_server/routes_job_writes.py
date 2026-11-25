"""Job write endpoints. Port of create_job / state changes / patch / clear / pin.

Security fixes folded in (D4):
- FJ-004: hashcat ``extra_args``/``mask`` pass a server-side allowlist before the
  job is created (``job_args``), never reaching the runner raw.
- FJ-007: job mutations are scoped to the owner — an Operator may only act on
  their own jobs; a holder of ManageScheduling (Superadmin) acts cross-tenant.
Every mutation is audited (ICD §10).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Depends, status

from flamejob_api.schemas import ClearedJobs, JobCreate, JobView, PatchJob, PinRequest
from flamejob_core import Capability, JobState, roles_have

from . import job_args
from .audit import audit
from .auth import AuthUser
from .deps import get_pool, require
from .errors import Forbidden, NotFound, TooManyRequests
from .pools import compute_eligibility

router = APIRouter(tags=["jobs"])
_submit = require(Capability.SUBMIT_JOBS)
_manage_agents = require(Capability.MANAGE_AGENTS)

# Archive finished jobs into job_history, then delete them from the live queue.
_ARCHIVE_ALL = (
    "INSERT INTO job_history "
    "(id, name, hashlist_id, owner_user_id, attack_mode, state, created_at, finished_at) "
    "SELECT id, name, hashlist_id, owner_user_id, attack_mode, state, created_at, finished_at "
    "FROM jobs WHERE state IN ('completed','exhausted','cancelled','error') "
    "ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, "
    "finished_at = EXCLUDED.finished_at, archived_at = now()"
)
_DELETE_ALL = "DELETE FROM jobs WHERE state IN ('completed','exhausted','cancelled','error')"
_ARCHIVE_OWN = (
    "INSERT INTO job_history "
    "(id, name, hashlist_id, owner_user_id, attack_mode, state, created_at, finished_at) "
    "SELECT id, name, hashlist_id, owner_user_id, attack_mode, state, created_at, finished_at "
    "FROM jobs WHERE state IN ('completed','exhausted','cancelled','error') AND owner_user_id = $1 "
    "ON CONFLICT (id) DO UPDATE SET state = EXCLUDED.state, "
    "finished_at = EXCLUDED.finished_at, archived_at = now()"
)
_DELETE_OWN = (
    "DELETE FROM jobs WHERE state IN ('completed','exhausted','cancelled','error') "
    "AND owner_user_id = $1"
)


async def _authorize_job_mutation(conn: asyncpg.Connection, user: AuthUser, job_id: UUID) -> None:
    """FJ-007: the caller must own the job, or hold ManageScheduling (cross-tenant)."""
    owner = await conn.fetchval("SELECT owner_user_id FROM jobs WHERE id = $1", job_id)
    if owner is None:
        raise NotFound("job not found")
    if user.id == owner or roles_have(user.roles, Capability.MANAGE_SCHEDULING):
        return
    raise Forbidden("not your job")


@router.post("/jobs", status_code=status.HTTP_201_CREATED)
async def create_job(
    body: JobCreate,
    user: AuthUser = Depends(_submit),
    pool: asyncpg.Pool = Depends(get_pool),
) -> JobView:
    # FJ-004: validate hashcat arguments before anything is persisted.
    if body.config.mask is not None:
        job_args.validate_mask(body.config.mask)
    job_args.validate_extra_args(body.config.extra_args)

    job_id = uuid4()
    priority = body.priority if body.priority is not None else 100
    config_json = body.config.model_dump_json()
    async with pool.acquire() as conn:
        # Server-derived eligibility; raises Forbidden for a directory user with
        # no granted pool once pools exist (never a client field).
        owner_group_sid, eligible_pool_ids = await compute_eligibility(conn, user.id)
        if owner_group_sid is not None:
            m = await conn.fetchval(
                "SELECT max_submit_jobs FROM group_quota WHERE group_sid = $1", owner_group_sid
            )
            if m is not None:
                active = await conn.fetchval(
                    "SELECT count(*) FROM jobs WHERE owner_group_sid = $1 "
                    "AND state IN ('queued','assigned','running')",
                    owner_group_sid,
                )
                if active >= m:
                    raise TooManyRequests(
                        f"your group's submit limit is reached ({m} queued/running jobs)"
                    )
        await conn.execute(
            "INSERT INTO jobs "
            "(id, name, owner_user_id, hashlist_id, attack_mode, config, priority, "
            "owner_group_sid, eligible_pool_ids) "
            "VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)",
            job_id,
            body.name,
            user.id,
            body.hashlist_id,
            body.attack_mode,
            config_json,
            priority,
            owner_group_sid,
            eligible_pool_ids,
        )
        total = await conn.fetchval("SELECT total FROM hashlists WHERE id = $1", body.hashlist_id)
    await audit(pool, user.id, "job.create", "job", str(job_id))
    return JobView(
        id=job_id,
        name=body.name,
        hashlist_id=body.hashlist_id,
        state=JobState.QUEUED,
        priority=priority,
        created_at=datetime.now(timezone.utc),
        progress=0.0,
        speed=0,
        cracked=0,
        total=total or 0,
    )


@router.patch("/jobs/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def patch_job(
    job_id: UUID,
    body: PatchJob,
    user: AuthUser = Depends(_submit),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        await _authorize_job_mutation(conn, user, job_id)
        await conn.execute("UPDATE jobs SET priority = $1 WHERE id = $2", body.priority, job_id)
    await audit(pool, user.id, "job.patch", "job", str(job_id), detail={"priority": body.priority})


async def _set_state(pool: asyncpg.Pool, user: AuthUser, job_id: UUID, to: JobState) -> None:
    async with pool.acquire() as conn:
        await _authorize_job_mutation(conn, user, job_id)
        await conn.execute(
            "UPDATE jobs SET state = $1::job_state, est_completion = NULL WHERE id = $2",
            to.value,
            job_id,
        )
    await audit(pool, user.id, f"job.{to.value}", "job", str(job_id))


@router.post("/jobs/{job_id}/pause", status_code=status.HTTP_202_ACCEPTED)
async def pause_job(
    job_id: UUID, user: AuthUser = Depends(_submit), pool: asyncpg.Pool = Depends(get_pool)
) -> None:
    await _set_state(pool, user, job_id, JobState.PAUSED)


@router.post("/jobs/{job_id}/resume", status_code=status.HTTP_202_ACCEPTED)
async def resume_job(
    job_id: UUID, user: AuthUser = Depends(_submit), pool: asyncpg.Pool = Depends(get_pool)
) -> None:
    await _set_state(pool, user, job_id, JobState.QUEUED)


@router.post("/jobs/{job_id}/cancel", status_code=status.HTTP_202_ACCEPTED)
async def cancel_job(
    job_id: UUID, user: AuthUser = Depends(_submit), pool: asyncpg.Pool = Depends(get_pool)
) -> None:
    await _set_state(pool, user, job_id, JobState.CANCELLED)


@router.post("/jobs/clear")
async def clear_finished_jobs(
    user: AuthUser = Depends(_submit),
    pool: asyncpg.Pool = Depends(get_pool),
) -> ClearedJobs:
    # FJ-007: scope the clear to the caller's own finished jobs unless they hold
    # ManageScheduling (then clear the whole queue, as the Rust server does).
    cross = roles_have(user.roles, Capability.MANAGE_SCHEDULING)
    async with pool.acquire() as conn, conn.transaction():
        if cross:
            await conn.execute(_ARCHIVE_ALL)
            res = await conn.execute(_DELETE_ALL)
        else:
            await conn.execute(_ARCHIVE_OWN, user.id)
            res = await conn.execute(_DELETE_OWN, user.id)
    cleared = int(res.split()[-1]) if res.startswith("DELETE") else 0
    await audit(pool, user.id, "job.clear", "job", None, detail={"cleared": cleared})
    return ClearedJobs(cleared=cleared)


@router.post("/jobs/{job_id}/pin", status_code=status.HTTP_202_ACCEPTED)
async def pin_job(
    job_id: UUID,
    req: PinRequest,
    user: AuthUser = Depends(_manage_agents),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        exists = await conn.fetchval("SELECT id FROM agents WHERE id = $1", req.agent_id)
        if exists is None:
            raise NotFound("agent not found")
        updated = await conn.execute(
            "UPDATE jobs SET pinned_agent_id = $1 WHERE id = $2", req.agent_id, job_id
        )
    if updated.endswith("0"):
        raise NotFound("job not found")
    await audit(pool, user.id, "job.pin", "job", str(job_id), detail={"agent": str(req.agent_id)})


@router.delete("/jobs/{job_id}/pin", status_code=status.HTTP_202_ACCEPTED)
async def unpin_job(
    job_id: UUID,
    user: AuthUser = Depends(_manage_agents),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        await conn.execute("UPDATE jobs SET pinned_agent_id = NULL WHERE id = $1", job_id)
    await audit(pool, user.id, "job.unpin", "job", str(job_id))
