"""Preemption + priority-override endpoints (the "management decree" lever).

Port of the ``preempt.rs`` handlers. Both act deliberately against fair-share, so
both require ManageScheduling and are audited. The pure guard/split helpers live
in ``preempt``; the scheduler resume + keyspace handoff in ``scheduler``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, status

from flamejob_api.schemas import PreemptRequest, PriorityOverrideRequest
from flamejob_core import Capability

from .audit import audit
from .auth import AuthUser
from .deps import get_pool, require
from .errors import BadRequest, NotFound
from .preempt import MIN_RUN_SECS, SHIELD_FRAC, is_preemptible

router = APIRouter(tags=["jobs"])
_manage_scheduling = require(Capability.MANAGE_SCHEDULING)

_OVERALL_PROGRESS = (
    "SELECT COALESCE(SUM(CASE WHEN state='done' THEN GREATEST(keyspace_len,1)::float8 "
    "ELSE progress*GREATEST(keyspace_len,1)::float8 END) "
    "/ NULLIF(SUM(GREATEST(keyspace_len,1)),0), 0)::float8 "
    "FROM tasks WHERE job_id = $1"
)


@router.post("/jobs/{job_id}/priority", status_code=status.HTTP_202_ACCEPTED)
async def set_priority_override(
    job_id: UUID,
    req: PriorityOverrideRequest,
    user: AuthUser = Depends(_manage_scheduling),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        res = await conn.execute(
            "UPDATE jobs SET priority_override = $2 WHERE id = $1",
            job_id,
            req.priority_override,
        )
    if res.endswith("0"):
        raise NotFound("job not found")
    await audit(
        pool,
        user.id,
        "schedule.priority_override",
        "job",
        str(job_id),
        detail={"override": req.priority_override, "reason": req.reason or ""},
    )


@router.post("/jobs/{job_id}/preempt", status_code=status.HTTP_202_ACCEPTED)
async def preempt_job(
    job_id: UUID,
    req: PreemptRequest,
    user: AuthUser = Depends(_manage_scheduling),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    reason = req.reason or ""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT state::text AS state, started_at FROM jobs WHERE id = $1", job_id
        )
        if row is None:
            raise NotFound("job not found")
        if row["state"] != "running":
            raise BadRequest(f"job is {row['state']}, only a running job can be preempted")

        if req.mode == "cancel":
            await conn.execute(
                "UPDATE jobs SET state = 'cancelled', preempt_state = 'cancelled', "
                "preempted_at = now(), preempt_reason = $2, est_completion = NULL WHERE id = $1",
                job_id,
                reason,
            )
        elif req.mode == "requeue":
            # Guards (skippable with force): don't evict a just-started or
            # nearly-finished job.
            if not req.force:
                started = row["started_at"]
                run_secs = (
                    int((datetime.now(timezone.utc) - started).total_seconds())
                    if started is not None
                    else 0
                )
                prog = await conn.fetchval(_OVERALL_PROGRESS, job_id)
                if not is_preemptible(run_secs, float(prog), MIN_RUN_SECS, SHIELD_FRAC):
                    raise BadRequest(
                        "job just started or is near completion — pass force to override"
                    )
            # Optional demotion: hand the remaining keyspace to another pool.
            if req.target_pool_id is not None:
                exists = await conn.fetchval(
                    "SELECT id FROM agent_pools WHERE id = $1", req.target_pool_id
                )
                if exists is None:
                    raise BadRequest("unknown target pool")
                await conn.execute(
                    "UPDATE jobs SET eligible_pool_ids = ARRAY[$2]::uuid[] WHERE id = $1",
                    job_id,
                    req.target_pool_id,
                )
            # Ride the paused->running machinery: 'paused' makes the scheduler stop
            # the in-flight chunks cleanly; preempt_state='requeued' tells its
            # resume path to split the stopped chunks at their offset and
            # re-dispatch the remainder (on the possibly-new pool).
            await conn.execute(
                "UPDATE jobs SET state = 'paused', preempt_state = 'requeued', "
                "preempted_at = now(), preempt_reason = $2, resume_after = now(), "
                "est_completion = NULL WHERE id = $1",
                job_id,
                reason,
            )
        else:
            raise BadRequest(f"mode must be requeue|cancel, got '{req.mode}'")

    await audit(
        pool,
        user.id,
        "schedule.preempt",
        "job",
        str(job_id),
        detail={
            "mode": req.mode,
            "target_pool": str(req.target_pool_id) if req.target_pool_id else None,
            "reason": reason,
        },
    )
