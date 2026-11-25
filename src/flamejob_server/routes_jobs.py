"""Jobs read endpoints (ViewJobs). Port of the GET /jobs* handlers."""

from __future__ import annotations

from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends

from flamejob_api.schemas import JobHistoryView, JobView, TaskView
from flamejob_core import Capability

from . import queries
from .config import Config
from .deps import get_config, get_pool, require
from .errors import NotFound

router = APIRouter(tags=["jobs"])
_view_jobs = require(Capability.VIEW_JOBS)


@router.get("/jobs")
async def list_jobs(
    _user: object = Depends(_view_jobs),
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> list[JobView]:
    async with pool.acquire() as conn:
        return await queries.list_jobs(conn, cfg)


# Declared before /jobs/{id} so "history" is never parsed as an id.
@router.get("/jobs/history")
async def list_job_history(
    _user: object = Depends(_view_jobs),
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[JobHistoryView]:
    async with pool.acquire() as conn:
        return await queries.list_job_history(conn)


@router.get("/jobs/{job_id}")
async def get_job(
    job_id: UUID,
    _user: object = Depends(_view_jobs),
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> JobView:
    async with pool.acquire() as conn:
        view = await queries.get_job(conn, cfg, job_id)
    if view is None:
        raise NotFound("job not found")
    return view


@router.get("/jobs/{job_id}/tasks")
async def list_job_tasks(
    job_id: UUID,
    _user: object = Depends(_view_jobs),
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[TaskView]:
    async with pool.acquire() as conn:
        return await queries.list_job_tasks(conn, job_id)
