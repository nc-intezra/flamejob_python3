"""File read endpoints. Ports list_files (ViewJobs) + storage_usage (Ingest)."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends

from flamejob_api.schemas import FileView, StorageUsageView
from flamejob_core import Capability

from . import queries
from .config import Config
from .deps import get_config, get_pool, require

router = APIRouter(tags=["files"])


@router.get("/files")
async def list_files(
    _user: object = Depends(require(Capability.VIEW_JOBS)),
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[FileView]:
    async with pool.acquire() as conn:
        return await queries.list_files(conn)


@router.get("/files/usage")
async def storage_usage(
    _user: object = Depends(require(Capability.INGEST)),
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> StorageUsageView:
    async with pool.acquire() as conn:
        return await queries.storage_usage(conn, cfg)
