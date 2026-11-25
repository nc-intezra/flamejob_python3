"""Telemetry read endpoints. Ports list_devices + device_history (ViewStats)."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends

from flamejob_api.schemas import DeviceSample, DeviceView
from flamejob_core import Capability

from . import queries
from .config import Config
from .deps import get_config, get_pool, require

router = APIRouter(tags=["telemetry"])
_view_stats = require(Capability.VIEW_STATS)


@router.get("/devices")
async def list_devices(
    _user: object = Depends(_view_stats),
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[DeviceView]:
    async with pool.acquire() as conn:
        return await queries.list_devices(conn)


@router.get("/devices/{name}/history")
async def device_history(
    name: str,
    _user: object = Depends(_view_stats),
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> list[DeviceSample]:
    async with pool.acquire() as conn:
        return await queries.device_history(conn, cfg, name)
