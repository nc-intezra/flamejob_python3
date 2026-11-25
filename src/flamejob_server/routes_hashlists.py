"""Hashlist read endpoints. Ports list_hashlists (ViewJobs) + list_cracked (ViewPlaintext)."""

from __future__ import annotations

from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends

from flamejob_api.schemas import CrackedHash, HashlistView
from flamejob_core import Capability

from . import queries
from .config import Config
from .crypto import Cipher, key_from_config
from .deps import get_config, get_pool, require

router = APIRouter(tags=["hashlists"])


@router.get("/hashlists")
async def list_hashlists(
    _user: object = Depends(require(Capability.VIEW_JOBS)),
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[HashlistView]:
    async with pool.acquire() as conn:
        return await queries.list_hashlists(conn)


@router.get("/hashlists/{hashlist_id}/cracked")
async def list_cracked(
    hashlist_id: UUID,
    _user: object = Depends(require(Capability.VIEW_PLAINTEXT)),
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> list[CrackedHash]:
    cipher = Cipher(key_from_config(cfg))
    async with pool.acquire() as conn:
        return await queries.list_cracked(conn, cipher, hashlist_id)
