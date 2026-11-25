"""Auth read endpoints: /auth/me, /auth/api-keys, /auth/capabilities."""

from __future__ import annotations

import asyncpg
from fastapi import APIRouter, Depends

from flamejob_api.schemas import ApiKeyView, MeResponse
from flamejob_core import Role

from . import queries
from .auth import AuthUser
from .deps import current_user, get_pool

router = APIRouter(tags=["auth"])


@router.get("/auth/me")
async def me(user: AuthUser = Depends(current_user)) -> MeResponse:
    return MeResponse(id=user.id, username=user.username, roles=user.roles)


@router.get("/auth/api-keys")
async def list_api_keys(
    user: AuthUser = Depends(current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[ApiKeyView]:
    async with pool.acquire() as conn:
        return await queries.list_api_keys(conn, user.id)


@router.get("/auth/capabilities")
async def capabilities() -> dict[str, list[str]]:
    """The role→capability map, single-sourced from the domain model.

    Lets the dashboard derive ROLE_CAPS from the server instead of hand-mirroring
    model.rs (plan §7). Public: it is static policy, not user data.
    """
    return {role.value: [c.value for c in role.capabilities] for role in Role}
