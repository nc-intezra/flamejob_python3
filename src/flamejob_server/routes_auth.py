"""Auth endpoints.

Reads: /auth/me, GET /auth/api-keys, /auth/capabilities.
Writes: POST /auth/api-keys, DELETE /auth/api-keys/{id} — a user manages only
their own keys (scoped by ``user_id`` on every statement). Mutations audited.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, status

from flamejob_api.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyView, MeResponse
from flamejob_core import Role

from . import queries
from .audit import audit
from .auth import AuthUser, generate_api_key
from .deps import current_user, get_pool
from .errors import BadRequest, NotFound

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


@router.post("/auth/api-keys", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    body: ApiKeyCreate,
    user: AuthUser = Depends(current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> ApiKeyCreated:
    name = body.name.strip()
    if not name:
        raise BadRequest("key name is required")
    # Default 1-year lifetime; 0 or negative means it never expires (Rust parity).
    days = body.expires_in_days if body.expires_in_days is not None else 365
    expires_at = datetime.now(timezone.utc) + timedelta(days=days) if days > 0 else None
    secret, prefix, key_hash = generate_api_key()
    async with pool.acquire() as conn:
        key_id = await conn.fetchval(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, expires_at) "
            "VALUES ($1,$2,$3,$4,$5) RETURNING id",
            user.id,
            name,
            prefix,
            key_hash,
            expires_at,
        )
    await audit(pool, user.id, "apikey.create", "api_key", str(key_id))
    return ApiKeyCreated(id=key_id, name=name, prefix=prefix, key=secret, expires_at=expires_at)


@router.delete("/auth/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: UUID,
    user: AuthUser = Depends(current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        res = await conn.execute(
            "UPDATE api_keys SET revoked = true "
            "WHERE id = $1 AND user_id = $2 AND NOT revoked",
            key_id,
            user.id,
        )
    if res.endswith("0"):
        raise NotFound("api key not found")
    await audit(pool, user.id, "apikey.revoke", "api_key", str(key_id))


@router.get("/auth/capabilities")
async def capabilities() -> dict[str, list[str]]:
    """The role→capability map, single-sourced from the domain model.

    Lets the dashboard derive ROLE_CAPS from the server instead of hand-mirroring
    model.rs (plan §7). Public: it is static policy, not user data.
    """
    return {role.value: [c.value for c in role.capabilities] for role in Role}
