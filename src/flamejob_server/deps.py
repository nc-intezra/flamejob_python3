"""FastAPI dependencies: app state access + the AuthUser extractor.

Ports ``auth.rs``'s ``FromRequestParts`` provider chain: a ``fj_`` bearer is an
API key (DB lookup with revoked/disabled/expiry checks + live role load);
anything else is a session JWT (HS256, pinned). Capability gates mirror
``auth.require`` / ``require_any``.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

import asyncpg
import jwt
from fastapi import Depends, Request

from flamejob_core import Capability

from . import queries
from .auth import AuthUser, api_key_hash, decode_token
from .config import Config
from .errors import Forbidden, Unauthorized


def get_pool(request: Request) -> asyncpg.Pool:
    return request.app.state.pool


def get_config(request: Request) -> Config:
    return cast(Config, request.app.state.cfg)


def _bearer(request: Request) -> str:
    header = request.headers.get("authorization")
    if not header or not header.lower().startswith("bearer "):
        raise Unauthorized("missing bearer token")
    return header[7:].strip()


async def current_user(
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> AuthUser:
    token = _bearer(request)
    if token.startswith("fj_"):
        key_hash = api_key_hash(token)
        async with pool.acquire() as conn:
            row = await queries.lookup_api_key(conn, key_hash)
            if row is None:
                raise Unauthorized("invalid API key")
            if not cfg.read_shadow:
                await queries.stamp_api_key_used(conn, key_hash)  # best-effort usage stamp
            roles = await queries.load_roles_for(conn, row["id"])
        return AuthUser(id=row["id"], username=row["username"], roles=roles)

    try:
        return decode_token(cfg, token)
    except jwt.InvalidTokenError as exc:
        raise Unauthorized("invalid or expired token") from exc


def require(cap: Capability) -> Callable[[AuthUser], Awaitable[AuthUser]]:
    async def _dep(user: AuthUser = Depends(current_user)) -> AuthUser:
        try:
            user.require(cap)
        except PermissionError as exc:
            raise Forbidden(str(exc)) from exc
        return user

    return _dep


def require_any(caps: list[Capability]) -> Callable[[AuthUser], Awaitable[AuthUser]]:
    async def _dep(user: AuthUser = Depends(current_user)) -> AuthUser:
        try:
            user.require_any(caps)
        except PermissionError as exc:
            raise Forbidden(str(exc)) from exc
        return user

    return _dep
