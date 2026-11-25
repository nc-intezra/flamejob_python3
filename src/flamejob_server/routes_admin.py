"""Admin endpoints: POST /admin/users (ManageUsers).

Security fix folded in (D4):
- FJ-005 (role-grant ceiling): the Rust ``create_user`` inserts whatever roles
  the body names, so a bare ManageUsers holder could mint a Superadmin. Here a
  caller may grant only roles **strictly below** their own highest role rank
  (Superadmin > Admin > Operator > Viewer) — nobody escalates to or beyond their
  own level, and no one creates a Superadmin through the API. Audited.
"""

from __future__ import annotations

from uuid import uuid4

import asyncpg
from fastapi import APIRouter, Depends, status

from flamejob_api.schemas import UserCreate
from flamejob_core import Capability, Role

from .audit import audit
from .auth import AuthUser, hash_password
from .deps import get_pool, require
from .errors import BadRequest, Forbidden

router = APIRouter(tags=["admin"])
_manage_users = require(Capability.MANAGE_USERS)

# FJ-005 privilege ordering. Server-side policy (not in the Rust model), so it
# lives here rather than in flamejob_core, which stays a faithful port of model.rs.
_ROLE_RANK: dict[Role, int] = {
    Role.VIEWER: 0,
    Role.OPERATOR: 1,
    Role.ADMIN: 2,
    Role.SUPERADMIN: 3,
}


def _caller_rank(user: AuthUser) -> int:
    return max((_ROLE_RANK[r] for r in user.roles), default=-1)


@router.post("/admin/users", status_code=status.HTTP_201_CREATED)
async def create_user(
    body: UserCreate,
    user: AuthUser = Depends(_manage_users),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    username = body.username.strip()
    if not username:
        raise BadRequest("username is required")

    # FJ-005: cannot grant a role at or above the caller's own rank.
    ceiling = _caller_rank(user)
    over = [r for r in body.roles if _ROLE_RANK[r] >= ceiling]
    if over:
        raise Forbidden(
            "cannot grant a role at or above your own: " + ", ".join(r.value for r in over)
        )

    user_id = uuid4()
    pw_hash = hash_password(body.password)
    async with pool.acquire() as conn, conn.transaction():
        try:
            await conn.execute(
                "INSERT INTO users (id, username, source, password_hash) "
                "VALUES ($1,$2,'local',$3)",
                user_id,
                username,
                pw_hash,
            )
        except asyncpg.UniqueViolationError as exc:
            raise BadRequest("username already exists") from exc
        for role in body.roles:
            await conn.execute(
                "INSERT INTO user_roles (user_id, role) VALUES ($1, $2::role)",
                user_id,
                role.value,
            )
    await audit(
        pool,
        user.id,
        "user.create",
        "user",
        str(user_id),
        detail={"username": username, "roles": [r.value for r in body.roles]},
    )
