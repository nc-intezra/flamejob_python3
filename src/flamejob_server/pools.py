"""Agent pools + server-enforced job→pool eligibility. Port of ``pools.rs``.

``summarize_grants`` is pure (unit-tested); ``compute_eligibility`` resolves a
job owner's eligibility at submit from the owner's *verified* cached group SIDs
— never a client field. The admin pool CRUD endpoints are deferred to a later
sub-phase; the scheduler + submit path only need these two functions.

FJ-011 (flagged): a local (non-directory) account is currently unrestricted —
eligible for all pools. Tightening that to require an explicit grant/flag for
local accounts is a follow-up decision, not changed here.
"""

from __future__ import annotations

from uuid import UUID

import asyncpg

from .errors import Forbidden


def summarize_grants(pairs: list[tuple[str, UUID]]) -> tuple[str | None, list[UUID]]:
    """Reduce grant pairs to (owner_group_sid, eligible_pool_ids).

    The owning group (charged for fairness) is the lexicographically smallest
    granting SID; eligible pools are the distinct granted pools, first-seen order.
    """
    pools: list[UUID] = []
    for _group, pool in pairs:
        if pool not in pools:
            pools.append(pool)
    owner = min((g for g, _ in pairs), default=None)
    return owner, pools


async def compute_eligibility(
    conn: asyncpg.Connection, owner_user_id: UUID
) -> tuple[str | None, list[UUID]]:
    """Owner eligibility at submit. Raises Forbidden for a directory user with no grant."""
    pools_exist = await conn.fetchval("SELECT count(*) FROM agent_pools")
    if not pools_exist:
        return None, []  # no pools anywhere → unrestricted (pre-v2.0 behaviour)
    external_sid = await conn.fetchval(
        "SELECT external_sid FROM users WHERE id = $1", owner_user_id
    )
    if external_sid is None:
        return None, []  # local / break-glass account → unrestricted (FJ-011)
    rows = await conn.fetch(
        "SELECT g.group_sid, g.pool_id FROM directory_agent_grants g "
        "JOIN user_dir_groups u ON u.group_sid = g.group_sid WHERE u.user_id = $1",
        owner_user_id,
    )
    if not rows:
        raise Forbidden(
            "no authorized agent pools for your groups — ask an admin for a pool grant"
        )
    return summarize_grants([(r["group_sid"], r["pool_id"]) for r in rows])
