"""Audit sink. Writes privileged mutations to ``audit_events`` (ICD §10).

Best-effort: an audit insert failure must never fail the mutation it records.
"""

from __future__ import annotations

import json
from uuid import UUID

import asyncpg


async def audit(
    pool: asyncpg.Pool,
    actor_user_id: UUID | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    outcome: str = "ok",
    detail: dict[str, object] | None = None,
) -> None:
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO audit_events "
                "(actor_user_id, action, target_type, target_id, outcome, detail) "
                "VALUES ($1, $2, $3, $4, $5, $6::jsonb)",
                actor_user_id,
                action,
                target_type,
                target_id,
                outcome,
                json.dumps(detail) if detail is not None else None,
            )
    except asyncpg.PostgresError:
        pass
