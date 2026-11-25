"""Read-side SQL (parameterized asyncpg). Ports the read handlers' queries.

**Parameterized only** — every value is bound as ``$n``; the one constant query
(`JOB_SELECT`) carries no user input. Never build SQL with f-strings / `%`.
"""

from __future__ import annotations

from uuid import UUID

import asyncpg

from flamejob_api.schemas import ApiKeyView, JobHistoryView, JobView, TaskView
from flamejob_core import JobState, Role, TaskState

from .config import Config

# Verbatim port of routes.rs JOB_SELECT, with explicit column aliases so rows
# can be read by name (the Rust tuple form relies on position). No user input.
JOB_SELECT = """
SELECT j.id, j.name AS name, j.hashlist_id, j.state::text AS state, j.priority,
       j.created_at, j.est_completion,
       COALESCE((SELECT SUM(CASE WHEN t.state='done' THEN GREATEST(t.keyspace_len,1)::float8
            ELSE t.progress*GREATEST(t.keyspace_len,1)::float8 END)
            / NULLIF(SUM(GREATEST(t.keyspace_len,1)),0)
            FROM tasks t WHERE t.job_id=j.id),0)::float8 AS progress,
       COALESCE((SELECT SUM(speed) FROM tasks t
            WHERE t.job_id=j.id AND t.state='running'),0)::int8 AS speed,
       h.cracked, h.total, j.pinned_agent_id, ap.name AS pinned_agent,
       j.priority_override, j.preempt_state
  FROM jobs j JOIN hashlists h ON h.id=j.hashlist_id
  LEFT JOIN agents ap ON ap.id=j.pinned_agent_id
"""


def _job_view(r: asyncpg.Record) -> JobView:
    return JobView(
        id=r["id"],
        name=r["name"],
        hashlist_id=r["hashlist_id"],
        state=JobState(r["state"]),
        priority=r["priority"],
        priority_override=r["priority_override"],
        preempt_state=r["preempt_state"],
        created_at=r["created_at"],
        est_completion=r["est_completion"],
        progress=r["progress"],
        speed=r["speed"],
        cracked=r["cracked"],
        total=r["total"],
        pinned_agent_id=r["pinned_agent_id"],
        pinned_agent=r["pinned_agent"],
        running_agents=[],  # filled below (local-mode) / by the hub in Phase 2
    )


async def _running_agents_by_job(conn: asyncpg.Connection, cfg: Config) -> dict[UUID, list[str]]:
    """Per-job running-agent names.

    In remote mode the live names come from the AgentHub (Phase 2); in M1 we can
    still replicate the Rust local-mode fallback: running chunks are attributed
    to the configured local host name. Remote-mode deployments therefore route
    GET /jobs to Rust until Phase 2, or the diff harness normalises this field.
    """
    out: dict[UUID, list[str]] = {}
    if cfg.scheduler.runner == "remote":
        return out
    name = cfg.scheduler.local_agent_name
    rows = await conn.fetch("SELECT job_id FROM tasks WHERE state = 'running'")
    for row in rows:
        out.setdefault(row["job_id"], [])
        if name not in out[row["job_id"]]:
            out[row["job_id"]].append(name)
    return out


async def list_jobs(conn: asyncpg.Connection, cfg: Config) -> list[JobView]:
    rows = await conn.fetch(
        JOB_SELECT + " ORDER BY COALESCE(j.priority_override, j.priority), j.created_at"
    )
    running = await _running_agents_by_job(conn, cfg)
    views = [_job_view(r) for r in rows]
    for v in views:
        if v.id in running:
            v.running_agents = running[v.id]
    return views


async def get_job(conn: asyncpg.Connection, cfg: Config, job_id: UUID) -> JobView | None:
    row = await conn.fetchrow(JOB_SELECT + " WHERE j.id = $1", job_id)
    if row is None:
        return None
    view = _job_view(row)
    running = await _running_agents_by_job(conn, cfg)
    if view.id in running:
        view.running_agents = running[view.id]
    return view


async def list_job_tasks(conn: asyncpg.Connection, job_id: UUID) -> list[TaskView]:
    rows = await conn.fetch(
        "SELECT id, job_id, state::text AS state, progress, speed, keyspace_offset, keyspace_len "
        "FROM tasks WHERE job_id = $1 ORDER BY keyspace_offset",
        job_id,
    )
    return [
        TaskView(
            id=r["id"],
            job_id=r["job_id"],
            state=TaskState(r["state"]),
            progress=r["progress"],
            speed=r["speed"],
            keyspace_offset=r["keyspace_offset"],
            keyspace_len=r["keyspace_len"],
            eta=None,
        )
        for r in rows
    ]


async def list_job_history(conn: asyncpg.Connection) -> list[JobHistoryView]:
    rows = await conn.fetch(
        "SELECT jh.id, jh.name, jh.hashlist_id, jh.state::text AS state, "
        "       h.cracked, h.total, jh.created_at, jh.finished_at "
        "FROM job_history jh JOIN hashlists h ON h.id = jh.hashlist_id "
        "ORDER BY jh.archived_at DESC"
    )
    return [
        JobHistoryView(
            id=r["id"],
            name=r["name"],
            hashlist_id=r["hashlist_id"],
            state=JobState(r["state"]),
            cracked=r["cracked"],
            total=r["total"],
            created_at=r["created_at"],
            finished_at=r["finished_at"],
            archived=True,
        )
        for r in rows
    ]


async def list_api_keys(conn: asyncpg.Connection, user_id: UUID) -> list[ApiKeyView]:
    rows = await conn.fetch(
        "SELECT id, name, prefix, created_at, expires_at, last_used_at, revoked "
        "FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC",
        user_id,
    )
    return [
        ApiKeyView(
            id=r["id"],
            name=r["name"],
            prefix=r["prefix"],
            created_at=r["created_at"],
            expires_at=r["expires_at"],
            last_used_at=r["last_used_at"],
            revoked=r["revoked"],
        )
        for r in rows
    ]


# ---- auth-path reads ----


async def load_roles_for(conn: asyncpg.Connection, user_id: UUID) -> list[Role]:
    rows = await conn.fetch("SELECT role::text AS role FROM user_roles WHERE user_id = $1", user_id)
    out: list[Role] = []
    for r in rows:
        try:
            out.append(Role(r["role"]))
        except ValueError:
            continue
    return out


async def lookup_api_key(conn: asyncpg.Connection, key_hash: str) -> asyncpg.Record | None:
    """Return (id, username) for a live, non-revoked, non-expired key on a non-disabled user."""
    return await conn.fetchrow(
        "SELECT u.id, u.username FROM api_keys k JOIN users u ON u.id = k.user_id "
        "WHERE k.key_hash = $1 AND NOT k.revoked AND NOT u.disabled "
        "  AND (k.expires_at IS NULL OR k.expires_at > now())",
        key_hash,
    )


async def stamp_api_key_used(conn: asyncpg.Connection, key_hash: str) -> None:
    await conn.execute("UPDATE api_keys SET last_used_at = now() WHERE key_hash = $1", key_hash)
