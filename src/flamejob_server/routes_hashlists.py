"""Hashlist endpoints.

Reads (shared): list_hashlists (ViewJobs) + list_cracked (ViewPlaintext).
Writes (Ingest): create_hashlist + import_hashes.

Security fixes folded in (D4):
- FJ-007: *writing into* a hashlist (import) is scoped to its owner
  (``created_by``); a holder of ManageScheduling acts cross-tenant. Reads stay
  shared (the hashlist catalog is referenced by jobs across operators) — see the
  port plan's Phase 2c review.
Mutations are audited (ICD §10).
"""

from __future__ import annotations

from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Depends, Request, status

from flamejob_api.schemas import CrackedHash, HashlistCreate, HashlistView
from flamejob_core import Capability, roles_have

from . import queries
from .audit import audit
from .auth import AuthUser
from .config import Config
from .crypto import Cipher, key_from_config
from .deps import get_config, get_pool, require
from .errors import BadRequest, Forbidden, NotFound

router = APIRouter(tags=["hashlists"])
_ingest = require(Capability.INGEST)

# Stream guard matching the Rust server (§7): refuse a body past 8 GiB rather
# than buffering it. The stream is consumed in chunks and inserted in batches, so
# only one batch of rows is ever held in memory.
_MAX_HASH_UPLOAD = 8 * 1024 * 1024 * 1024  # 8 GiB
_HASH_COPY_BATCH = 10_000  # rows per COPY flush


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


@router.post("/hashlists", status_code=status.HTTP_201_CREATED)
async def create_hashlist(
    body: HashlistCreate,
    user: AuthUser = Depends(_ingest),
    pool: asyncpg.Pool = Depends(get_pool),
) -> HashlistView:
    hashlist_id = uuid4()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO hashlists (id, name, hash_type, created_by) VALUES ($1,$2,$3,$4)",
            hashlist_id,
            body.name,
            body.hash_type,
            user.id,
        )
    await audit(pool, user.id, "hashlist.create", "hashlist", str(hashlist_id))
    return HashlistView(
        id=hashlist_id, name=body.name, hash_type=body.hash_type, total=0, cracked=0
    )


async def _flush_hashes(
    conn: asyncpg.Connection, hashlist_id: UUID, batch: list[tuple[UUID, str]]
) -> None:
    if not batch:
        return
    # Binary COPY (no delimiter escaping); far lighter than the Rust multi-VALUES
    # batches and insulated from hash contents.
    await conn.copy_records_to_table(
        "hashes", records=batch, columns=["hashlist_id", "hash"]
    )
    batch.clear()


@router.post("/hashlists/{hashlist_id}/hashes")
async def import_hashes(
    hashlist_id: UUID,
    request: Request,
    user: AuthUser = Depends(_ingest),
    pool: asyncpg.Pool = Depends(get_pool),
) -> HashlistView:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT hash_type, created_by FROM hashlists WHERE id = $1", hashlist_id
        )
        if row is None:
            raise NotFound("hashlist not found")
        # FJ-007: only the owner (or a ManageScheduling holder) may import.
        _authorize_hashlist_write(user, row["created_by"])

        pending = bytearray()
        batch: list[tuple[UUID, str]] = []
        total_bytes = 0
        async with conn.transaction():
            async for chunk in request.stream():
                total_bytes += len(chunk)
                if total_bytes > _MAX_HASH_UPLOAD:
                    raise BadRequest("hash upload exceeds 8 GiB limit")
                pending.extend(chunk)
                # Split on newlines; keep only the trailing partial line.
                start = 0
                nl = pending.find(b"\n", start)
                while nl != -1:
                    line = pending[start:nl].decode("utf-8", "replace").strip()
                    if line:
                        batch.append((hashlist_id, line))
                    start = nl + 1
                    nl = pending.find(b"\n", start)
                del pending[:start]
                if len(batch) >= _HASH_COPY_BATCH:
                    await _flush_hashes(conn, hashlist_id, batch)
            tail = pending.decode("utf-8", "replace").strip()
            if tail:
                batch.append((hashlist_id, tail))
            await _flush_hashes(conn, hashlist_id, batch)

        counts = await conn.fetchrow(
            "SELECT count(*) AS total, count(plain) AS cracked FROM hashes WHERE hashlist_id = $1",
            hashlist_id,
        )
        total = int(counts["total"])
        cracked = int(counts["cracked"])
        await conn.execute(
            "UPDATE hashlists SET total = $1, cracked = $2 WHERE id = $3",
            total,
            cracked,
            hashlist_id,
        )
        name = await conn.fetchval("SELECT name FROM hashlists WHERE id = $1", hashlist_id)
    await audit(
        pool, user.id, "hashlist.import", "hashlist", str(hashlist_id), detail={"total": total}
    )
    return HashlistView(
        id=hashlist_id, name=name, hash_type=row["hash_type"], total=total, cracked=cracked
    )


def _authorize_hashlist_write(user: AuthUser, created_by: UUID | None) -> None:
    if created_by is not None and user.id == created_by:
        return
    if roles_have(user.roles, Capability.MANAGE_SCHEDULING):
        return
    raise Forbidden("not your hashlist")
