"""Cracked-result ingest. Port of ``agent.rs::import_cracked``.

Resolves the task's hashlist, writes each plaintext **AES-GCM encrypted** into
the matching uncracked `hashes` row, then recomputes `hashlists.cracked`.
"""

from __future__ import annotations

from uuid import UUID

import asyncpg

from flamejob_api.agent import CrackedItem

from .crypto import Cipher


async def import_cracked(
    pool: asyncpg.Pool, cipher: Cipher, task_id: UUID, items: list[CrackedItem]
) -> None:
    async with pool.acquire() as conn:
        hashlist_id = await conn.fetchval(
            "SELECT j.hashlist_id FROM jobs j JOIN tasks t ON t.job_id = j.id WHERE t.id = $1",
            task_id,
        )
        if hashlist_id is None:
            return
        for item in items:
            ct = cipher.encrypt(item.plain.encode())
            await conn.execute(
                "UPDATE hashes SET plain = $1, cracked_at = now() "
                "WHERE hashlist_id = $2 AND hash = $3 AND plain IS NULL",
                ct,
                hashlist_id,
                item.hash,
            )
        await conn.execute(
            "UPDATE hashlists SET cracked = "
            "(SELECT count(*) FROM hashes WHERE hashlist_id = $1 AND plain IS NOT NULL) "
            "WHERE id = $1",
            hashlist_id,
        )
