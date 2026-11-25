"""File endpoints.

Reads (shared): list_files (ViewJobs) + storage_usage (Ingest).
Writes (Ingest): upload_file + delete_file.

Security fixes folded in (D4):
- Uploads are stored under a server-generated **UUID** name (never the client
  filename), streamed straight to disk while hashing, so a multi-GiB wordlist
  never sits in memory.
- Global storage quota (``[hashcat].files_quota_bytes``, 0 = unlimited) enforced
  as in the Rust server: checked after the write (multipart gives no size up
  front), the just-written file removed and **507** returned if it would exceed
  the cap.
- FJ-007: deleting a file is scoped to its owner (``uploaded_by``); a holder of
  ManageScheduling acts cross-tenant. Reads stay shared.
Mutations are audited (ICD §10).
"""

from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

import anyio
import asyncpg
from fastapi import APIRouter, Depends, File, Form, UploadFile, status

from flamejob_api.schemas import FileView, StorageUsageView
from flamejob_core import Capability, roles_have

from . import queries
from .audit import audit
from .auth import AuthUser
from .config import Config
from .deps import get_config, get_pool, require
from .errors import BadRequest, Forbidden, InsufficientStorage, Internal, NotFound

router = APIRouter(tags=["files"])
_ingest = require(Capability.INGEST)

_FILE_KINDS = frozenset({"wordlist", "rule", "mask", "other"})
_UPLOAD_CHUNK = 1024 * 1024  # 1 MiB read window while streaming to disk


@router.get("/files")
async def list_files(
    _user: object = Depends(require(Capability.VIEW_JOBS)),
    pool: asyncpg.Pool = Depends(get_pool),
) -> list[FileView]:
    async with pool.acquire() as conn:
        return await queries.list_files(conn)


@router.get("/files/usage")
async def storage_usage(
    _user: object = Depends(require(Capability.INGEST)),
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> StorageUsageView:
    async with pool.acquire() as conn:
        return await queries.storage_usage(conn, cfg)


@router.post("/files", status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...),
    kind: str = Form("other"),
    user: AuthUser = Depends(_ingest),
    pool: asyncpg.Pool = Depends(get_pool),
    cfg: Config = Depends(get_config),
) -> FileView:
    if kind not in _FILE_KINDS:
        kind = "other"
    name = file.filename
    if not name:
        raise BadRequest("missing file field")

    file_id = uuid4()
    directory = anyio.Path(cfg.hashcat.data_dir) / "files"
    try:
        await directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise Internal(str(exc)) from exc
    path = directory / str(file_id)

    hasher = hashlib.sha256()
    size_bytes = 0
    try:
        async with await anyio.open_file(path, "wb") as out:
            while True:
                chunk = await file.read(_UPLOAD_CHUNK)
                if not chunk:
                    break
                await out.write(chunk)
                hasher.update(chunk)
                size_bytes += len(chunk)
    except OSError as exc:
        await path.unlink(missing_ok=True)
        raise Internal(str(exc)) from exc

    # Global quota check (0 = unlimited). Matches Rust: checked after streaming,
    # the bytes already on disk are removed before returning when over the cap.
    quota = cfg.hashcat.files_quota_bytes
    if quota > 0:
        async with pool.acquire() as conn:
            used = await conn.fetchval(
                "SELECT COALESCE(SUM(size_bytes), 0)::bigint FROM files"
            )
        if int(used) + size_bytes > quota:
            await path.unlink(missing_ok=True)
            raise InsufficientStorage(
                f"storage quota exceeded: {used} in use + {size_bytes} would exceed {quota}"
            )

    sha256 = hasher.hexdigest()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO files (id, name, kind, path, size_bytes, sha256, uploaded_by) "
            "VALUES ($1,$2,$3::file_kind,$4,$5,$6,$7)",
            file_id,
            name,
            kind,
            str(path),
            size_bytes,
            sha256,
            user.id,
        )
    await audit(pool, user.id, "file.upload", "file", str(file_id), detail={"bytes": size_bytes})
    return FileView(id=file_id, name=name, kind=kind, size_bytes=size_bytes, sha256=sha256)


@router.delete("/files/{file_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_file(
    file_id: UUID,
    user: AuthUser = Depends(_ingest),
    pool: asyncpg.Pool = Depends(get_pool),
) -> None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT path, uploaded_by FROM files WHERE id = $1", file_id
        )
        if row is None:
            raise NotFound("file not found")
        # FJ-007: only the owner (or a ManageScheduling holder) may delete.
        if row["uploaded_by"] != user.id and not roles_have(
            user.roles, Capability.MANAGE_SCHEDULING
        ):
            raise Forbidden("not your file")
        await conn.execute("DELETE FROM files WHERE id = $1", file_id)
    if row["path"]:
        await anyio.Path(row["path"]).unlink(missing_ok=True)
    await audit(pool, user.id, "file.delete", "file", str(file_id))
