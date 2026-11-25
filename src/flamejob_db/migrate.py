"""Migration runner over the existing ``migrations/*.sql``.

The Rust server applies these with ``sqlx migrate`` and records them in the
``_sqlx_migrations`` ledger. This runner is deliberately **sqlx-ledger-aware**:
it treats any version already present in ``_sqlx_migrations`` as applied and
skips it. That is the behaviour the strangler needs — pointed at the shared
production database (every version already applied by Rust) it writes nothing;
pointed at a fresh CI Postgres it applies all 12 in ascending order.

Migrations stay **immutable once shipped** (sqlx checksums each file by
content). We keep the files byte-for-byte from the Rust repo and never edit an
applied one.

NOTE (Phase-0 follow-up): the checksum written here is SHA-384 of the file
bytes, believed to match sqlx's algorithm but **not yet verified byte-for-byte
against a real sqlx-migrated database**. Until that is confirmed in the Phase-3
integration rig, do not let this runner write to a database that the Rust server
will later migrate; in the strangler, Rust owns migrations and this runner only
skips/verifies.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

import asyncpg

_FILENAME = re.compile(r"^(\d+)_(.+)\.sql$")

_LEDGER_DDL = """
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
)
"""


@dataclass(frozen=True)
class Migration:
    version: int
    description: str
    sql: str
    checksum: bytes

    @property
    def name(self) -> str:
        return f"{self.version:04d}_{self.description}"


def load_migrations(directory: str | Path) -> list[Migration]:
    out: list[Migration] = []
    for path in sorted(Path(directory).glob("*.sql")):
        m = _FILENAME.match(path.name)
        if not m:
            continue
        sql = path.read_text(encoding="utf-8")
        out.append(
            Migration(
                version=int(m.group(1)),
                description=m.group(2),
                sql=sql,
                checksum=hashlib.sha384(sql.encode()).digest(),
            )
        )
    out.sort(key=lambda mig: mig.version)
    return out


async def applied_versions(conn: asyncpg.Connection) -> set[int]:
    await conn.execute(_LEDGER_DDL)
    rows = await conn.fetch("SELECT version FROM _sqlx_migrations WHERE success")
    return {int(r["version"]) for r in rows}


async def apply(pool: asyncpg.Pool, directory: str | Path) -> list[int]:
    """Apply any migrations not yet in the ledger. Returns versions applied."""
    migrations = load_migrations(directory)
    applied: list[int] = []
    async with pool.acquire() as conn:
        done = await applied_versions(conn)
        for mig in migrations:
            if mig.version in done:
                continue
            async with conn.transaction():
                await conn.execute(mig.sql)
                await conn.execute(
                    "INSERT INTO _sqlx_migrations "
                    "(version, description, success, checksum, execution_time) "
                    "VALUES ($1, $2, true, $3, 0)",
                    mig.version,
                    mig.description,
                    mig.checksum,
                )
            applied.append(mig.version)
    return applied
