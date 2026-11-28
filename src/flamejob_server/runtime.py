"""Scheduler runtime supervisor + the singular-brain guard.

The scheduler, the AgentHub fan-out, and the telemetry collector are stateful and
in-process: exactly one process may run them against a given database, or jobs
double-dispatch (plan §3). The Rust server leaves this to operational discipline;
the port enforces it with a Postgres **session-level advisory lock** so a second
process simply runs API-only instead of corrupting the queue.

``SchedulerSupervisor.start`` acquires the lock on a dedicated connection held for
the process lifetime. Won → it constructs and starts the :class:`Scheduler`. Lost
→ it logs and leaves the scheduler unstarted; the REST surface still serves (a
read replica / M1 read-shadow deploy). ``stop`` tears the scheduler down and
releases the lock.
"""

from __future__ import annotations

import contextlib
import hashlib
import logging

import asyncpg

from .config import Config
from .crypto import Cipher
from .hub import AgentHub
from .scheduler import Scheduler

_log = logging.getLogger("flamejob.runtime")

# Stable 64-bit (signed bigint) advisory-lock key for "the flamejob scheduler".
# Derived once from a fixed label so every process computes the same value.
_LOCK_KEY = int.from_bytes(
    hashlib.blake2b(b"flamejob.scheduler", digest_size=8).digest(), "big", signed=True
)


class SchedulerSupervisor:
    """Owns the scheduler's lifecycle and the advisory lock that keeps it singular."""

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lock_conn: asyncpg.Connection | None = None
        self._scheduler: Scheduler | None = None
        self.active = False

    @property
    def scheduler(self) -> Scheduler | None:
        return self._scheduler

    async def start(self, pool: asyncpg.Pool, hub: AgentHub, cipher: Cipher) -> None:
        if not self._cfg.scheduler.enabled:
            _log.info("scheduler disabled by config; serving API-only")
            return
        # A standalone connection (not from the pool) so the session-level lock is
        # held for the whole process and never handed back / reset.
        conn = await asyncpg.connect(dsn=self._cfg.database.dsn)
        try:
            won = await conn.fetchval("SELECT pg_try_advisory_lock($1)", _LOCK_KEY)
        except Exception:
            await conn.close()
            raise
        if not won:
            await conn.close()
            _log.warning(
                "another control-plane brain holds the scheduler lock; serving API-only"
            )
            return
        self._lock_conn = conn
        self._scheduler = Scheduler(pool, self._cfg, hub, cipher)
        self._scheduler.start()
        self.active = True
        _log.info("scheduler started (singular brain; advisory lock held)")

    async def stop(self) -> None:
        if self._scheduler is not None:
            await self._scheduler.stop()
            self._scheduler = None
        if self._lock_conn is not None:
            with contextlib.suppress(Exception):
                await self._lock_conn.execute("SELECT pg_advisory_unlock($1)", _LOCK_KEY)
            with contextlib.suppress(Exception):
                await self._lock_conn.close()
            self._lock_conn = None
        self.active = False
