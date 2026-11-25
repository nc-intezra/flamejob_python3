"""Scheduler primitives. Port of the pure parts of ``scheduler.rs``.

Phase 2b-1 lands the pure, unit-tested helpers: keyspace chunk planning and the
EMA ETA projector. The stateful ``Scheduler`` class — the tick loop,
``fill_fleet``/``claim_and_start``/``consume`` that drive the hub and transition
job/task state — is Phase 2b-2 and will extend this module.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import asyncpg

from flamejob_api.agent import AgentTask, Assign
from flamejob_api.schemas import JobConfig
from flamejob_core import TaskState

from . import fairness, preempt
from .config import Config
from .crypto import Cipher
from .hub import AgentHub, StatusSink

# EMA weight for a fresh rate sample (vs. the retained smoothed rate).
ETA_EMA_ALPHA = 0.4
# Minimum elapsed time between rate samples; shorter gaps are too noisy.
ETA_MIN_DT_SECS = 0.75
# A gap longer than this (seconds) is a discontinuity (pause/resume, restart).
ETA_RESET_SECS = 20

_log = logging.getLogger("flamejob.scheduler")


def plan_chunks(total: int, chunk_size: int, max_chunks: int) -> list[tuple[int, int]]:
    """Split ``total`` keyspace into (offset, len) chunks.

    ``total <= 0`` (unknown) yields a single full-run chunk (len 0 → no
    ``--skip``/``--limit``). The ``max_chunks`` cap widens the chunk size.
    """
    if total <= 0 or chunk_size <= 0:
        return [(0, 0)]
    size = chunk_size
    count = (total + size - 1) // size
    if count > max_chunks:
        size = (total + max_chunks - 1) // max_chunks
    chunks: list[tuple[int, int]] = []
    off = 0
    while off < total:
        length = min(size, total - off)
        chunks.append((off, length))
        off += length
    return chunks


def project_eta(
    prev_progress: float, prev_rate: float, overall: float, dt_secs: float
) -> tuple[float, float | None]:
    """Update the smoothed completion rate from a new progress observation.

    Returns (new_rate, remaining_secs); ``rate`` is progress fraction per second.
    A sub-threshold ``dt_secs`` retains the previous rate. Pure.
    """
    rate = prev_rate
    if dt_secs >= ETA_MIN_DT_SECS:
        inst = (overall - prev_progress) / dt_secs
        if inst > 0.0:
            if prev_rate > 0.0:
                rate = ETA_EMA_ALPHA * inst + (1.0 - ETA_EMA_ALPHA) * prev_rate
            else:
                rate = inst
    remaining: float | None = None
    if rate > 0.0 and overall < 1.0:
        r = (1.0 - overall) / rate
        if math.isfinite(r):
            remaining = r
    return rate, remaining


_TERMINAL_JOB = ("completed", "exhausted", "cancelled", "error")


@dataclass
class JobInputs:
    hash_type: int
    attack_mode: int
    hashes: list[str]
    mask: str | None
    wordlist_id: UUID | None
    rule_ids: list[UUID]
    extra_args: list[str]
    total_keyspace: int


@dataclass
class _EtaState:
    progress: float
    at: datetime
    rate: float


def _task_state_str(s: TaskState) -> str:
    return s.value


class Scheduler:
    """The control-plane brain: admit jobs, chunk them, fill the fleet via the
    hub under fair-share, and drive chunks to terminal state. Port of the remote
    path of scheduler.rs. Exactly one per database (the singular brain).

    asyncio note: the Rust ``Mutex``-guarded maps become plain dicts — asyncio is
    single-threaded, so dict mutations between awaits are atomic; the locks were
    for tokio's multi-thread runtime.
    """

    def __init__(
        self,
        pool: asyncpg.Pool,
        cfg: Config,
        hub: AgentHub,
        cipher: Cipher,
    ) -> None:
        self._pool = pool
        self._cfg = cfg
        self._hub = hub
        self._cipher = cipher
        self._chunk_size = cfg.scheduler.chunk_size
        self._max_chunks = max(cfg.scheduler.max_chunks, 1)
        self._max_concurrent_jobs = cfg.scheduler.max_concurrent_jobs
        self._max_retries = 2
        self._keyspace_timeout = 20.0

        self._inflight: dict[UUID, UUID] = {}  # task_id -> job_id
        self._inputs: dict[UUID, JobInputs] = {}  # job_id -> inputs
        self._progress: dict[UUID, tuple[float, int]] = {}  # task_id -> (progress, speed)
        self._eta: dict[UUID, _EtaState] = {}  # job_id -> ETA state
        self._retries: dict[UUID, int] = {}  # task_id -> attempts
        self._consumers: set[asyncio.Task[None]] = set()
        self._run_task: asyncio.Task[None] | None = None

    # ---- lifecycle ----

    def start(self) -> None:
        if self._run_task is None:
            self._run_task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        if self._run_task is not None:
            self._run_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._run_task
            self._run_task = None
        for t in list(self._consumers):
            t.cancel()

    async def _run(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:
                _log.warning("scheduler tick failed", exc_info=True)
            await asyncio.sleep(2)

    async def tick(self) -> None:
        # 1) Reconcile cancel/pause against in-flight chunks.
        for job_id in self._inflight_jobs():
            st = await self._job_state(job_id)
            if st in ("cancelled", "paused"):
                await self._cancel_inflight_for(job_id)
        # 2) Backstop: finalize running jobs whose chunks are all terminal.
        await self._finalize_completed_jobs()
        # 3) Restart recovery: re-queue running jobs whose in-memory inputs are gone.
        await self._requeue_orphaned_running()
        # 4) Preemption handoff: resume preempt-requeued jobs from their durable
        #    keyspace offset once their chunks have stopped.
        await self._resume_preempted_jobs()
        await self._promote_queued_jobs()
        await self._fill_fleet()

    # ---- restart recovery + preemption handoff (Phase 2d) ----

    async def _requeue_orphaned_running(self) -> None:
        """Re-queue running jobs whose shared inputs are missing from memory (a
        restart mid-job); ``_promote``/``_launch`` then rebuilds their chunk set."""
        async with self._pool.acquire() as conn:
            ids = [
                r["id"]
                for r in await conn.fetch(
                    "SELECT j.id FROM jobs j WHERE j.state = 'running' "
                    "AND EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id "
                    "AND t.state IN ('pending','running'))"
                )
            ]
        for job_id in ids:
            if job_id in self._inputs:
                continue
            async with self._pool.acquire() as conn:
                await conn.execute("UPDATE jobs SET state = 'queued' WHERE id = $1", job_id)

    async def _resume_preempted_jobs(self) -> None:
        """Resume preempt-requeued jobs that have fully stopped: split each stopped
        chunk's unfinished keyspace at its last progress offset and re-dispatch the
        remainder on the (possibly new) pool — the handoff a whole-job restart
        can't do. Rebuilds inputs WITHOUT re-planning chunks (which would wipe the
        split), then flips back to running."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT j.id, j.hashlist_id, j.attack_mode, j.config FROM jobs j "
                "WHERE j.preempt_state = 'requeued' AND j.state = 'paused' "
                "AND (j.resume_after IS NULL OR j.resume_after <= now()) "
                "AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id "
                "AND t.state = 'running')"
            )
        for row in rows:
            job_id = row["id"]
            if self._inflight_count_for(job_id) > 0:
                continue  # an in-flight handle isn't torn down yet; wait a tick
            async with self._pool.acquire() as conn:
                tasks = await conn.fetch(
                    "SELECT id, keyspace_offset, keyspace_len, progress FROM tasks "
                    "WHERE job_id = $1 AND state = 'paused'",
                    job_id,
                )
            for t in tasks:
                noff, nlen = preempt.remaining_window(
                    t["keyspace_offset"], t["keyspace_len"], t["progress"]
                )
                if t["keyspace_len"] > 0 and nlen <= 0:
                    await self._set_task(t["id"], "done")
                else:
                    async with self._pool.acquire() as conn:
                        await conn.execute(
                            "UPDATE tasks SET keyspace_offset = $2, keyspace_len = $3, "
                            "state = 'pending', progress = 0 WHERE id = $1",
                            t["id"],
                            noff,
                            nlen,
                        )
            # Rebuild inputs (hash set + keyspace probe) WITHOUT re-planning.
            try:
                inputs = await self._prepare_inputs(
                    job_id, row["hashlist_id"], row["attack_mode"], row["config"]
                )
            except Exception:
                _log.warning("preempt-resume: failed to rebuild inputs", exc_info=True)
                continue
            self._inputs[job_id] = inputs
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE jobs SET state = 'running', preempt_state = NULL, "
                    "est_completion = NULL WHERE id = $1",
                    job_id,
                )

    # ---- admission ----

    async def _promote_queued_jobs(self) -> None:
        while True:
            if self._max_concurrent_jobs > 0:
                async with self._pool.acquire() as conn:
                    active = await conn.fetchval(
                        "SELECT count(*) FROM jobs WHERE state IN ('assigned','running')"
                    )
                if active and active >= self._max_concurrent_jobs:
                    break
            if not await self._claim_and_start():
                break

    async def _claim_and_start(self) -> bool:
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                row = await conn.fetchrow(
                    "SELECT id, hashlist_id, attack_mode, config FROM jobs "
                    "WHERE state = 'queued' "
                    "ORDER BY COALESCE(priority_override, priority), created_at "
                    "FOR UPDATE SKIP LOCKED LIMIT 1"
                )
                if row is None:
                    return False
                await conn.execute("UPDATE jobs SET state = 'assigned' WHERE id = $1", row["id"])
        job_id = row["id"]
        try:
            await self._launch(job_id, row["hashlist_id"], row["attack_mode"], row["config"])
        except Exception as exc:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE jobs SET state = 'error', error = $2, finished_at = now() "
                    "WHERE id = $1",
                    job_id,
                    str(exc),
                )
            await self._cleanup(job_id)
        return True

    async def _launch(
        self, job_id: UUID, hashlist_id: UUID, attack_mode: int, config: object
    ) -> None:
        inputs = await self._prepare_inputs(job_id, hashlist_id, attack_mode, config)
        chunks = plan_chunks(inputs.total_keyspace, self._chunk_size, self._max_chunks)
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM tasks WHERE job_id = $1", job_id)
            for off, length in chunks:
                await conn.execute(
                    "INSERT INTO tasks "
                    "(id, job_id, runner_id, keyspace_offset, keyspace_len, state) "
                    "VALUES ($1, $2, 'local', $3, $4, 'pending')",
                    uuid4(),
                    job_id,
                    off,
                    length,
                )
            await conn.execute(
                "UPDATE jobs SET state = 'running', started_at = now() WHERE id = $1", job_id
            )
        self._inputs[job_id] = inputs

    async def _prepare_inputs(
        self, job_id: UUID, hashlist_id: UUID, attack_mode: int, config: object
    ) -> JobInputs:
        data = json.loads(config) if isinstance(config, str) else config
        jc = JobConfig.model_validate(data or {})
        async with self._pool.acquire() as conn:
            hash_type = await conn.fetchval(
                "SELECT hash_type FROM hashlists WHERE id = $1", hashlist_id
            )
            rows = await conn.fetch(
                "SELECT hash, salt FROM hashes WHERE hashlist_id = $1", hashlist_id
            )
        hashes = [f"{r['hash']}:{r['salt']}" if r["salt"] else r["hash"] for r in rows]
        if jc.mask is None and jc.wordlist_file_id is None:
            raise ValueError("job has neither wordlist nor mask")
        inputs = JobInputs(
            hash_type=hash_type,
            attack_mode=attack_mode,
            hashes=hashes,
            mask=jc.mask,
            wordlist_id=jc.wordlist_file_id,
            rule_ids=list(jc.rule_file_ids),
            extra_args=list(jc.extra_args),
            total_keyspace=0,
        )
        inputs.total_keyspace = await self._probe_keyspace(inputs)
        return inputs

    def _agent_task(self, inputs: JobInputs, task_id: UUID, offset: int, length: int) -> AgentTask:
        return AgentTask(
            task_id=task_id,
            hash_type=inputs.hash_type,
            attack_mode=inputs.attack_mode,
            hashes=inputs.hashes,
            mask=inputs.mask,
            wordlist=inputs.wordlist_id,
            rules=inputs.rule_ids,
            keyspace_offset=offset,
            keyspace_len=length,
            extra_args=inputs.extra_args,
        )

    async def _probe_keyspace(self, inputs: JobInputs) -> int:
        probe = self._agent_task(inputs, uuid4(), 0, 0)
        fut = await self._hub.keyspace_probe(probe)
        if fut is None:
            return 0
        try:
            return int(await asyncio.wait_for(fut, timeout=self._keyspace_timeout))
        except (asyncio.TimeoutError, asyncio.CancelledError):
            return 0

    # ---- fleet filling ----

    async def _fill_fleet(self) -> None:
        want = max(await self._hub.capacity(), 1)
        quotas = await self._load_quotas()
        while len(self._inflight) < want:
            job_group = await self._active_group_map()
            if_job: dict[UUID, int] = {}
            for jid in self._inflight.values():
                if_job[jid] = if_job.get(jid, 0) + 1
            if_group: dict[str, int] = {}
            for jid, n in if_job.items():
                g = job_group.get(jid, "")
                if_group[g] = if_group.get(g, 0) + n

            rows = await self._fillable_candidate_rows()
            cands = [
                fairness.Candidate(
                    job_id=jid,
                    group=group,
                    priority=priority,
                    created_at=created,
                    in_flight_job=if_job.get(jid, 0),
                )
                for (jid, group, priority, created) in rows
                if jid in self._inputs
            ]
            if not cands:
                break
            job_id = fairness.select_job(cands, if_group, quotas)
            if job_id is None:
                break
            chunk = await self._next_pending_chunk(job_id)
            if chunk is None:
                break
            task_id, off, length = chunk
            if not await self._start_chunk(job_id, task_id, off, length):
                break

    async def _active_group_map(self) -> dict[UUID, str]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, COALESCE(owner_group_sid, '') AS g FROM jobs "
                "WHERE state IN ('running','assigned')"
            )
        return {r["id"]: r["g"] for r in rows}

    async def _fillable_candidate_rows(self) -> list[tuple[UUID, str, int, int]]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT j.id, COALESCE(j.owner_group_sid, '') AS g, "
                "COALESCE(j.priority_override, j.priority) AS prio, "
                "EXTRACT(EPOCH FROM j.created_at)::bigint AS created "
                "FROM jobs j WHERE j.state = 'running' "
                "AND EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id AND t.state = 'pending')"
            )
        return [(r["id"], r["g"], r["prio"], r["created"]) for r in rows]

    async def _load_quotas(self) -> dict[str, fairness.Quota]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT group_sid, weight, floor_slots, ceil_slots FROM group_quota"
            )
        return {
            r["group_sid"]: fairness.Quota(
                weight=max(float(r["weight"]), 1.0),
                floor=r["floor_slots"],
                ceil=r["ceil_slots"],
            )
            for r in rows
        }

    async def _eligible_agents_for(self, job_id: UUID) -> list[UUID] | None:
        async with self._pool.acquire() as conn:
            pools = await conn.fetchval("SELECT eligible_pool_ids FROM jobs WHERE id = $1", job_id)
            if not pools:
                return None
            agents = await conn.fetch(
                "SELECT DISTINCT agent_id FROM agent_pool_members WHERE pool_id = ANY($1)", pools
            )
        return [r["agent_id"] for r in agents]

    async def _next_pending_chunk(self, job_id: UUID) -> tuple[UUID, int, int] | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, keyspace_offset, keyspace_len FROM tasks "
                "WHERE job_id = $1 AND state = 'pending' ORDER BY keyspace_offset LIMIT 1",
                job_id,
            )
        if row is None:
            return None
        return row["id"], row["keyspace_offset"], row["keyspace_len"]

    async def _start_chunk(self, job_id: UUID, task_id: UUID, offset: int, length: int) -> bool:
        inputs = self._inputs.get(job_id)
        if inputs is None:
            return False
        async with self._pool.acquire() as conn:
            pinned = await conn.fetchval("SELECT pinned_agent_id FROM jobs WHERE id = $1", job_id)
        allowed = await self._eligible_agents_for(job_id)
        at = self._agent_task(inputs, task_id, offset, length)
        await self._set_task(task_id, "running")
        sink: StatusSink = asyncio.Queue()
        await self._hub.dispatch(Assign(task=at), pinned, allowed, sink)
        self._inflight[task_id] = job_id
        self._progress[task_id] = (0.0, 0)
        t = asyncio.create_task(self._consume(job_id, task_id, sink))
        self._consumers.add(t)
        t.add_done_callback(self._consumers.discard)
        return True

    async def _consume(self, job_id: UUID, task_id: UUID, sink: StatusSink) -> None:
        last = TaskState.RUNNING
        while True:
            u = await sink.get()
            async with self._pool.acquire() as conn:
                await conn.execute(
                    "UPDATE tasks SET progress = $1, speed = $2, state = $3::task_state, "
                    "updated_at = now() WHERE id = $4",
                    u.progress,
                    u.speed,
                    _task_state_str(u.state),
                    task_id,
                )
            self._progress[task_id] = (u.progress, u.speed)
            eta = await self._compute_job_eta(job_id)
            if eta is not None:
                async with self._pool.acquire() as conn:
                    await conn.execute(
                        "UPDATE jobs SET est_completion = $1 WHERE id = $2", eta, job_id
                    )
            last = u.state
            if u.state in (TaskState.DONE, TaskState.FAILED, TaskState.PAUSED):
                break
        await self._finalize_chunk(job_id, task_id, last)

    async def _finalize_chunk(self, job_id: UUID, task_id: UUID, last: TaskState) -> None:
        self._inflight.pop(task_id, None)
        self._progress.pop(task_id, None)

        st = await self._job_state(job_id)
        if st == "cancelled":
            await self._set_task(task_id, "failed")
            return
        if st == "paused":
            await self._set_task(task_id, "paused")
            return
        if st in ("completed", "exhausted", "error"):
            await self._set_task(task_id, "done" if last == TaskState.DONE else "failed")
            return

        # Remote cracked results are imported by the hub (import_cracked) as they
        # arrive; counts come straight from hashlists.
        total, cracked = await self._counts(job_id)
        if total > 0 and cracked >= total:
            await self._set_task(task_id, "done")
            await self._cancel_inflight_for(job_id)
            await self._set_job_terminal(job_id, "completed")
            return

        if last == TaskState.DONE:
            await self._set_task(task_id, "done")
            async with self._pool.acquire() as conn:
                pending = await conn.fetchval(
                    "SELECT count(*) FROM tasks WHERE job_id = $1 AND state = 'pending'", job_id
                )
            others = self._inflight_count_for(job_id)
            if pending == 0 and others == 0:
                total, cracked = await self._counts(job_id)
                final = "completed" if total > 0 and cracked >= total else "exhausted"
                await self._set_job_terminal(job_id, final)
        else:
            await self._handle_chunk_failure(job_id, task_id)

    async def _handle_chunk_failure(self, job_id: UUID, task_id: UUID) -> None:
        attempts = self._retries.get(task_id, 0) + 1
        self._retries[task_id] = attempts
        if attempts <= self._max_retries:
            await self._set_task(task_id, "pending")  # re-run this chunk
        else:
            await self._set_task(task_id, "failed")
            await self._cancel_inflight_for(job_id)
            await self._set_job_terminal(job_id, "error", "chunk failed after retries")

    async def _compute_job_eta(self, job_id: UUID) -> datetime | None:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT id, state::text AS st, keyspace_len FROM tasks WHERE job_id = $1", job_id
            )
        total = 0.0
        done = 0.0
        for r in rows:
            length = r["keyspace_len"]
            if length <= 0:
                continue
            fl = float(length)
            total += fl
            if r["st"] == "done":
                done += fl
            else:
                p, _ = self._progress.get(r["id"], (0.0, 0))
                done += fl * min(max(p, 0.0), 1.0)
        if total <= 0.0:
            return None
        overall = min(max(done / total, 0.0), 1.0)
        if overall >= 1.0:
            return None

        now = datetime.now(timezone.utc)
        prev = self._eta.get(job_id)
        remaining: float | None
        if prev is not None and (now - prev.at).total_seconds() > ETA_RESET_SECS:
            self._eta[job_id] = _EtaState(progress=overall, at=now, rate=0.0)
            remaining = None
        elif prev is not None:
            dt = (now - prev.at).total_seconds()
            rate, remaining = project_eta(prev.progress, prev.rate, overall, dt)
            if dt >= ETA_MIN_DT_SECS:
                self._eta[job_id] = _EtaState(progress=overall, at=now, rate=rate)
        else:
            self._eta[job_id] = _EtaState(progress=overall, at=now, rate=0.0)
            remaining = None
        if remaining is None or remaining <= 0.0:
            return None
        return now + timedelta(seconds=remaining)

    async def _finalize_completed_jobs(self) -> None:
        async with self._pool.acquire() as conn:
            ids = await conn.fetch(
                "SELECT j.id FROM jobs j WHERE j.state = 'running' "
                "AND NOT EXISTS (SELECT 1 FROM tasks t WHERE t.job_id = j.id "
                "AND t.state IN ('pending','running'))"
            )
        for r in ids:
            job_id = r["id"]
            if self._inflight_count_for(job_id) > 0:
                continue
            total, cracked = await self._counts(job_id)
            final = "completed" if total > 0 and cracked >= total else "exhausted"
            await self._set_job_terminal(job_id, final)

    async def _set_job_terminal(self, job_id: UUID, state: str, error: str | None = None) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE jobs SET state = $2::job_state, error = $3, finished_at = now(), "
                "est_completion = NULL WHERE id = $1 "
                "AND state NOT IN ('completed','exhausted','cancelled','error')",
                job_id,
                state,
                error,
            )
        await self._cleanup(job_id)

    async def _cleanup(self, job_id: UUID) -> None:
        for tid in [t for t, j in self._inflight.items() if j == job_id]:
            self._inflight.pop(tid, None)
        self._inputs.pop(job_id, None)
        self._eta.pop(job_id, None)

    # ---- small helpers ----

    def _inflight_jobs(self) -> list[UUID]:
        return sorted(set(self._inflight.values()))

    def _inflight_count_for(self, job_id: UUID) -> int:
        return sum(1 for j in self._inflight.values() if j == job_id)

    async def _cancel_inflight_for(self, job_id: UUID) -> None:
        for task_id, j in list(self._inflight.items()):
            if j == job_id:
                await self._hub.cancel_task(task_id)

    async def _counts(self, job_id: UUID) -> tuple[int, int]:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT h.total, h.cracked FROM hashlists h "
                "JOIN jobs j ON j.hashlist_id = h.id WHERE j.id = $1",
                job_id,
            )
        if row is None:
            return 0, 0
        return row["total"], row["cracked"]

    async def _job_state(self, job_id: UUID) -> str:
        async with self._pool.acquire() as conn:
            st = await conn.fetchval("SELECT state::text FROM jobs WHERE id = $1", job_id)
        return st or "error"

    async def _set_task(self, task_id: UUID, state: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE tasks SET state = $2::task_state, updated_at = now() WHERE id = $1",
                task_id,
                state,
            )
