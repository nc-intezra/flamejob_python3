"""The agent hub. asyncio port of ``agent.rs``'s ``AgentHub``.

The tokio design (``Mutex<HubInner>`` + per-connection ``mpsc`` + ``oneshot``
keyspace waiters + ``broadcast``/``watch``) maps onto: a single ``asyncio.Lock``
guarding the inner maps, one bounded ``asyncio.Queue`` per connection as its
writer channel, and ``asyncio.Future`` keyspace waiters. ``drain`` stays
synchronous (no awaits, only ``put_nowait``) exactly as the Rust ``fn drain``,
so assignment is atomic under the lock.

This is the *singular brain*: exactly one process may run a hub against a given
database (plan §3). The scheduler (Phase 2b) drives ``dispatch`` and consumes
the per-task status sinks; Phase 2a builds and tests the hub itself.
"""

from __future__ import annotations

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import TypeVar
from uuid import UUID, uuid4

from flamejob_api.agent import AgentTask, Assign, Cancel, ComputeKeyspace, ServerMsg
from flamejob_core import TaskState
from flamejob_core.runner import StatusUpdate

StatusSink = asyncio.Queue[StatusUpdate]
_T = TypeVar("_T")


def agent_eligible(
    agent_id: UUID, pinned_agent_id: UUID | None, allowed_agents: list[UUID] | None
) -> bool:
    """Eligibility under the chunk's pin + pool allow-set (pure)."""
    if pinned_agent_id is not None and pinned_agent_id != agent_id:
        return False
    if allowed_agents is None:
        return True
    return agent_id in allowed_agents


@dataclass
class _Conn:
    name: str
    queue: asyncio.Queue[ServerMsg]
    slots: int = 0
    max_slots: int = 0


@dataclass
class _QueuedTask:
    task: Assign  # carries the AgentTask (task.task)
    pinned_agent_id: UUID | None
    allowed_agents: list[UUID] | None


@dataclass
class AgentLive:
    busy: bool
    errored: bool


@dataclass
class _Inner:
    conns: dict[UUID, _Conn] = field(default_factory=dict)
    sinks: dict[UUID, StatusSink] = field(default_factory=dict)
    assigned: dict[UUID, UUID] = field(default_factory=dict)  # task_id -> agent_id
    queue: deque[_QueuedTask] = field(default_factory=deque)
    ks_waiters: dict[UUID, asyncio.Future[int]] = field(default_factory=dict)
    errored: set[UUID] = field(default_factory=set)


def _failed(task_id: UUID) -> StatusUpdate:
    return StatusUpdate(
        task_id=task_id, progress=0.0, speed=0, recovered=0, eta=None, state=TaskState.FAILED
    )


class AgentHub:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._g = _Inner()

    async def register(self, agent_id: UUID, name: str, queue: asyncio.Queue[ServerMsg]) -> None:
        async with self._lock:
            self._g.errored.discard(agent_id)
            self._g.conns[agent_id] = _Conn(name=name, queue=queue)

    async def disconnect(self, agent_id: UUID) -> None:
        async with self._lock:
            self._g.conns.pop(agent_id, None)
            self._g.errored.discard(agent_id)
            orphaned = [t for t, a in self._g.assigned.items() if a == agent_id]
            for task_id in orphaned:
                self._g.assigned.pop(task_id, None)
                sink = self._g.sinks.pop(task_id, None)
                if sink is not None:
                    _try_put(sink, _failed(task_id))

    async def set_ready(self, agent_id: UUID, slots: int) -> None:
        async with self._lock:
            self._g.errored.discard(agent_id)
            c = self._g.conns.get(agent_id)
            if c is not None:
                c.slots = slots
                c.max_slots = max(c.max_slots, slots)
            self._drain()

    async def mark_error(self, agent_id: UUID) -> None:
        async with self._lock:
            self._g.errored.add(agent_id)

    async def live(self) -> dict[UUID, AgentLive]:
        async with self._lock:
            return {
                aid: AgentLive(
                    busy=c.max_slots > 1 and c.slots == 0,
                    errored=aid in self._g.errored,
                )
                for aid, c in self._g.conns.items()
            }

    async def dispatch(
        self,
        assign: Assign,
        pinned_agent_id: UUID | None,
        allowed_agents: list[UUID] | None,
        sink: StatusSink,
    ) -> None:
        async with self._lock:
            self._g.sinks[assign.task.task_id] = sink
            self._g.queue.append(
                _QueuedTask(
                    task=assign,
                    pinned_agent_id=pinned_agent_id,
                    allowed_agents=allowed_agents,
                )
            )
            self._drain()

    def _drain(self) -> None:
        # Synchronous, lock-held; mirrors agent.rs fn drain. A pinned/pool task
        # that finds no free eligible agent stays queued while later tasks are
        # considered, rather than blocking the queue.
        i = 0
        q = self._g.queue
        while i < len(q):
            qt = q[i]
            agent_id = next(
                (
                    a
                    for a, c in self._g.conns.items()
                    if c.slots > 0
                    and agent_eligible(a, qt.pinned_agent_id, qt.allowed_agents)
                ),
                None,
            )
            if agent_id is None:
                i += 1
                continue
            del q[i]
            c = self._g.conns.get(agent_id)
            if c is None:
                continue
            c.slots -= 1
            try:
                c.queue.put_nowait(qt.task)
                self._g.assigned[qt.task.task.task_id] = agent_id
            except asyncio.QueueFull:
                c.slots += 1
                q.insert(i, qt)
                i += 1

    async def assignments(self) -> dict[UUID, str]:
        async with self._lock:
            out: dict[UUID, str] = {}
            for task_id, agent_id in self._g.assigned.items():
                c = self._g.conns.get(agent_id)
                if c is not None:
                    out[task_id] = c.name
            return out

    async def sink_for(self, task_id: UUID) -> StatusSink | None:
        async with self._lock:
            return self._g.sinks.get(task_id)

    async def finish_task(self, task_id: UUID) -> None:
        async with self._lock:
            self._g.sinks.pop(task_id, None)
            agent_id = self._g.assigned.pop(task_id, None)
            if agent_id is not None:
                c = self._g.conns.get(agent_id)
                if c is not None:
                    c.slots += 1
            self._drain()

    async def cancel_task(self, task_id: UUID) -> None:
        async with self._lock:
            agent_id = self._g.assigned.get(task_id)
            if agent_id is not None:
                c = self._g.conns.get(agent_id)
                if c is not None:
                    _try_put(c.queue, Cancel(task_id=task_id))

    async def keyspace_probe(self, task: AgentTask) -> asyncio.Future[int] | None:
        """Ask any free agent to compute a keyspace. None if none is free."""
        async with self._lock:
            agent_id = next((a for a, c in self._g.conns.items() if c.slots > 0), None)
            if agent_id is None:
                return None
            c = self._g.conns[agent_id]
            req_id = uuid4()
            fut: asyncio.Future[int] = asyncio.get_running_loop().create_future()
            try:
                c.queue.put_nowait(ComputeKeyspace(req_id=req_id, task=task))
            except asyncio.QueueFull:
                return None
            self._g.ks_waiters[req_id] = fut
            return fut

    async def fulfill_keyspace(self, req_id: UUID, value: int) -> None:
        async with self._lock:
            fut = self._g.ks_waiters.pop(req_id, None)
        if fut is not None and not fut.done():
            fut.set_result(value)

    async def connected_count(self) -> int:
        async with self._lock:
            return len(self._g.conns)

    async def capacity(self) -> int:
        async with self._lock:
            free = sum(c.slots for c in self._g.conns.values())
            return free + len(self._g.assigned)


def _try_put(q: asyncio.Queue[_T], item: _T) -> None:
    try:
        q.put_nowait(item)
    except asyncio.QueueFull:
        pass
