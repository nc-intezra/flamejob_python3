"""AgentHub unit tests — ports of the agent.rs hub tests (pure asyncio, no I/O)."""

from __future__ import annotations

import asyncio
import uuid

from flamejob_api.agent import AgentTask, Assign
from flamejob_core import TaskState
from flamejob_server.hub import AgentHub
from flamejob_server.routes_agent import _parse_task_state


def _task() -> AgentTask:
    return AgentTask(
        task_id=uuid.uuid4(),
        hash_type=0,
        attack_mode=3,
        hashes=[],
        mask="?d?d",
        keyspace_offset=0,
        keyspace_len=0,
    )


def _assign() -> Assign:
    return Assign(task=_task())


def test_parse_task_state() -> None:
    assert _parse_task_state("done") == TaskState.DONE
    assert _parse_task_state("failed") == TaskState.FAILED
    assert _parse_task_state("running") == TaskState.RUNNING
    assert _parse_task_state("anything") == TaskState.RUNNING  # unknown → Running


async def test_hub_queues_without_agents() -> None:
    hub = AgentHub()
    assert await hub.connected_count() == 0
    # No agents: a keyspace probe returns None rather than blocking.
    assert await hub.keyspace_probe(_task()) is None


async def test_capacity_tracks_fleet_slots() -> None:
    hub = AgentHub()
    a = uuid.uuid4()
    await hub.register(a, "gpu-1", asyncio.Queue())
    assert await hub.capacity() == 0  # connected, no slots advertised yet
    await hub.set_ready(a, 3)
    assert await hub.capacity() == 3
    # Dispatching a chunk moves one slot free → assigned; total holds at 3.
    await hub.dispatch(_assign(), None, None, asyncio.Queue())
    assert await hub.capacity() == 3


async def test_pinned_task_only_runs_on_its_agent() -> None:
    hub = AgentHub()
    a1, a2 = uuid.uuid4(), uuid.uuid4()
    q1: asyncio.Queue = asyncio.Queue()
    q2: asyncio.Queue = asyncio.Queue()
    await hub.register(a1, "gpu-1", q1)
    await hub.register(a2, "gpu-2", q2)
    await hub.set_ready(a1, 1)  # only a1 has a free slot

    pinned = _assign()
    pid = pinned.task.task_id
    await hub.dispatch(pinned, a2, None, asyncio.Queue())  # pinned to the full agent
    assert q1.empty(), "pinned task must not land on the wrong agent"
    assert "gpu-1" not in (await hub.assignments()).values()

    await hub.set_ready(a2, 1)  # a2 frees a slot → pinned task placed on a2
    msg = q2.get_nowait()
    assert isinstance(msg, Assign) and msg.task.task_id == pid
    assert (await hub.assignments()).get(pid) == "gpu-2"


async def test_agent_live_status_online_busy_error() -> None:
    hub = AgentHub()
    a = uuid.uuid4()
    await hub.register(a, "gpu-1", asyncio.Queue())
    await hub.set_ready(a, 2)  # multi-slot, both free
    live = await hub.live()
    assert not live[a].busy and not live[a].errored

    for _ in range(2):
        await hub.dispatch(_assign(), None, None, asyncio.Queue())
    assert (await hub.live())[a].busy  # fully loaded multi-slot → busy

    await hub.mark_error(a)
    assert (await hub.live())[a].errored
    await hub.set_ready(a, 1)  # a fresh Ready clears the error
    assert not (await hub.live())[a].errored


async def test_pool_restricted_task_only_runs_on_allowed_agent() -> None:
    hub = AgentHub()
    a1, a2 = uuid.uuid4(), uuid.uuid4()
    q1: asyncio.Queue = asyncio.Queue()
    q2: asyncio.Queue = asyncio.Queue()
    await hub.register(a1, "gpu-1", q1)
    await hub.register(a2, "gpu-2", q2)
    await hub.set_ready(a1, 1)
    await hub.set_ready(a2, 1)  # both free, but pool allows only a2

    t = _assign()
    tid = t.task.task_id
    await hub.dispatch(t, None, [a2], asyncio.Queue())
    assert q1.empty(), "pool-restricted task must not land on a non-allowed agent"
    msg = q2.get_nowait()
    assert isinstance(msg, Assign) and msg.task.task_id == tid
