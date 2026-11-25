"""Runner work unit + status types. Port of ``flamejob-core/src/runner.rs``.

The ``Runner`` trait itself (keyspace/start/pause/resume/cancel/capacity) is an
async Protocol here; the Local/Remote implementations land in Phase 2/4.
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, Field

from .model import TaskState


class RunnerTask(BaseModel):
    task_id: UUID
    hash_type: int
    attack_mode: int
    hash_file: str
    primary: str  # wordlist path or mask, depending on attack mode
    rules: list[str] = Field(default_factory=list)
    keyspace_offset: int
    keyspace_len: int
    extra_args: list[str] = Field(default_factory=list)
    pinned_agent_id: UUID | None = None
    # None = unrestricted; otherwise the chunk may only run on an agent whose id
    # is in this set (pool eligibility). Intersected with pinned_agent_id.
    allowed_agents: list[UUID] | None = None


class DeviceSpeed(BaseModel):
    device_id: int
    speed: int


class StatusUpdate(BaseModel):
    task_id: UUID
    progress: float
    speed: int
    recovered: int
    eta: datetime | None = None
    state: TaskState
    device_speeds: list[DeviceSpeed] = Field(default_factory=list)


class RunHandle(BaseModel):
    task_id: UUID


class Runner(Protocol):
    async def keyspace(self, task: RunnerTask) -> int: ...
    async def start(self, task: RunnerTask) -> RunHandle: ...
    async def pause(self, handle: RunHandle) -> None: ...
    async def resume(self, handle: RunHandle) -> None: ...
    async def cancel(self, handle: RunHandle) -> None: ...
    async def capacity(self) -> int: ...
