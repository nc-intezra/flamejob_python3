"""flamejob-core: pure domain model, state machines, and the Runner protocol."""

from __future__ import annotations

from .errors import FlamejobError, InvalidTransition, RunnerError
from .model import Capability, JobState, Role, TaskState, roles_have
from .runner import DeviceSpeed, RunHandle, Runner, RunnerTask, StatusUpdate

__all__ = [
    "Capability",
    "DeviceSpeed",
    "FlamejobError",
    "InvalidTransition",
    "JobState",
    "Role",
    "RunHandle",
    "Runner",
    "RunnerError",
    "RunnerTask",
    "StatusUpdate",
    "TaskState",
    "roles_have",
]
