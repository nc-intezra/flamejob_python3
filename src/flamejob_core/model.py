"""Pure domain model, RBAC, and state machines.

Faithful port of ``crates/flamejob-core/src/model.rs``. Enum *values* are the
exact serde wire strings the Rust server emits (Role: lowercase; Capability:
snake_case; JobState/TaskState: lowercase), so tokens, DB enum text, and JSON
bodies interoperate with the Rust server unchanged.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    SUPERADMIN = "superadmin"
    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"

    @property
    def capabilities(self) -> tuple[Capability, ...]:
        return _ROLE_CAPS[self]

    def has(self, cap: Capability) -> bool:
        return cap in _ROLE_CAPS[self]


class Capability(str, Enum):
    MANAGE_USERS = "manage_users"
    SUBMIT_JOBS = "submit_jobs"
    INGEST = "ingest"
    VIEW_PLAINTEXT = "view_plaintext"
    VIEW_STATS = "view_stats"
    VIEW_JOBS = "view_jobs"
    MANAGE_DIRECTORY = "manage_directory"
    VIEW_DIRECTORY_CONFIG = "view_directory_config"
    MANAGE_AGENTS = "manage_agents"
    MANAGE_SETTINGS = "manage_settings"
    MANAGE_SCHEDULING = "manage_scheduling"


_C = Capability
# Mirrors Role::capabilities() in model.rs exactly. This is the single source of
# truth; the dashboard's ROLE_CAPS must be derived from it (served via an API
# endpoint in Phase 1) rather than hand-mirrored — see the port plan §7.
_ROLE_CAPS: dict[Role, tuple[Capability, ...]] = {
    Role.SUPERADMIN: (
        _C.MANAGE_USERS,
        _C.SUBMIT_JOBS,
        _C.INGEST,
        _C.VIEW_PLAINTEXT,
        _C.VIEW_STATS,
        _C.VIEW_JOBS,
        _C.MANAGE_DIRECTORY,
        _C.VIEW_DIRECTORY_CONFIG,
        _C.MANAGE_AGENTS,
        _C.MANAGE_SETTINGS,
        _C.MANAGE_SCHEDULING,
    ),
    Role.ADMIN: (
        _C.MANAGE_USERS,
        _C.MANAGE_AGENTS,
        _C.VIEW_JOBS,
        _C.MANAGE_SETTINGS,
        _C.INGEST,
        _C.VIEW_DIRECTORY_CONFIG,
        _C.MANAGE_SCHEDULING,
    ),
    Role.OPERATOR: (
        _C.SUBMIT_JOBS,
        _C.INGEST,
        _C.VIEW_PLAINTEXT,
        _C.VIEW_STATS,
        _C.VIEW_JOBS,
    ),
    Role.VIEWER: (_C.VIEW_STATS, _C.VIEW_JOBS),
}


def roles_have(roles: list[Role], cap: Capability) -> bool:
    """True if any of the roles grants the capability (any-of union)."""
    return any(r.has(cap) for r in roles)


class JobState(str, Enum):
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    EXHAUSTED = "exhausted"
    CANCELLED = "cancelled"
    ERROR = "error"

    def can_transition(self, to: JobState) -> bool:
        return (self, to) in _LEGAL_TRANSITIONS

    def is_terminal(self) -> bool:
        return self in _TERMINAL_STATES


_LEGAL_TRANSITIONS: frozenset[tuple[JobState, JobState]] = frozenset(
    {
        (JobState.QUEUED, JobState.ASSIGNED),
        (JobState.QUEUED, JobState.CANCELLED),
        (JobState.ASSIGNED, JobState.RUNNING),
        (JobState.ASSIGNED, JobState.QUEUED),
        (JobState.ASSIGNED, JobState.CANCELLED),
        (JobState.RUNNING, JobState.PAUSED),
        (JobState.RUNNING, JobState.COMPLETED),
        (JobState.RUNNING, JobState.EXHAUSTED),
        (JobState.RUNNING, JobState.ERROR),
        (JobState.RUNNING, JobState.CANCELLED),
        (JobState.PAUSED, JobState.RUNNING),
        (JobState.PAUSED, JobState.CANCELLED),
    }
)

_TERMINAL_STATES: frozenset[JobState] = frozenset(
    {JobState.COMPLETED, JobState.EXHAUSTED, JobState.CANCELLED, JobState.ERROR}
)


class TaskState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    DONE = "done"
    FAILED = "failed"
