"""Agent enrollment + WebSocket task protocol. Port of ``flamejob-api/src/agent.rs``.

The ``AgentMsg``/``ServerMsg`` Rust enums use ``#[serde(tag = "type",
rename_all = "snake_case")]``; they are modelled here as discriminated unions on
a ``type`` literal so the JSON frames are byte-compatible with the Rust agent.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field


# ---- enrollment (HTTP) ----
class AgentClaimCreate(BaseModel):
    name: str


class AgentClaim(BaseModel):
    claim_token: str
    name: str


class EnrollRequest(BaseModel):
    claim_token: str
    name: str
    csr_pem: str


class EnrollResponse(BaseModel):
    agent_id: UUID
    cert_pem: str
    ca_pem: str


class AgentInfo(BaseModel):
    id: UUID
    name: str
    status: str
    enrolled_at: datetime
    last_seen: datetime | None = None
    os: str | None = None


# ---- shared payloads ----
class AgentTask(BaseModel):
    task_id: UUID
    hash_type: int
    attack_mode: int
    hashes: list[str]
    mask: str | None = None
    wordlist: UUID | None = None
    rules: list[UUID] = Field(default_factory=list)
    keyspace_offset: int
    keyspace_len: int
    extra_args: list[str] = Field(default_factory=list)


class CrackedItem(BaseModel):
    hash: str
    plain: str


class AgentMetric(BaseModel):
    name: str
    kind: str
    temp: int
    util: int
    mem_used: int
    mem_total: int
    pstate: str
    power_w: int
    fan: int
    clock_mhz: int
    mem_clock_mhz: int
    hashrate: int


# ---- Agent -> Server ----
class Hello(BaseModel):
    type: Literal["hello"] = "hello"
    name: str
    cert_pem: str
    os: str = ""


class Ready(BaseModel):
    type: Literal["ready"] = "ready"
    slots: int


class Keyspace(BaseModel):
    type: Literal["keyspace"] = "keyspace"
    req_id: UUID
    value: int


class Progress(BaseModel):
    type: Literal["progress"] = "progress"
    task_id: UUID
    progress: float
    speed: int
    recovered: int
    state: str
    eta: datetime | None = None


class Cracked(BaseModel):
    type: Literal["cracked"] = "cracked"
    task_id: UUID
    items: list[CrackedItem]


class Metrics(BaseModel):
    type: Literal["metrics"] = "metrics"
    samples: list[AgentMetric]


class TaskDone(BaseModel):
    type: Literal["task_done"] = "task_done"
    task_id: UUID
    state: str


class AgentError(BaseModel):
    type: Literal["error"] = "error"
    task_id: UUID | None = None
    message: str


AgentMsg = Annotated[
    Hello | Ready | Keyspace | Progress | Cracked | Metrics | TaskDone | AgentError,
    Field(discriminator="type"),
]


# ---- Server -> Agent ----
class Welcome(BaseModel):
    type: Literal["welcome"] = "welcome"
    agent_id: UUID


class ComputeKeyspace(BaseModel):
    type: Literal["compute_keyspace"] = "compute_keyspace"
    req_id: UUID
    task: AgentTask


class Assign(BaseModel):
    type: Literal["assign"] = "assign"
    task: AgentTask


class Cancel(BaseModel):
    type: Literal["cancel"] = "cancel"
    task_id: UUID


class Heartbeat(BaseModel):
    type: Literal["heartbeat"] = "heartbeat"


class Rejected(BaseModel):
    type: Literal["rejected"] = "rejected"
    reason: str


ServerMsg = Annotated[
    Welcome | ComputeKeyspace | Assign | Cancel | Heartbeat | Rejected,
    Field(discriminator="type"),
]
