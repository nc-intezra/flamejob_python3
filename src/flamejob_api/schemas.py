"""The wire contract (DTOs). Port of ``flamejob-api/src/lib.rs``.

Field names, types, optionality and serde ``default`` semantics match the Rust
structs so request/response bodies interoperate with the Rust server during the
strangler. FastAPI generates the OpenAPI document from these (replacing utoipa),
so the schema is single-sourced here.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from flamejob_core import JobState, Role, TaskState


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    expires_at: datetime
    roles: list[Role]


class MeResponse(BaseModel):
    id: UUID
    username: str
    roles: list[Role]


class JobConfig(BaseModel):
    wordlist_file_id: UUID | None = None
    rule_file_ids: list[UUID] = Field(default_factory=list)
    mask: str | None = None
    # FJ-004: in the Rust server this reaches the hashcat argv verbatim. The port
    # replaces it with a server-validated allowlist in Phase 2 (plan §6); the
    # field is kept on the wire for compatibility but must not pass through raw.
    extra_args: list[str] = Field(default_factory=list)


class JobCreate(BaseModel):
    name: str
    hashlist_id: UUID
    attack_mode: int
    priority: int | None = None
    config: JobConfig


class PatchJob(BaseModel):
    priority: int


class PinRequest(BaseModel):
    agent_id: UUID


class JobView(BaseModel):
    id: UUID
    name: str
    hashlist_id: UUID
    state: JobState
    priority: int
    priority_override: int | None = None
    preempt_state: str | None = None
    created_at: datetime
    est_completion: datetime | None = None
    progress: float
    speed: int
    cracked: int
    total: int
    pinned_agent_id: UUID | None = None
    pinned_agent: str | None = None
    running_agents: list[str] = Field(default_factory=list)


class JobHistoryView(BaseModel):
    id: UUID
    name: str
    hashlist_id: UUID
    state: JobState
    cracked: int
    total: int
    created_at: datetime
    finished_at: datetime | None = None
    archived: bool


class TaskView(BaseModel):
    id: UUID
    job_id: UUID
    state: TaskState
    progress: float
    speed: int
    keyspace_offset: int
    keyspace_len: int
    eta: datetime | None = None


class HashlistCreate(BaseModel):
    name: str
    hash_type: int


class HashlistView(BaseModel):
    id: UUID
    name: str
    hash_type: int
    total: int
    cracked: int


class CrackedHash(BaseModel):
    hash: str
    salt: str | None = None
    plain: str


class FileView(BaseModel):
    id: UUID
    name: str
    kind: str
    size_bytes: int
    sha256: str


class StorageUsageView(BaseModel):
    files_bytes: int
    file_count: int
    quota_bytes: int
    disk_total_bytes: int
    disk_available_bytes: int
    path: str


class UserCreate(BaseModel):
    username: str
    password: str
    roles: list[Role]


class ClearedJobs(BaseModel):
    cleared: int


class SiteSettingsView(BaseModel):
    https_enabled: bool
    has_cert: bool
    has_key: bool
    https_listening: bool
    https_bind: str
    cert_fingerprint: str | None = None
    updated_at: datetime | None = None


class SiteSettingsUpdate(BaseModel):
    https_enabled: bool
    tls_cert_pem: str | None = None
    tls_key_pem: str | None = None


# ---- Directory (AD/LDAP) ----


class DirectoryConfigView(BaseModel):
    enabled: bool
    transport: str
    discovery: str
    domain: str | None = None
    servers: list[str]
    use_global_catalog: bool
    base_dn: str | None = None
    bind_dn: str | None = None
    has_bind_password: bool
    user_filter: str
    login_attributes: list[str]
    has_ca_bundle: bool
    verify_hostname: bool
    allow_insecure_tls: bool
    plaintext_ack: bool
    group_source: str
    cache_ttl_secs: int
    on_directory_down: str
    default_role: Role | None = None
    jwt_ttl_hours: int
    last_test_ok_at: datetime | None = None
    updated_at: datetime | None = None


class DirectoryConfigUpdate(BaseModel):
    transport: str
    discovery: str
    domain: str | None = None
    servers: list[str]
    use_global_catalog: bool
    base_dn: str | None = None
    bind_dn: str | None = None
    bind_password: str | None = None
    clear_bind_password: bool = False
    user_filter: str
    login_attributes: list[str]
    ca_bundle_pem: str | None = None
    verify_hostname: bool
    allow_insecure_tls: bool
    plaintext_ack: bool
    group_source: str
    cache_ttl_secs: int
    on_directory_down: str
    default_role: Role | None = None
    jwt_ttl_hours: int


class DirectoryTestRequest(BaseModel):
    sample_user: str | None = None


class DirectoryTestStep(BaseModel):
    name: str
    ok: bool
    detail: str


class DirectoryTestResult(BaseModel):
    ok: bool
    steps: list[DirectoryTestStep]


class DirectoryTestLoginRequest(BaseModel):
    username: str
    password: str


class DirectoryTestLoginResult(BaseModel):
    ok: bool
    detail: str
    dn: str | None = None
    sid: str | None = None
    group_sids: list[str]
    roles: list[Role]


class DirectoryRoleMapEntry(BaseModel):
    group_sid: str
    role: Role
    group_cn: str | None = None


class PoolView(BaseModel):
    id: UUID
    name: str
    agent_ids: list[UUID]
    created_at: datetime


class PoolCreate(BaseModel):
    name: str


class PoolMemberUpdate(BaseModel):
    agent_id: UUID


class DirectoryGrantEntry(BaseModel):
    group_sid: str
    pool_id: UUID
    pool_name: str | None = None
    group_cn: str | None = None


class PriorityOverrideRequest(BaseModel):
    priority_override: int | None = None
    reason: str | None = None


class PreemptRequest(BaseModel):
    mode: str
    target_pool_id: UUID | None = None
    reason: str | None = None
    force: bool = False


class GroupQuotaEntry(BaseModel):
    group_sid: str
    weight: int
    floor_slots: int
    ceil_slots: int | None = None
    max_submit_jobs: int | None = None
    group_cn: str | None = None


class Problem(BaseModel):
    """RFC 7807 problem+json error body."""

    model_config = ConfigDict(populate_by_name=True)

    type_uri: str = Field(
        default="about:blank", serialization_alias="type", validation_alias="type"
    )
    title: str
    status: int
    detail: str | None = None


class DeviceView(BaseModel):
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


class DeviceSample(BaseModel):
    ts: datetime
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


class ApiKeyCreate(BaseModel):
    name: str
    expires_in_days: int | None = None


class ApiKeyView(BaseModel):
    id: UUID
    name: str
    prefix: str
    created_at: datetime
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    revoked: bool


class ApiKeyCreated(BaseModel):
    id: UUID
    name: str
    prefix: str
    key: str
    expires_at: datetime | None = None


# ---- Server-sent events (GET /events), serde tag = "type" ----


class JobUpdated(BaseModel):
    type: Literal["JobUpdated"] = "JobUpdated"
    job_id: UUID
    state: JobState


class TaskUpdated(BaseModel):
    type: Literal["TaskUpdated"] = "TaskUpdated"
    job_id: UUID
    task_id: UUID
    progress: float
    speed: int
    eta: datetime | None = None


class HashCracked(BaseModel):
    type: Literal["HashCracked"] = "HashCracked"
    hashlist_id: UUID
    hash: str


Event = JobUpdated | TaskUpdated | HashCracked
