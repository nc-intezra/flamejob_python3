"""Serde-parity checks on the Pydantic DTOs."""

from __future__ import annotations

from uuid import UUID

from pydantic import TypeAdapter

from flamejob_api.agent import AgentMsg, AgentTask, Assign, Hello, Progress, ServerMsg
from flamejob_api.schemas import JobConfig, JobUpdated, LoginResponse
from flamejob_core import JobState, Role

_U = "11111111-2222-3333-4444-555555555555"


def test_role_serializes_lowercase() -> None:
    resp = LoginResponse(token="t", expires_at="2026-01-01T00:00:00Z", roles=[Role.SUPERADMIN])
    assert resp.model_dump(mode="json")["roles"] == ["superadmin"]


def test_jobconfig_defaults_match_serde() -> None:
    cfg = JobConfig()
    assert cfg.rule_file_ids == []
    assert cfg.extra_args == []
    assert cfg.wordlist_file_id is None


def test_agentmsg_discriminated_union() -> None:
    ta = TypeAdapter(AgentMsg)
    hello = ta.validate_python({"type": "hello", "name": "gpu01", "cert_pem": "PEM"})
    assert isinstance(hello, Hello)
    assert hello.os == ""  # serde default
    prog = ta.validate_python(
        {
            "type": "progress",
            "task_id": _U,
            "progress": 0.5,
            "speed": 100,
            "recovered": 2,
            "state": "running",
        }
    )
    assert isinstance(prog, Progress)
    assert prog.eta is None


def test_servermsg_nested_task() -> None:
    ta = TypeAdapter(ServerMsg)
    msg = ta.validate_python(
        {
            "type": "assign",
            "task": {
                "task_id": _U,
                "hash_type": 1000,
                "attack_mode": 0,
                "hashes": ["aad3b4..."],
                "keyspace_offset": 0,
                "keyspace_len": 1000,
            },
        }
    )
    assert isinstance(msg, Assign)
    assert isinstance(msg.task, AgentTask)
    assert msg.task.rules == []


def test_event_tag() -> None:
    ev = JobUpdated(job_id=UUID(_U), state=JobState.RUNNING)
    dumped = ev.model_dump(mode="json")
    assert dumped["type"] == "JobUpdated"
    assert dumped["state"] == "running"
