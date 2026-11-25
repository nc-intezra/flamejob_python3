"""RBAC + job state-machine parity with the Rust model.rs tests.

Direct ports of ``rbac_matches_spec`` and ``job_transitions`` — two of the 60
Rust unit tests, carried over as the regression oracle for the port.
"""

from __future__ import annotations

from flamejob_core import Capability as C
from flamejob_core import JobState as J
from flamejob_core import Role, roles_have


def test_rbac_matches_spec() -> None:
    assert Role.OPERATOR.has(C.SUBMIT_JOBS)
    assert not Role.ADMIN.has(C.SUBMIT_JOBS)
    assert Role.ADMIN.has(C.MANAGE_USERS)
    assert Role.ADMIN.has(C.VIEW_JOBS)
    assert not Role.ADMIN.has(C.SUBMIT_JOBS)
    assert not Role.VIEWER.has(C.SUBMIT_JOBS)
    assert Role.VIEWER.has(C.VIEW_JOBS)
    assert Role.SUPERADMIN.has(C.MANAGE_DIRECTORY)
    assert Role.SUPERADMIN.has(C.VIEW_DIRECTORY_CONFIG)
    assert Role.ADMIN.has(C.VIEW_DIRECTORY_CONFIG)
    assert not Role.ADMIN.has(C.MANAGE_DIRECTORY)
    assert not Role.OPERATOR.has(C.VIEW_DIRECTORY_CONFIG)
    assert Role.SUPERADMIN.has(C.MANAGE_SCHEDULING)
    assert Role.ADMIN.has(C.MANAGE_SCHEDULING)
    assert not Role.OPERATOR.has(C.MANAGE_SCHEDULING)
    assert not Role.VIEWER.has(C.MANAGE_SCHEDULING)
    assert Role.SUPERADMIN.has(C.MANAGE_AGENTS)
    assert Role.ADMIN.has(C.MANAGE_AGENTS)
    assert not Role.OPERATOR.has(C.MANAGE_AGENTS)
    assert Role.SUPERADMIN.has(C.MANAGE_SETTINGS)
    assert Role.ADMIN.has(C.MANAGE_SETTINGS)
    assert not Role.OPERATOR.has(C.MANAGE_SETTINGS)
    assert not Role.VIEWER.has(C.MANAGE_SETTINGS)
    assert Role.SUPERADMIN.has(C.INGEST)
    assert Role.OPERATOR.has(C.INGEST)
    assert Role.ADMIN.has(C.INGEST)
    assert not Role.VIEWER.has(C.INGEST)


def test_roles_have_union() -> None:
    assert roles_have([Role.VIEWER, Role.OPERATOR], C.SUBMIT_JOBS)
    assert not roles_have([Role.VIEWER], C.SUBMIT_JOBS)


def test_job_transitions() -> None:
    assert J.QUEUED.can_transition(J.ASSIGNED)
    assert J.RUNNING.can_transition(J.COMPLETED)
    assert not J.COMPLETED.can_transition(J.RUNNING)
    assert J.COMPLETED.is_terminal()
    assert not J.RUNNING.is_terminal()
