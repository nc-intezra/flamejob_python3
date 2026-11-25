"""Unit tests for the M1 read-shadow diff logic (no live servers)."""

from __future__ import annotations

from flamejob_server.shadowdiff import compare, normalize


def test_identical_is_clean() -> None:
    a = [{"id": "1", "state": "running", "speed": 500}]
    b = [{"id": "1", "state": "running", "speed": 500}]
    assert compare("/jobs", a, b) == []


def test_volatile_running_agents_normalised() -> None:
    # remote-mode running_agents differs but is normalised away for /jobs.
    a = [{"id": "1", "running_agents": ["gpu01"]}]
    b = [{"id": "1", "running_agents": []}]
    assert compare("/jobs", a, b) == []


def test_volatile_disk_available_normalised() -> None:
    a = {"files_bytes": 10, "disk_available_bytes": 111}
    b = {"files_bytes": 10, "disk_available_bytes": 222}
    assert compare("/files/usage", a, b) == []


def test_real_difference_reported() -> None:
    a = [{"id": "1", "cracked": 3}]
    b = [{"id": "1", "cracked": 4}]
    diffs = compare("/jobs", a, b)
    assert any("cracked" in d for d in diffs)


def test_length_mismatch_reported() -> None:
    diffs = compare("/hashlists", [{"id": "1"}], [{"id": "1"}, {"id": "2"}])
    assert any("length" in d for d in diffs)


def test_normalize_does_not_touch_unlisted_paths() -> None:
    obj = {"running_agents": ["x"]}
    # /devices has no volatile config → running_agents stays.
    assert normalize("/devices", dict(obj)) == obj
