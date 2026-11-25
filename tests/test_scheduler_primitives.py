"""Scheduler primitive tests — ports of the scheduler.rs pure-helper tests."""

from __future__ import annotations

from flamejob_server.scheduler import plan_chunks, project_eta


def test_chunking_splits_keyspace() -> None:
    assert plan_chunks(40, 15, 500) == [(0, 15), (15, 15), (30, 10)]
    assert plan_chunks(0, 15, 500) == [(0, 0)]  # unknown keyspace → one chunk
    assert plan_chunks(10, 15, 500) == [(0, 10)]  # smaller than chunk size
    # max_chunks cap widens the chunk size.
    c = plan_chunks(1000, 1, 4)
    assert len(c) <= 4
    assert sum(length for _, length in c) == 1000


def test_eta_projects_from_observed_rate() -> None:
    # No prior rate: first real sample (10% over 10s) → ~1%/s, ~90s left.
    rate, remaining = project_eta(0.0, 0.0, 0.10, 10.0)
    assert abs(rate - 0.01) < 1e-9
    assert remaining is not None and abs(remaining - 90.0) < 1e-6

    # A sub-threshold gap keeps the previous rate and still projects.
    rate2, remaining2 = project_eta(0.10, 0.01, 0.1001, 0.1)
    assert abs(rate2 - 0.01) < 1e-9
    assert remaining2 is not None and remaining2 > 0.0

    # No progress yet (rate stays 0) → no estimate.
    assert project_eta(0.0, 0.0, 0.0, 5.0)[1] is None
