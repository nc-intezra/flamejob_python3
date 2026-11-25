"""Fairness selector tests — ports of the fairness.rs unit tests."""

from __future__ import annotations

import uuid

from flamejob_server.fairness import Candidate, Quota, select_job


def _u(n: int) -> uuid.UUID:
    return uuid.UUID(int=n)


def _cand(n: int, group: str, prio: int, created: int, inflight: int) -> Candidate:
    return Candidate(
        job_id=_u(n), group=group, priority=prio, created_at=created, in_flight_job=inflight
    )


def test_single_group_round_robins_across_jobs() -> None:
    cands = [_cand(1, "", 100, 10, 3), _cand(2, "", 100, 11, 1)]
    assert select_job(cands, {"": 4}, {}) == _u(2)


def test_favors_the_under_utilized_group() -> None:
    cands = [_cand(1, "A", 100, 10, 2), _cand(2, "B", 100, 10, 0)]
    assert select_job(cands, {"A": 4, "B": 1}, {}) == _u(2)


def test_weight_gives_proportional_share() -> None:
    cands = [_cand(1, "A", 100, 5, 2), _cand(2, "B", 100, 9, 1)]
    quotas = {"A": Quota(weight=200.0, floor=0, ceil=None), "B": Quota()}
    # At 2:1 the ratios tie; older A job wins → A allowed twice B's concurrency.
    assert select_job(cands, {"A": 2, "B": 1}, quotas) == _u(1)
    # Past its 2:1 share (3:1), B is more starved → B wins.
    assert select_job(cands, {"A": 3, "B": 1}, quotas) == _u(2)


def test_ceiling_excludes_a_group() -> None:
    cands = [_cand(1, "A", 100, 10, 0), _cand(2, "B", 100, 10, 5)]
    quotas = {"A": Quota(weight=100.0, floor=0, ceil=2)}
    assert select_job(cands, {"A": 2, "B": 5}, quotas) == _u(2)


def test_floor_is_serviced_before_weighted_share() -> None:
    cands = [_cand(1, "A", 100, 10, 0), _cand(2, "B", 100, 10, 1)]
    quotas = {"B": Quota(weight=100.0, floor=2, ceil=None)}
    assert select_job(cands, {"A": 0, "B": 1}, quotas) == _u(2)


def test_all_at_ceiling_returns_none() -> None:
    cands = [_cand(1, "A", 100, 10, 0)]
    quotas = {"A": Quota(weight=100.0, floor=0, ceil=3)}
    assert select_job(cands, {"A": 3}, quotas) is None
