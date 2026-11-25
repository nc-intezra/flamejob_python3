"""Weighted fair-share selection of the next chunk to dispatch.

Pure port of ``fairness.rs``. The scheduler supplies live in-flight counts and
quotas; this decides *whose* chunk fills the next free slot:

- a group at its ``ceil`` is skipped;
- a group under its ``floor`` is serviced before any weighted sharing;
- otherwise the group with the smallest ``in_flight / weight`` wins (weighted
  max-min; idle groups' slots flow to demanding ones), tie-broken by
  oldest-waiting then group name;
- within the group, the job with the fewest in-flight chunks (round-robin),
  then priority, then age.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class Quota:
    weight: float = 100.0
    floor: int = 0
    ceil: int | None = None


@dataclass(frozen=True)
class Candidate:
    job_id: UUID
    group: str  # owning group SID, or "" for ungrouped (local / no-pool)
    priority: int
    created_at: int  # unix seconds; older (smaller) wins ties
    in_flight_job: int


_DEFAULT = Quota()


def select_job(
    cands: list[Candidate],
    group_inflight: dict[str, int],
    quotas: dict[str, Quota],
) -> UUID | None:
    """Next job to dispatch a chunk from; None only when every group is at ceiling."""
    if not cands:
        return None

    def q(g: str) -> Quota:
        return quotas.get(g, _DEFAULT)

    def gif(g: str) -> int:
        return group_inflight.get(g, 0)

    # Distinct candidate groups under their ceiling, in first-seen order.
    groups: list[str] = []
    for c in cands:
        g = c.group
        if g not in groups and (q(g).ceil is None or gif(g) < q(g).ceil):  # type: ignore[operator]
            groups.append(g)
    if not groups:
        return None

    # Under-floor groups take precedence over weighted sharing.
    under = [g for g in groups if gif(g) < q(g).floor]
    pool = under if under else groups

    def oldest(g: str) -> int:
        ages = [c.created_at for c in cands if c.group == g]
        return min(ages) if ages else 2**63 - 1

    def group_key(g: str) -> tuple[float, int, str]:
        ratio = gif(g) / max(q(g).weight, 1.0)
        return (ratio, oldest(g), g)

    chosen = min(pool, key=group_key)

    def job_key(c: Candidate) -> tuple[int, int, int]:
        return (c.in_flight_job, c.priority, c.created_at)

    in_group = [c for c in cands if c.group == chosen]
    return min(in_group, key=job_key).job_id
