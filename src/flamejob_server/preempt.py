"""Preemption + priority-override pure helpers. Port of the testable core of
``preempt.rs``.

The HTTP handlers live in ``routes_preempt`` and the scheduler-side resume +
keyspace handoff in ``scheduler``; both import :func:`remaining_window` /
:func:`is_preemptible` from here so the split/guard logic has one home and is
unit-tested in isolation.
"""

from __future__ import annotations

import math

# A running job is not preemptible if it only just started (not worth a
# checkpoint + re-dispatch) or is near completion (finishing frees the GPU sooner
# than evicting it). ``force`` bypasses both.
MIN_RUN_SECS = 60
SHIELD_FRAC = 0.90


def remaining_window(offset: int, length: int, progress: float) -> tuple[int, int]:
    """The unfinished keyspace window of a chunk given its last progress — the
    basis of the cross-agent/pool handoff (resume from the durable offset via
    hashcat ``--skip``/``--limit``, never a host-bound ``.restore`` file).

    ``length <= 0`` (unknown / full-run chunk) passes through unchanged.
    """
    if length <= 0:
        return offset, length
    clamped = min(max(progress, 0.0), 1.0)
    consumed = min(max(math.floor(length * clamped), 0), length)
    return offset + consumed, length - consumed


def is_preemptible(
    run_secs: int, overall_progress: float, min_run_secs: int, shield_frac: float
) -> bool:
    """Whether a running job may be preempted under the guards."""
    return run_secs >= min_run_secs and overall_progress < shield_frac
