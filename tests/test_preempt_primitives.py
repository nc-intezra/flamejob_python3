"""Phase 2d pure-helper unit tests — ports of the preempt.rs #[test] cases.

No database; the split/guard logic is exercised in isolation.
"""

from __future__ import annotations

from flamejob_server.preempt import (
    MIN_RUN_SECS,
    SHIELD_FRAC,
    is_preemptible,
    remaining_window,
)


def test_remaining_window_splits_at_progress_offset() -> None:
    # 50% through a 1000-wide chunk starting at 2000 → resume at 2500 for 500.
    assert remaining_window(2000, 1000, 0.5) == (2500, 500)
    # Barely started → almost the whole chunk remains.
    assert remaining_window(0, 100, 0.0) == (0, 100)
    # Essentially done → tiny/zero remainder.
    assert remaining_window(0, 100, 1.0) == (100, 0)
    # Clamps out-of-range progress.
    assert remaining_window(10, 40, 2.0) == (50, 0)
    # Unknown / full-run chunk (len 0) passes through unchanged.
    assert remaining_window(0, 0, 0.5) == (0, 0)


def test_preemptible_guards() -> None:
    # Healthy mid-run job: preemptible.
    assert is_preemptible(300, 0.4, MIN_RUN_SECS, SHIELD_FRAC)
    # Just started: shielded.
    assert not is_preemptible(10, 0.4, MIN_RUN_SECS, SHIELD_FRAC)
    # Near completion: shielded.
    assert not is_preemptible(300, 0.95, MIN_RUN_SECS, SHIELD_FRAC)
    # Exactly at the boundaries.
    assert is_preemptible(60, 0.0, MIN_RUN_SECS, SHIELD_FRAC)
    assert not is_preemptible(60, 0.90, MIN_RUN_SECS, SHIELD_FRAC)
