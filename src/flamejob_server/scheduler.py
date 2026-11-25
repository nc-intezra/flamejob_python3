"""Scheduler primitives. Port of the pure parts of ``scheduler.rs``.

Phase 2b-1 lands the pure, unit-tested helpers: keyspace chunk planning and the
EMA ETA projector. The stateful ``Scheduler`` class — the tick loop,
``fill_fleet``/``claim_and_start``/``consume`` that drive the hub and transition
job/task state — is Phase 2b-2 and will extend this module.
"""

from __future__ import annotations

import math

# EMA weight for a fresh rate sample (vs. the retained smoothed rate).
ETA_EMA_ALPHA = 0.4
# Minimum elapsed time between rate samples; shorter gaps are too noisy.
ETA_MIN_DT_SECS = 0.75
# A gap longer than this (seconds) is a discontinuity (pause/resume, restart).
ETA_RESET_SECS = 20


def plan_chunks(total: int, chunk_size: int, max_chunks: int) -> list[tuple[int, int]]:
    """Split ``total`` keyspace into (offset, len) chunks.

    ``total <= 0`` (unknown) yields a single full-run chunk (len 0 → no
    ``--skip``/``--limit``). The ``max_chunks`` cap widens the chunk size.
    """
    if total <= 0 or chunk_size <= 0:
        return [(0, 0)]
    size = chunk_size
    count = (total + size - 1) // size
    if count > max_chunks:
        size = (total + max_chunks - 1) // max_chunks
    chunks: list[tuple[int, int]] = []
    off = 0
    while off < total:
        length = min(size, total - off)
        chunks.append((off, length))
        off += length
    return chunks


def project_eta(
    prev_progress: float, prev_rate: float, overall: float, dt_secs: float
) -> tuple[float, float | None]:
    """Update the smoothed completion rate from a new progress observation.

    Returns (new_rate, remaining_secs); ``rate`` is progress fraction per second.
    A sub-threshold ``dt_secs`` retains the previous rate. Pure.
    """
    rate = prev_rate
    if dt_secs >= ETA_MIN_DT_SECS:
        inst = (overall - prev_progress) / dt_secs
        if inst > 0.0:
            if prev_rate > 0.0:
                rate = ETA_EMA_ALPHA * inst + (1.0 - ETA_EMA_ALPHA) * prev_rate
            else:
                rate = inst
    remaining: float | None = None
    if rate > 0.0 and overall < 1.0:
        r = (1.0 - overall) / rate
        if math.isfinite(r):
            remaining = r
    return rate, remaining
