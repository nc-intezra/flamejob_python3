"""Telemetry write path. Port of ``telemetry.rs::persist``.

Appends each device sample to ``metric_samples`` and upserts the
``current_devices`` snapshot (the dominant steady-state DB write — one upsert
per device every ~5 s). Failures are swallowed so collection never stalls.
"""

from __future__ import annotations

import asyncpg

from flamejob_api.schemas import DeviceView

_INSERT_SAMPLE = (
    "INSERT INTO metric_samples "
    "(name, kind, temp, util, mem_used, mem_total, pstate, power_w, fan, "
    "clock_mhz, mem_clock_mhz, hashrate) "
    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"
)

_UPSERT_CURRENT = (
    "INSERT INTO current_devices "
    "(name, kind, temp, util, mem_used, mem_total, pstate, power_w, fan, "
    "clock_mhz, mem_clock_mhz, hashrate, updated_at) "
    "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12, now()) "
    "ON CONFLICT (name) DO UPDATE SET "
    "kind=EXCLUDED.kind, temp=EXCLUDED.temp, util=EXCLUDED.util, "
    "mem_used=EXCLUDED.mem_used, mem_total=EXCLUDED.mem_total, pstate=EXCLUDED.pstate, "
    "power_w=EXCLUDED.power_w, fan=EXCLUDED.fan, clock_mhz=EXCLUDED.clock_mhz, "
    "mem_clock_mhz=EXCLUDED.mem_clock_mhz, hashrate=EXCLUDED.hashrate, updated_at=now()"
)


async def record(pool: asyncpg.Pool, devices: list[DeviceView]) -> None:
    async with pool.acquire() as conn:
        for d in devices:
            args = (
                d.name, d.kind, d.temp, d.util, d.mem_used, d.mem_total, d.pstate,
                d.power_w, d.fan, d.clock_mhz, d.mem_clock_mhz, d.hashrate,
            )
            try:
                await conn.execute(_INSERT_SAMPLE, *args)
                await conn.execute(_UPSERT_CURRENT, *args)
            except asyncpg.PostgresError:
                continue
