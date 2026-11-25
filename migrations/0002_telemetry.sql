-- Phase 2 telemetry: historical metric samples plus a current-devices snapshot.

-- Append-only history of every GPU/host sample taken while the collector runs.
CREATE TABLE metric_samples (
  id            bigserial PRIMARY KEY,
  ts            timestamptz NOT NULL DEFAULT now(),
  name          text NOT NULL,
  kind          text NOT NULL,          -- 'gpu' | 'cpu'
  temp          integer,
  util          integer,                -- percent
  mem_used      bigint,                 -- MiB
  mem_total     bigint,                 -- MiB
  pstate        text,
  power_w       integer,
  fan           integer,                -- percent
  clock_mhz     integer,                -- core/graphics clock
  mem_clock_mhz integer,                -- memory clock
  hashrate      bigint
);
CREATE INDEX ix_metric_samples_ts ON metric_samples(ts DESC);
CREATE INDEX ix_metric_samples_name_ts ON metric_samples(name, ts DESC);

-- Latest sample per device, upserted each collection cycle. Lets GET /devices
-- survive a restart before the next sample lands.
CREATE TABLE current_devices (
  name          text PRIMARY KEY,
  kind          text NOT NULL,
  temp          integer,
  util          integer,
  mem_used      bigint,
  mem_total     bigint,
  pstate        text,
  power_w       integer,
  fan           integer,
  clock_mhz     integer,
  mem_clock_mhz integer,
  hashrate      bigint,
  updated_at    timestamptz NOT NULL DEFAULT now()
);
