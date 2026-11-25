-- flamejob v2.0 Phase 5 — per-group fair-share weights and quotas (PR3).
--
-- Fairness/quota policy keyed on the owning directory group (`jobs.owner_group_sid`,
-- set in PR2). Rows are optional: a group with no row uses the defaults
-- (weight 100, no floor, no ceiling, no submit cap). Design:
-- `claude/ad-ldap-integration-design.md` §5.
--
--   weight          relative share of contested capacity (max-min fair; higher
--                   weight ⇒ proportionally more concurrent chunks).
--   floor_slots     guaranteed concurrent chunks (serviced before weighted share).
--   ceil_slots      burst ceiling on concurrent chunks (NULL = uncapped).
--   max_submit_jobs backpressure: max queued+running jobs for the group
--                   (NULL = unlimited), enforced at submit.
CREATE TABLE group_quota (
  group_sid        text PRIMARY KEY,
  weight           integer NOT NULL DEFAULT 100 CHECK (weight > 0),
  floor_slots      integer NOT NULL DEFAULT 0   CHECK (floor_slots >= 0),
  ceil_slots       integer CHECK (ceil_slots IS NULL OR ceil_slots >= 0),
  max_submit_jobs  integer CHECK (max_submit_jobs IS NULL OR max_submit_jobs >= 0),
  group_cn         text,
  updated_by       uuid REFERENCES users(id),
  updated_at       timestamptz NOT NULL DEFAULT now()
);
