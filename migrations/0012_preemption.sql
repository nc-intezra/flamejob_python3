-- flamejob v2.0 Phase 5 — preemption + priority override (PR4).
--
-- The 3-piece design from the Slurm research §"Design note: preemption and
-- priority-override": (1) a priority-override lever (jump the queue), audited;
-- (2) operator-triggered eviction of a running job (requeue or cancel); (3)
-- keyspace handoff — a requeued job's unfinished chunks re-dispatch (optionally
-- to a slower pool) from their durable keyspace offset, which only flamejob can
-- do because it owns the keyspace (Slurm restarts the whole job).
--
-- Preemption is modeled with columns (not new job_state enum values): a requeued
-- job rides the existing paused→running machinery while `preempt_state` carries
-- the intent, so the scheduler's resume path can perform the handoff.

ALTER TABLE jobs
  -- One-off queue bump (= Slurm `scontrol top`). Effective scheduling priority is
  -- COALESCE(priority_override, priority); lower number = higher priority.
  ADD COLUMN priority_override  integer,
  -- NULL | 'requeued' (evicted, will resume) | 'cancelled' (evicted, terminal).
  ADD COLUMN preempt_state      text,
  ADD COLUMN preempted_at       timestamptz,
  -- The higher-priority job this one was evicted for (audit / causality).
  ADD COLUMN preempted_by_job_id uuid REFERENCES jobs(id) ON DELETE SET NULL,
  ADD COLUMN preempt_reason     text,
  -- A requeued job becomes eligible to resume at/after this time.
  ADD COLUMN resume_after       timestamptz;
