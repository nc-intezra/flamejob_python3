-- v1.3.3: pin a job to a specific agent. When set, the scheduler assigns the
-- job's chunks only to this agent. NULL = run on any available agent (default).
-- ON DELETE SET NULL so de-enrolling an agent simply unpins its jobs.
ALTER TABLE jobs
  ADD COLUMN pinned_agent_id uuid REFERENCES agents(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS jobs_pinned_agent_id_idx ON jobs (pinned_agent_id);
