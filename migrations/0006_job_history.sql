-- flamejob: durable record of finished jobs.
--
-- Cracked plaintext lives in `hashes` (keyed by hashlist, ON DELETE CASCADE from
-- `hashlists`), and `jobs.hashlist_id` has NO cascade, so clearing a job already
-- leaves the hashlist + cracked rows intact. What it does NOT leave is any way to
-- find them: the only UI path to `/hashlists/{id}/cracked` was through the live
-- job row. Once a superadmin runs "Clear finished", the job vanishes and the
-- cracked evidence becomes unreachable.
--
-- `job_history` keeps a lightweight, durable pointer to every finished job that is
-- cleared, so the dashboard's "Completed" tab can still list it and re-open its
-- cracked hashes via the preserved `hashlist_id`. It is NOT deleted when a job is
-- cleared; it is only removed if the underlying hashlist itself is deleted (at
-- which point the cracked rows are gone too — nothing left to point at).
CREATE TABLE job_history (
  id             uuid PRIMARY KEY,                 -- the original jobs.id
  name           text NOT NULL,
  hashlist_id    uuid NOT NULL REFERENCES hashlists(id) ON DELETE CASCADE,
  owner_user_id  uuid REFERENCES users(id),
  attack_mode    smallint NOT NULL,
  state          job_state NOT NULL,               -- terminal state at archive time
  created_at     timestamptz NOT NULL,
  finished_at    timestamptz,
  archived_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_job_history_archived ON job_history(archived_at DESC);
CREATE INDEX ix_job_history_hashlist ON job_history(hashlist_id);
