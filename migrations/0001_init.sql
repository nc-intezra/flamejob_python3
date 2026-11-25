-- flamejob Phase 1 schema
CREATE TYPE job_state  AS ENUM ('queued','assigned','running','paused','completed','exhausted','cancelled','error');
CREATE TYPE task_state AS ENUM ('pending','running','paused','done','failed');
CREATE TYPE role       AS ENUM ('superadmin','admin','operator','viewer');
CREATE TYPE file_kind  AS ENUM ('wordlist','rule','mask','other');

CREATE TABLE users (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  username      text NOT NULL UNIQUE,
  source        text NOT NULL DEFAULT 'local',
  password_hash text,
  display_name  text,
  disabled      boolean NOT NULL DEFAULT false,
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_roles (
  user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role    role NOT NULL,
  PRIMARY KEY (user_id, role)
);

CREATE TABLE files (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  kind        file_kind NOT NULL,
  path        text NOT NULL,
  size_bytes  bigint NOT NULL,
  sha256      char(64) NOT NULL,
  uploaded_by uuid REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hashlists (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  hash_type   integer NOT NULL,
  created_by  uuid REFERENCES users(id),
  total       integer NOT NULL DEFAULT 0,
  cracked     integer NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE hashes (
  id          bigserial PRIMARY KEY,
  hashlist_id uuid NOT NULL REFERENCES hashlists(id) ON DELETE CASCADE,
  hash        text NOT NULL,
  salt        text,
  plain       bytea,
  cracked_at  timestamptz
);
CREATE INDEX ix_hashes_hashlist ON hashes(hashlist_id);

CREATE TABLE jobs (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name           text NOT NULL,
  owner_user_id  uuid NOT NULL REFERENCES users(id),
  hashlist_id    uuid NOT NULL REFERENCES hashlists(id),
  attack_mode    smallint NOT NULL,
  config         jsonb NOT NULL,
  priority       integer NOT NULL DEFAULT 100,
  state          job_state NOT NULL DEFAULT 'queued',
  est_completion timestamptz,
  error          text,
  created_at     timestamptz NOT NULL DEFAULT now(),
  started_at     timestamptz,
  finished_at    timestamptz
);
CREATE INDEX ix_jobs_queue ON jobs(state, priority, created_at);

CREATE TABLE tasks (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  job_id          uuid NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
  runner_id       text,
  keyspace_offset bigint NOT NULL DEFAULT 0,
  keyspace_len    bigint NOT NULL DEFAULT 0,
  state           task_state NOT NULL DEFAULT 'pending',
  progress        double precision NOT NULL DEFAULT 0,
  speed           bigint NOT NULL DEFAULT 0,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_tasks_job ON tasks(job_id);
CREATE INDEX ix_tasks_state ON tasks(state);

CREATE TABLE audit_events (
  id            bigserial PRIMARY KEY,
  ts            timestamptz NOT NULL DEFAULT now(),
  actor_user_id uuid REFERENCES users(id),
  action        text NOT NULL,
  target_type   text,
  target_id     text,
  client        text,
  source_ip     inet,
  outcome       text NOT NULL,
  detail        jsonb
);
CREATE INDEX ix_audit_ts ON audit_events(ts DESC);
CREATE INDEX ix_audit_actor ON audit_events(actor_user_id);
