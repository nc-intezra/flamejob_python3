-- flamejob v2.0 Phase 5 — agent pools, directory->pool grants, pool-aware jobs.
--
-- Builds on 0009 (directory auth). A "pool" is a named set of agents; a security
-- group is granted a pool; a job's eligible agents are the members of the pools
-- its owner's groups are granted. Enforced server-side in the scheduler from the
-- owner's *verified* group SIDs — never from a client-supplied field.
-- Design: `claude/ad-ldap-integration-design.md` §4.
--
-- Backward-compatible: with NO pools defined, enforcement is OFF (jobs run on any
-- agent, as today). A job's `eligible_pool_ids` empty = unrestricted; non-empty =
-- restricted to those pools' members. Local (non-directory) users are
-- unrestricted; a directory user with groups but no granted pool is rejected at
-- submit once any pool exists.

-- Group SIDs resolved for a directory user at login (from tokenGroups), cached so
-- submit/scheduling can resolve pool eligibility without re-querying the DC.
-- Refreshed on every directory login.
CREATE TABLE user_dir_groups (
  user_id   uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  group_sid text NOT NULL,
  PRIMARY KEY (user_id, group_sid)
);
CREATE INDEX ix_user_dir_groups_sid ON user_dir_groups(group_sid);

-- A named set of agents. The unit of authorization and (later) fairness.
CREATE TABLE agent_pools (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name       text NOT NULL UNIQUE,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Agent membership in a pool (an agent may be in several pools).
CREATE TABLE agent_pool_members (
  pool_id  uuid NOT NULL REFERENCES agent_pools(id) ON DELETE CASCADE,
  agent_id uuid NOT NULL REFERENCES agents(id)      ON DELETE CASCADE,
  PRIMARY KEY (pool_id, agent_id)
);
CREATE INDEX ix_agent_pool_members_agent ON agent_pool_members(agent_id);

-- group objectSid -> pool grant. A user's authorized pools = the union of pools
-- granted to any group in their resolved tokenGroups.
CREATE TABLE directory_agent_grants (
  group_sid  text NOT NULL,
  pool_id    uuid NOT NULL REFERENCES agent_pools(id) ON DELETE CASCADE,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_sid, pool_id)
);
CREATE INDEX ix_directory_agent_grants_sid ON directory_agent_grants(group_sid);

-- Per-job authorization snapshot (an optimization + audit record; the scheduler
-- re-derives the eligible agent set live at assignment so a narrowed grant takes
-- effect on the next chunk). owner_group_sid is the group charged for fairness
-- (PR3). eligible_pool_ids empty = unrestricted (run on any agent).
ALTER TABLE jobs
  ADD COLUMN owner_group_sid  text,
  ADD COLUMN eligible_pool_ids uuid[] NOT NULL DEFAULT '{}';
