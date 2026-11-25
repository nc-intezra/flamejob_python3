-- Phase 3 distributed agents: enrollment claim tokens and enrolled agents.

-- One-time enrollment tokens minted by an admin. Consumed on first use.
CREATE TABLE agent_claims (
  token      text PRIMARY KEY,
  name       text NOT NULL,
  created_by uuid REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(),
  used_at    timestamptz
);

-- Enrolled worker nodes. The fingerprint is the SHA-256 (hex) of the issued
-- client certificate's DER; the agent presents the cert on connect and the
-- server matches it here.
CREATE TABLE agents (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name        text NOT NULL,
  fingerprint text NOT NULL UNIQUE,
  enrolled_at timestamptz NOT NULL DEFAULT now(),
  last_seen   timestamptz,
  status      text NOT NULL DEFAULT 'enrolled'   -- enrolled | online | offline | revoked
);
