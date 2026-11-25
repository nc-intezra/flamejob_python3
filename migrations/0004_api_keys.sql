-- API keys: long-lived, revocable credentials a user mints from the web UI to
-- call the API programmatically. Only the SHA-256 of the secret is stored; the
-- plaintext key is shown once at creation and never persisted.
CREATE TABLE api_keys (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id      uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         text NOT NULL,
  -- Non-secret display prefix (e.g. "fj_1a2b3c4d") so a key is recognisable in
  -- the UI without revealing the secret.
  prefix       text NOT NULL,
  -- Hex SHA-256 of the full secret; unique so a key maps to exactly one row.
  key_hash     text NOT NULL UNIQUE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  -- NULL means the key never expires (revoke to disable).
  expires_at   timestamptz,
  last_used_at timestamptz,
  revoked      boolean NOT NULL DEFAULT false
);

CREATE INDEX api_keys_user_idx ON api_keys (user_id);
CREATE INDEX api_keys_hash_idx ON api_keys (key_hash);
