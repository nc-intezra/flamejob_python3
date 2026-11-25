-- flamejob v2.0 Phase 5 — directory authentication (AD/LDAP) core.
--
-- This migration adds directory-backed sign-in and the SID->role mapping. Agent
-- pools, directory->pool grants and fairness quotas are a separate concern and
-- land in a later migration; this one is only auth + role mapping + the
-- runtime-editable connection config.
--
-- Design: `claude/ad-ldap-integration-design.md` (backend) and
-- `claude/ad-ldap-config-page-design.md` (config page). All authorization
-- matching is on the group's immutable `objectSid`; CNs are display-only.

-- Directory users are shadowed into `users` on first login so that existing FKs
-- (owner_user_id, api_keys, audit) and the capability path keep working. The
-- stable directory identity is the account's objectSid.
ALTER TABLE users
  ADD COLUMN external_sid text UNIQUE;

-- Runtime-editable connection config, a single row (id pinned to 1), mirroring
-- the `site_settings` singleton. The service-account bind password is stored
-- ENCRYPTED at rest with the same AES-256-GCM cipher that protects cracked
-- plaintext and the TLS private key (see crypto.rs); it is never returned to the
-- browser. Transport is one of 'ldaps' | 'starttls' | 'plaintext'; plaintext is
-- opt-in and must be acknowledged (plaintext_ack) before it can be enabled.
CREATE TABLE directory_config (
  id                  smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  enabled             boolean NOT NULL DEFAULT false,
  transport           text    NOT NULL DEFAULT 'ldaps',   -- 'ldaps' | 'starttls' | 'plaintext'
  discovery           text    NOT NULL DEFAULT 'static',  -- 'srv' | 'static'
  domain              text,                               -- for SRV discovery (_ldap._tcp.dc._msdcs.<domain>)
  servers             text[]  NOT NULL DEFAULT '{}',      -- host[:port] list when static
  use_global_catalog  boolean NOT NULL DEFAULT true,
  base_dn             text,
  bind_dn             text,                               -- read-only service account
  bind_password_enc   bytea,                              -- AES-GCM; never returned
  user_filter         text    NOT NULL DEFAULT
    '(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(|(sAMAccountName=%u)(userPrincipalName=%u)(mail=%u)))',
  login_attributes    text[]  NOT NULL DEFAULT '{sAMAccountName,userPrincipalName,mail}',
  ca_bundle_pem       text,                               -- trust anchor(s) for a private CA (LDAPS/StartTLS)
  verify_hostname     boolean NOT NULL DEFAULT true,
  allow_insecure_tls  boolean NOT NULL DEFAULT false,     -- skip chain/host verify (lab only; warned in UI)
  plaintext_ack       boolean NOT NULL DEFAULT false,     -- explicit cleartext acknowledgment
  group_source        text    NOT NULL DEFAULT 'token_groups', -- 'token_groups' | 'matching_rule_in_chain'
  cache_ttl_secs      integer NOT NULL DEFAULT 600,
  on_directory_down   text    NOT NULL DEFAULT 'fail_closed',  -- 'fail_closed' | 'cache_only'
  default_role        role,                               -- NULL = no implicit role for authenticated users
  jwt_ttl_hours       integer NOT NULL DEFAULT 8,
  last_test_ok_at     timestamptz,                        -- gates "enable" (fresh passing service bind)
  updated_by          uuid REFERENCES users(id),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Seed the singleton (directory off) so the server always has a row to read.
INSERT INTO directory_config (id, enabled) VALUES (1, false)
ON CONFLICT (id) DO NOTHING;

-- group objectSid -> flamejob role. A user lands in the UNION of the roles of
-- every group in their resolved tokenGroups, so there is no precedence to
-- settle (capabilities union). `group_cn` is display-only and never matched on.
CREATE TABLE directory_role_map (
  group_sid   text NOT NULL,              -- canonical S-1-5-21-...-RID
  role        role NOT NULL,              -- reuses the existing `role` enum
  group_cn    text,                       -- display only; never used for matching
  created_by  uuid REFERENCES users(id),
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (group_sid, role)
);
CREATE INDEX ix_directory_role_map_sid ON directory_role_map(group_sid);
