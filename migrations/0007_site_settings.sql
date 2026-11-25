-- flamejob: sitewide settings, managed from the dashboard by superadmin/admin.
--
-- A single row (id is pinned to 1) holds the runtime TLS configuration for the
-- optional HTTPS-on-443 dashboard listener: the certificate (PEM, public) and
-- the private key (PEM, ENCRYPTED at rest with the same AES-256-GCM cipher that
-- protects cracked plaintext — see crypto.rs), plus an enable flag. Changing the
-- row signals the server to (re)bind or drop the :443 listener live; the plain
-- HTTP dashboard on its configured port (default 9443) is never affected.
CREATE TABLE site_settings (
  id             smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  https_enabled  boolean NOT NULL DEFAULT false,
  tls_cert_pem   text,                 -- certificate chain, PEM (public)
  tls_key_enc    bytea,                -- private key PEM, cipher-encrypted
  updated_at     timestamptz NOT NULL DEFAULT now(),
  updated_by     uuid REFERENCES users(id)
);

-- Seed the singleton row (HTTPS off, no cert) so the server always has a row.
INSERT INTO site_settings (id, https_enabled) VALUES (1, false)
ON CONFLICT (id) DO NOTHING;
