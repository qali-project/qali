-- Generic OIDC login. The provider, login policy, flows, and linked
-- identities are installation-wide platform data: login happens before any
-- workspace is known and users are global.

-- +goose Up
-- The bootstrap workspace authorizes installation-wide security settings.
-- Named primary_workspace_id so the singleton is not mistaken for a tenant
-- table.
ALTER TABLE qali.installation
  -- Deferred: bootstrap inserts the installation row (its race guard)
  -- before the workspace in the same transaction.
  ADD COLUMN primary_workspace_id uuid REFERENCES qali.workspaces (id) DEFERRABLE INITIALLY DEFERRED,
  ADD COLUMN local_login_enabled  boolean NOT NULL DEFAULT true,
  ADD COLUMN login_policy_version integer NOT NULL DEFAULT 1 CHECK (login_policy_version > 0);
-- Existing installations have exactly the bootstrap workspace. The
-- migrator owns qali.workspaces but has no BYPASSRLS, so FORCE is lifted for
-- this one read and restored in the same transaction.
ALTER TABLE qali.workspaces NO FORCE ROW LEVEL SECURITY;
UPDATE qali.installation
  SET primary_workspace_id = (SELECT id FROM qali.workspaces ORDER BY created_at, id LIMIT 1);
ALTER TABLE qali.workspaces FORCE ROW LEVEL SECURITY;
ALTER TABLE qali.installation ALTER COLUMN primary_workspace_id SET NOT NULL;

-- At most one provider. The client secret is sealed with the installation
-- DEK and never returned.
CREATE TABLE qali.oidc_provider (
  singleton         boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  id                uuid        NOT NULL UNIQUE,
  issuer            text        NOT NULL CHECK (length(issuer) BETWEEN 8 AND 2048),
  client_id         text        NOT NULL CHECK (length(client_id) BETWEEN 1 AND 512),
  label             text        NOT NULL CHECK (length(label) BETWEEN 1 AND 80),
  secret_dek_id     text        NOT NULL REFERENCES qali.encryption_keys (id),
  secret_nonce      bytea       NOT NULL,
  secret_ciphertext bytea       NOT NULL,
  status            text        NOT NULL CHECK (status IN ('draft', 'verified')),
  verified_at       timestamptz,
  verified_by       uuid        REFERENCES qali.users (id),
  created_at        timestamptz NOT NULL,
  updated_at        timestamptz NOT NULL,
  version           integer     NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK ((status = 'verified') = (verified_at IS NOT NULL)),
  CHECK ((verified_at IS NULL) = (verified_by IS NULL))
);

-- One authorization request: single use, valid for 10 minutes. state,
-- nonce, and the browser binding are stored only as keyed verifiers; the
-- PKCE verifier (and an invitation token, if any) are sealed.
CREATE TABLE qali.oidc_flows (
  id               uuid        PRIMARY KEY,
  lookup_id        text        NOT NULL UNIQUE,
  state_verifier   bytea       NOT NULL CHECK (length(state_verifier) = 32),
  nonce_verifier   bytea       NOT NULL CHECK (length(nonce_verifier) = 32),
  binding_verifier bytea       NOT NULL CHECK (length(binding_verifier) = 32),
  key_version      integer     NOT NULL CHECK (key_version > 0),
  provider_id      uuid        NOT NULL,
  purpose          text        NOT NULL CHECK (purpose IN ('login', 'invitation', 'link', 'verify')),
  user_id          uuid        REFERENCES qali.users (id),
  sealed_dek_id    text        NOT NULL REFERENCES qali.encryption_keys (id),
  sealed_nonce     bytea       NOT NULL,
  sealed_payload   bytea       NOT NULL,
  created_at       timestamptz NOT NULL,
  expires_at       timestamptz NOT NULL,
  consumed_at      timestamptz,
  CHECK (expires_at > created_at),
  CHECK ((purpose IN ('link', 'verify')) = (user_id IS NOT NULL))
);
CREATE INDEX oidc_flows_expiry ON qali.oidc_flows (expires_at);

CREATE TABLE qali.user_identities (
  id            uuid        PRIMARY KEY,
  user_id       uuid        NOT NULL REFERENCES qali.users (id),
  issuer        text        NOT NULL,
  subject       text        NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),
  link_method   text        NOT NULL CHECK (link_method IN ('explicit', 'verified_email', 'invitation', 'verify')),
  linked_at     timestamptz NOT NULL,
  last_login_at timestamptz,
  UNIQUE (issuer, subject),
  UNIQUE (user_id, issuer)
);

ALTER TABLE qali.sessions DROP CONSTRAINT sessions_auth_method_check;
ALTER TABLE qali.sessions ADD CONSTRAINT sessions_auth_method_check
  CHECK (auth_method IN ('password', 'bootstrap', 'oidc'));

-- +goose Down
DELETE FROM qali.sessions WHERE auth_method = 'oidc';
ALTER TABLE qali.sessions DROP CONSTRAINT sessions_auth_method_check;
ALTER TABLE qali.sessions ADD CONSTRAINT sessions_auth_method_check
  CHECK (auth_method IN ('password', 'bootstrap'));
DROP TABLE qali.user_identities;
DROP TABLE qali.oidc_flows;
DROP TABLE qali.oidc_provider;
ALTER TABLE qali.installation
  DROP COLUMN login_policy_version,
  DROP COLUMN local_login_enabled,
  DROP COLUMN primary_workspace_id;
