-- Identity, sessions, MFA, recovery, and throttling (ADR-0012). Users and
-- credentials are global identities; workspaces and memberships are tenant
-- data protected by row-level security (ADR-0011).

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION qali.current_user_id() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT NULLIF(current_setting('qali.user_id', true), '')::uuid $$;
-- +goose StatementEnd
GRANT EXECUTE ON FUNCTION qali.current_user_id() TO qali_app;

-- Exactly one row once bootstrap has completed.
CREATE TABLE qali.installation (
  singleton       boolean     PRIMARY KEY DEFAULT true CHECK (singleton),
  owner_user_id   uuid        NOT NULL,
  bootstrapped_at timestamptz NOT NULL
);

-- Wrapped data-encryption keys (ADR-0006); scope is 'installation' or a
-- workspace ID.
CREATE TABLE qali.encryption_keys (
  id          text        PRIMARY KEY,
  scope       text        NOT NULL UNIQUE,
  kek_version integer     NOT NULL CHECK (kek_version > 0),
  nonce       bytea       NOT NULL,
  ciphertext  bytea       NOT NULL,
  created_at  timestamptz NOT NULL
);

CREATE TABLE qali.users (
  id                  uuid        PRIMARY KEY,
  email               text        NOT NULL UNIQUE CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
  display_name        text        NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  password_hash       text        CHECK (password_hash IS NULL OR password_hash LIKE '$argon2id$%'),
  password_changed_at timestamptz,
  status              text        NOT NULL CHECK (status IN ('active', 'deactivated')),
  totp_algorithm      text,
  totp_dek_id         text        REFERENCES qali.encryption_keys (id),
  totp_nonce          bytea,
  totp_ciphertext     bytea,
  totp_confirmed_at   timestamptz,
  totp_last_step      bigint,
  created_at          timestamptz NOT NULL,
  updated_at          timestamptz NOT NULL,
  version             integer     NOT NULL DEFAULT 1 CHECK (version > 0),
  CHECK ((totp_ciphertext IS NULL) = (totp_nonce IS NULL)),
  CHECK (totp_confirmed_at IS NULL OR totp_ciphertext IS NOT NULL)
);

CREATE TABLE qali.workspaces (
  id         uuid        PRIMARY KEY,
  name       text        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  created_at timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  version    integer     NOT NULL DEFAULT 1 CHECK (version > 0)
);

CREATE TABLE qali.workspace_members (
  workspace_id uuid        NOT NULL REFERENCES qali.workspaces (id),
  user_id      uuid        NOT NULL REFERENCES qali.users (id),
  role         text        NOT NULL CHECK (role IN ('owner', 'workspace_admin', 'qa_lead', 'tester', 'viewer')),
  status       text        NOT NULL CHECK (status IN ('active', 'deactivated')),
  created_at   timestamptz NOT NULL,
  updated_at   timestamptz NOT NULL,
  version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),
  PRIMARY KEY (workspace_id, user_id)
);
CREATE INDEX workspace_members_user ON qali.workspace_members (user_id);
SELECT qali.enable_workspace_isolation('qali.workspace_members');
-- A user may also read their own memberships in every workspace (login,
-- MFA requirement, workspace switcher). Permissive policies are OR'ed.
CREATE POLICY member_self ON qali.workspace_members FOR SELECT
  USING (user_id = qali.current_user_id());

ALTER TABLE qali.workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE qali.workspaces FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_isolation ON qali.workspaces
  USING (id = qali.current_workspace())
  WITH CHECK (id = qali.current_workspace());
CREATE POLICY workspace_member_self ON qali.workspaces FOR SELECT
  USING (EXISTS (SELECT 1 FROM qali.workspace_members m
                 WHERE m.workspace_id = workspaces.id AND m.user_id = qali.current_user_id()));

CREATE TABLE qali.sessions (
  id              uuid        PRIMARY KEY,
  user_id         uuid        NOT NULL REFERENCES qali.users (id),
  lookup_id       text        NOT NULL UNIQUE,
  verifier        bytea       NOT NULL CHECK (length(verifier) = 32),
  key_version     integer     NOT NULL CHECK (key_version > 0),
  csrf_verifier   bytea       NOT NULL CHECK (length(csrf_verifier) = 32),
  state           text        NOT NULL CHECK (state IN ('mfa_enrollment', 'mfa_challenge', 'active')),
  auth_method     text        NOT NULL CHECK (auth_method IN ('password', 'bootstrap')),
  created_at      timestamptz NOT NULL,
  last_seen_at    timestamptz NOT NULL,
  idle_expires_at timestamptz NOT NULL,
  expires_at      timestamptz NOT NULL,
  mfa_verified_at timestamptz,
  revoked_at      timestamptz,
  revoke_reason   text        CHECK (revoke_reason IS NULL OR revoke_reason IN
                    ('logout', 'logout_all', 'rotated', 'password_changed', 'recovered', 'expired')),
  source_ip       inet,
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX sessions_live_by_user ON qali.sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE qali.recovery_codes (
  id            uuid        PRIMARY KEY,
  user_id       uuid        NOT NULL REFERENCES qali.users (id),
  lookup        text        NOT NULL CHECK (lookup ~ '^[A-Z2-7]{4}$'),
  code_hash     text        NOT NULL CHECK (code_hash LIKE '$argon2id$%'),
  created_at    timestamptz NOT NULL,
  used_at       timestamptz,
  superseded_at timestamptz
);
CREATE UNIQUE INDEX recovery_codes_live_lookup ON qali.recovery_codes (user_id, lookup)
  WHERE used_at IS NULL AND superseded_at IS NULL;

CREATE TABLE qali.password_resets (
  id          uuid        PRIMARY KEY,
  user_id     uuid        NOT NULL REFERENCES qali.users (id),
  lookup_id   text        NOT NULL UNIQUE,
  verifier    bytea       NOT NULL CHECK (length(verifier) = 32),
  key_version integer     NOT NULL CHECK (key_version > 0),
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);

-- Keys are HMACs of the normalized account identifier or client IP, so the
-- table reveals neither emails nor addresses.
CREATE TABLE qali.login_throttle (
  key             bytea       PRIMARY KEY CHECK (length(key) = 32),
  kind            text        NOT NULL CHECK (kind IN ('account', 'ip')),
  failures        integer     NOT NULL CHECK (failures >= 0),
  next_allowed_at timestamptz NOT NULL,
  updated_at      timestamptz NOT NULL
);

-- +goose Down
DROP TABLE qali.login_throttle;
DROP TABLE qali.password_resets;
DROP TABLE qali.recovery_codes;
DROP TABLE qali.sessions;
DROP POLICY workspace_member_self ON qali.workspaces;
DROP TABLE qali.workspace_members;
DROP TABLE qali.workspaces;
DROP TABLE qali.users;
DROP TABLE qali.encryption_keys;
DROP TABLE qali.installation;
DROP FUNCTION qali.current_user_id();
