-- One-time setup tokens for first-owner bootstrap (REVIEW-001, ADR-0012
-- amendment). The operator issues a token on the server with
-- `qali setup-token`; only its holder can claim a fresh installation.
-- Platform table: no workspace exists yet.

-- +goose Up
CREATE TABLE qali.setup_tokens (
  id          uuid        PRIMARY KEY,
  lookup_id   text        NOT NULL UNIQUE CHECK (lookup_id ~ '^[a-z2-7]{16}$'),
  verifier    bytea       NOT NULL CHECK (length(verifier) = 32),
  key_version integer     NOT NULL CHECK (key_version > 0),
  issued_by   text        NOT NULL CHECK (length(issued_by) BETWEEN 1 AND 200),
  created_at  timestamptz NOT NULL,
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz,
  CHECK (expires_at > created_at)
);
REVOKE DELETE ON qali.setup_tokens FROM qali_app;

-- +goose Down
DROP TABLE qali.setup_tokens;
