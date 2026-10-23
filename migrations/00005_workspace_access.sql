-- Invitations, projects as access objects, and direct project membership
-- (ADR-0013). Every table here is tenant data protected by row-level
-- security (ADR-0011); composite foreign keys keep references inside one
-- workspace (ADR-0009).

-- +goose Up
-- An invitation link is redeemed before the caller knows its workspace.
-- This global index maps a token's public lookup ID to that workspace only;
-- it holds no verifier, email, or role, and a lookup ID alone authorizes
-- nothing.
CREATE TABLE qali.invitation_lookups (
  lookup_id    text PRIMARY KEY CHECK (lookup_id ~ '^[a-z2-7]{16}$'),
  workspace_id uuid NOT NULL REFERENCES qali.workspaces (id)
);
REVOKE UPDATE ON qali.invitation_lookups FROM qali_app;

CREATE TABLE qali.invitations (
  id           uuid        PRIMARY KEY,
  workspace_id uuid        NOT NULL REFERENCES qali.workspaces (id),
  email        text        NOT NULL CHECK (email = lower(email) AND length(email) BETWEEN 3 AND 254),
  role         text        NOT NULL CHECK (role IN ('workspace_admin', 'qa_lead', 'tester', 'viewer')),
  lookup_id    text        NOT NULL UNIQUE REFERENCES qali.invitation_lookups (lookup_id),
  verifier     bytea       NOT NULL CHECK (length(verifier) = 32),
  key_version  integer     NOT NULL CHECK (key_version > 0),
  invited_by   uuid        NOT NULL,
  created_at   timestamptz NOT NULL,
  expires_at   timestamptz NOT NULL,
  accepted_at  timestamptz,
  accepted_by  uuid        REFERENCES qali.users (id),
  revoked_at   timestamptz,
  UNIQUE (workspace_id, id),
  FOREIGN KEY (workspace_id, invited_by) REFERENCES qali.workspace_members (workspace_id, user_id),
  CHECK (expires_at > created_at),
  CHECK ((accepted_at IS NULL) = (accepted_by IS NULL)),
  CHECK (accepted_at IS NULL OR revoked_at IS NULL)
);
CREATE INDEX invitations_pending ON qali.invitations (workspace_id, id)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;
SELECT qali.enable_workspace_isolation('qali.invitations');

CREATE TABLE qali.projects (
  id           uuid        PRIMARY KEY,
  workspace_id uuid        NOT NULL REFERENCES qali.workspaces (id),
  code         text        NOT NULL CHECK (code ~ '^[A-Z][A-Z0-9]{1,9}$'),
  name         text        NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
  visibility   text        NOT NULL CHECK (visibility IN ('public', 'restricted')),
  created_by   uuid        NOT NULL,
  created_at   timestamptz NOT NULL,
  updated_at   timestamptz NOT NULL,
  version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),
  UNIQUE (workspace_id, id),
  UNIQUE (workspace_id, code),
  FOREIGN KEY (workspace_id, created_by) REFERENCES qali.workspace_members (workspace_id, user_id)
);
SELECT qali.enable_workspace_isolation('qali.projects');

CREATE TABLE qali.project_members (
  workspace_id uuid        NOT NULL,
  project_id   uuid        NOT NULL,
  user_id      uuid        NOT NULL,
  level        text        NOT NULL CHECK (level IN ('contributor', 'viewer')),
  created_at   timestamptz NOT NULL,
  updated_at   timestamptz NOT NULL,
  version      integer     NOT NULL DEFAULT 1 CHECK (version > 0),
  PRIMARY KEY (workspace_id, project_id, user_id),
  FOREIGN KEY (workspace_id, project_id) REFERENCES qali.projects (workspace_id, id),
  FOREIGN KEY (workspace_id, user_id) REFERENCES qali.workspace_members (workspace_id, user_id)
);
CREATE INDEX project_members_user ON qali.project_members (workspace_id, user_id);
SELECT qali.enable_workspace_isolation('qali.project_members');

-- +goose Down
DROP TABLE qali.project_members;
DROP TABLE qali.projects;
DROP TABLE qali.invitations;
DROP TABLE qali.invitation_lookups;
