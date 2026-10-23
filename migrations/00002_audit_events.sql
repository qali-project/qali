-- Append-only audit log (SECURITY_ARCHITECTURE section 9). Each chain (one per
-- workspace, plus "system") is hash-linked so edits and gaps are detectable.

-- +goose Up
CREATE TABLE qali.audit_events (
  seq          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  id           uuid        NOT NULL UNIQUE,
  chain        text        NOT NULL,
  workspace_id uuid,
  occurred_at  timestamptz NOT NULL,
  actor_type   text        NOT NULL CHECK (actor_type IN ('user', 'ci', 'mcp', 'integration', 'system', 'operator')),
  actor_id     text,
  action       text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  target_type  text,
  target_id    text,
  outcome      text        NOT NULL CHECK (outcome IN ('success', 'failure', 'denied')),
  request_id   text,
  source_ip    inet,
  metadata     jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  prev_hash    bytea       CHECK (prev_hash IS NULL OR length(prev_hash) = 32),
  hash         bytea       NOT NULL CHECK (length(hash) = 32),
  CHECK ((workspace_id IS NULL) = (chain = 'system')),
  CHECK (workspace_id IS NULL OR chain = workspace_id::text)
);

CREATE INDEX audit_events_chain_seq ON qali.audit_events (chain, seq);
CREATE INDEX audit_events_workspace_time ON qali.audit_events (workspace_id, occurred_at);

-- +goose StatementBegin
CREATE FUNCTION qali.audit_events_immutable() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit events are immutable' USING ERRCODE = 'insufficient_privilege';
END
$$;
-- +goose StatementEnd

CREATE TRIGGER audit_events_no_update_delete
  BEFORE UPDATE OR DELETE ON qali.audit_events
  FOR EACH ROW EXECUTE FUNCTION qali.audit_events_immutable();
CREATE TRIGGER audit_events_no_truncate
  BEFORE TRUNCATE ON qali.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION qali.audit_events_immutable();

-- The runtime role may only append and read.
REVOKE UPDATE, DELETE, TRUNCATE ON qali.audit_events FROM qali_app;

-- +goose Down
DROP TABLE qali.audit_events;
DROP FUNCTION qali.audit_events_immutable();
