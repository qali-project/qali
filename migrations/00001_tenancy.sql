-- Workspace isolation primitives (AGENTS.md, SECURITY_ARCHITECTURE section 8).
-- The application sets qali.workspace_id per transaction (internal/platform/db);
-- tenant tables call qali.enable_workspace_isolation in their own migration so
-- row-level security backs every repository query.

-- +goose Up
-- +goose StatementBegin
CREATE FUNCTION qali.current_workspace() RETURNS uuid
LANGUAGE sql STABLE
AS $$ SELECT NULLIF(current_setting('qali.workspace_id', true), '')::uuid $$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION qali.enable_workspace_isolation(target regclass) RETURNS void
LANGUAGE plpgsql
AS $$
BEGIN
  EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', target);
  EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', target);
  EXECUTE format(
    'CREATE POLICY workspace_isolation ON %s USING (workspace_id = qali.current_workspace()) '
    'WITH CHECK (workspace_id = qali.current_workspace())', target);
END
$$;
-- +goose StatementEnd

GRANT EXECUTE ON FUNCTION qali.current_workspace() TO qali_app;

-- +goose Down
DROP FUNCTION qali.enable_workspace_isolation(regclass);
DROP FUNCTION qali.current_workspace();
