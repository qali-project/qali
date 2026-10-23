-- Per-database setup for Qali, run as a superuser after the roles exist.
-- Plain SQL (no psql meta-commands) so tests can execute it directly.

-- Nobody but the two Qali roles may connect; nobody may create objects in the
-- public schema.
DO $$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO qali_migrator, qali_app', current_database());
END $$;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- The migrator owns the application schema; the runtime role may only use it.
CREATE SCHEMA qali AUTHORIZATION qali_migrator;
GRANT USAGE ON SCHEMA qali TO qali_app;

-- Objects the migrator creates are usable, not owned, by the runtime role.
-- Migrations narrow these grants where needed (for example, audit events are
-- insert-only).
ALTER DEFAULT PRIVILEGES FOR ROLE qali_migrator IN SCHEMA qali
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO qali_app;
ALTER DEFAULT PRIVILEGES FOR ROLE qali_migrator IN SCHEMA qali
  GRANT USAGE, SELECT ON SEQUENCES TO qali_app;
ALTER DEFAULT PRIVILEGES FOR ROLE qali_migrator IN SCHEMA qali
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
