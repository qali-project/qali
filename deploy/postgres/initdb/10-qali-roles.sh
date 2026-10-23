#!/bin/sh
# Creates the Qali database roles on first PostgreSQL start
# (docs/SECURITY_ARCHITECTURE.md section 8):
#   qali_migrator  owns schema "qali" and runs migrations
#   qali_app       runtime role: DML only, owns nothing, cannot create objects
# Passwords come from mounted secret files, never from the environment.
# The integration tests run this same script. The postgres entrypoint may
# source this file, so it avoids `set -u`, `exit`, and "$0".
set -e

qali_secrets="${QALI_BOOTSTRAP_SECRETS:-/run/secrets}"
qali_database_sql="${QALI_BOOTSTRAP_SQL:-/opt/qali/qali-database.sql}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v migrator_pw="$(cat "$qali_secrets/migrator_password")" \
  -v app_pw="$(cat "$qali_secrets/app_password")" <<'SQL'
CREATE ROLE qali_migrator LOGIN PASSWORD :'migrator_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE qali_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE qali_migrator SET search_path = qali;
ALTER ROLE qali_app SET search_path = qali;
ALTER ROLE qali_migrator SET timezone = 'UTC';
ALTER ROLE qali_app SET timezone = 'UTC';
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$qali_database_sql"
