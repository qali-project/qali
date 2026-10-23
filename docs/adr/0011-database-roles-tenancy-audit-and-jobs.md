# ADR-0011: Database roles, tenancy enforcement, audit chain, and jobs

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-03

## Context

MVP-03 builds the persistence foundation every later item uses. Its exit gate
requires that no feature repository can exist outside the scoped transaction
and audit primitives. `docs/SECURITY_ARCHITECTURE.md` section 8 asks for split
migration/runtime roles and suggests row-level security (RLS) "after the
application query model is stable". These choices shape every migration.

## Decision

### Roles

- `deploy/postgres/initdb/10-qali-roles.sh` creates two roles on first start:
  `qali_migrator` owns schema `qali`; `qali_app` is the runtime role with DML
  only through default privileges, `NOINHERIT`, no `CREATEDB`/`CREATEROLE`/
  `BYPASSRLS`. `deploy/postgres/sql/qali-database.sql` revokes `PUBLIC` access
  to the database and the `public` schema.
- Both roles use `search_path = qali` and `timezone = UTC`.
- The runtime pool refuses to start as a superuser, a `BYPASSRLS` role, or the
  schema owner.
- `qali migrate up` runs with `QALI_MIGRATION_DATABASE_URL_FILE`; in Compose a
  one-shot `migrate` service is the only holder of that credential.

### Tenancy

- RLS is enabled now, as defense in depth below the application checks.
  Tenant tables call `qali.enable_workspace_isolation(table)` in their own
  migration, which enables and forces RLS with a policy comparing
  `workspace_id` to the transaction-local setting `qali.workspace_id`.
- Repositories receive only a `db.Querier` (or `db.WriteTx`) from
  `db.Store.Read`/`Write`, which set that setting with `set_config(..., true)`.
  The system scope sets no workspace, so tenant tables are invisible to it.
- Lint forbids `database/sql`, `pgxpool`, and `pgx/stdlib` in feature adapters
  and the test harness in production code.

### Units of work and audit

- `Store.Write` commits only if the callback recorded at least one audit
  event in the same transaction; otherwise it rolls back with `ErrUnaudited`.
- `Store.PlatformWrite` is the unaudited exception for platform bookkeeping
  (job leases) and is forbidden by lint outside `internal/platform`.
- Audit events are insert-only for the runtime role and protected by triggers
  against update, delete, and truncate even for the owner.
- Each chain (one per workspace, plus `system`) is hash-linked: SHA-256 over
  length-prefixed fields, canonical metadata JSON, and the previous hash.
  Appends lock the chain with a transaction-scoped advisory lock.
- Metadata is redacted before storage: `secret.Value` values and values of
  keys containing password, passphrase, secret, token, authorization, cookie,
  api_key, apikey, private_key, credential, pepper, recovery_code, otp, totp,
  session, or signature. Metadata is capped at 16 KiB.

### Jobs

- Default 5 attempts, lease 5 minutes, retry backoff 10 s doubling to a 1 h
  cap; jobs whose lease expires on their final attempt are dead-lettered.
- Claims use `FOR UPDATE SKIP LOCKED`; enqueue is idempotent per
  `(kind, idempotency_key)`.
- A dead-lettered job writes an audit event in its chain.

### Readiness

- `/health/ready` is ready only when the database answers and its schema
  version equals the newest migration embedded in the binary; a newer schema
  (binary rollback) is also not ready.

## Consequences

- A forgotten `workspace_id` filter in a feature query returns nothing instead
  of leaking data, and integration tests prove it.
- Every feature migration must call `qali.enable_workspace_isolation` for its
  tenant tables; contract tests should assert this for each new table.
- Role names `qali_migrator` and `qali_app` are fixed and referenced by
  migrations; renaming them requires a new ADR.

## Alternatives considered

- Application-only scoping without RLS: rejected; a single missing predicate
  would leak data, and RLS costs little at this size.
- Optional audit in write transactions: rejected; attribution would depend on
  every author remembering it (AGENTS.md requires audit attribution).
- A global audit chain: rejected; it would serialize all writes across
  workspaces.
