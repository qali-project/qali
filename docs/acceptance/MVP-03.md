# MVP-03 acceptance map

Item: MVP-03 — PostgreSQL, migrations, tenancy, jobs, and audit base  
Status: COMPLETE  
Coordinator: implementation agent  
Dependencies verified: MVP-02 COMPLETE (2026-10-22)

## Scope

Included:

- Database roles (`docs/SECURITY_ARCHITECTURE.md` section 8): a bootstrap
  script creates `qali_migrator` (owns schema `qali`) and `qali_app` (runtime, DML
  only through default privileges). The same script initializes the Compose
  database and the integration-test containers.
- goose migrations embedded in the binary, applied by `qali migrate up` with a
  PostgreSQL advisory-lock session locker; a one-shot Compose `migrate` service
  holds the migrator credential, the runtime container never does.
- `internal/platform/db`: pgx pool, transaction helper, error mapping,
  workspace scope with PostgreSQL row-level security as defense in depth, and
  read/write units of work where every write must record an audit event.
- `internal/platform/audit`: append-only, redacted, hash-chained audit events.
- `internal/platform/jobs`: PostgreSQL job queue (`FOR UPDATE SKIP LOCKED`),
  bounded retries with backoff, leases, dead-letter state, idempotent enqueue,
  and a worker with graceful drain.
- Typed SQL with sqlc for platform queries.
- `/health/ready`, `qali healthcheck`, request logging, metrics hooks, and
  ordered graceful shutdown.

Excluded (later items):

- Workspaces, users, memberships, and any feature table (MVP-04/05+). A
  test-only table exercises the tenancy primitives.
- Prometheus exposition and protected diagnostics endpoints (MVP-15); this item
  adds the recording interface only.
- Audit export, retention jobs, and administrative job retry UI.

## Threats

| Threat ID | Threat | Control |
|---|---|---|
| MVP-03.T-01 | A guessed or foreign ID reads or changes another workspace's data | Scope sets a transaction-local workspace; RLS policies on tenant tables; repository contract tests |
| MVP-03.T-02 | A compromised runtime credential alters schema, creates extensions, or rewrites history | Separate migrator and runtime roles; runtime has DML only; audit table insert-only plus trigger |
| MVP-03.T-03 | Two replicas migrate at once and corrupt the schema | goose session locker on a PostgreSQL advisory lock |
| MVP-03.T-04 | Changes happen without attribution | Write units of work fail to commit without an audit event |
| MVP-03.T-05 | Audit records leak secrets or are silently edited | Redaction of `secret.Value` and sensitive keys; hash chain verification |
| MVP-03.T-06 | Two workers run the same job, or failing jobs retry forever | `SKIP LOCKED` claims with leases; bounded attempts and dead-letter state |
| MVP-03.T-07 | Database errors leak SQL, constraint names, or data to clients | Error mapping to stable domain errors |
| MVP-03.T-08 | Orchestrators route traffic to an instance without a database or with pending migrations | Readiness checks database and migration version |
| MVP-03.T-09 | Logs capture credentials from headers, query strings, or bodies | Request logs record only method, route pattern, status, duration, and request ID |
| MVP-03.T-10 | Feature code bypasses the scoped primitives with a raw pool | Lint forbids pool and `database/sql` imports outside `internal/platform/db` |

## Criteria

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| MVP-03.AC-01 | Migrations apply from an empty database; reversible migrations roll back and re-apply | MVP-03.T-03 | `test/integration/migrations_test.go` | PASS |
| MVP-03.AC-02 | Concurrent migration runs are serialized and apply each version once | MVP-03.T-03 | `test/integration/migrations_test.go` | PASS |
| MVP-03.AC-03 | The runtime role cannot create, alter, or drop schema objects, schemas, roles, or extensions | MVP-03.T-02 | `test/integration/roles_test.go` | PASS |
| MVP-03.AC-04 | Transactions commit on success and roll back on error and panic; constraint, uniqueness, and missing-row errors map to stable errors without SQL text | MVP-03.T-07 | `internal/platform/db/errors_test.go`; `test/integration/store_test.go` | PASS |
| MVP-03.AC-05 | Guessed IDs and the wrong workspace never read, update, count, search, or delete data, even when a query omits the workspace filter | MVP-03.T-01 | `test/integration/tenancy_test.go` | PASS |
| MVP-03.AC-06 | Write units of work cannot commit without an audit event | MVP-03.T-04 | `test/integration/store_test.go` | PASS |
| MVP-03.AC-07 | Audit events are immutable, redact registered secret types, and a hash chain detects tampering | MVP-03.T-02, MVP-03.T-05 | `internal/platform/audit/audit_test.go`; `test/integration/audit_test.go` | PASS |
| MVP-03.AC-08 | Jobs: concurrent claims never overlap; retries back off; exhausted jobs dead-letter; expired leases are reclaimed; enqueue is idempotent | MVP-03.T-06 | `internal/platform/jobs/backoff_test.go`; `test/integration/jobs_test.go` | PASS |
| MVP-03.AC-09 | Readiness distinguishes database and migration failures and exposes only a boolean publicly; `qali healthcheck` reflects it | MVP-03.T-08 | `test/integration/readiness_test.go`; `internal/platform/httpserver/readiness_test.go` | PASS |
| MVP-03.AC-10 | Request logs contain request ID, method, route, status, and duration but no headers, query, or body; metrics hooks record HTTP and job outcomes | MVP-03.T-09 | `internal/platform/httpserver/logging_test.go`; `test/integration/jobs_test.go` | PASS |
| MVP-03.AC-11 | Shutdown stops HTTP, drains in-flight jobs, then closes the pool | MVP-03.T-06 | `test/integration/jobs_test.go` (worker drain); `cmd/qali` shutdown order test | PASS |
| MVP-03.AC-12 | Feature adapters cannot import the pool or `database/sql`; repositories receive scoped transactions only | MVP-03.T-10 | `tools/gateselftest/run.sh::adapter-pool-import` | PASS |
| MVP-03.AC-13 | Compose migrates with a one-shot service; the runtime container holds no migrator credential; the stack becomes ready | MVP-03.T-02 | `tools/deploycheck/deploycheck_test.go`; `make test-deploy` | PASS |

## Evidence

| Date (UTC) | Command | Result |
|---|---|---|
| 2026-10-22 | `go vet -tags integration ./test/integration/` before `internal/platform/db` existed | package not found (expected) |
| 2026-10-22 | `go vet` on audit, db, jobs, metrics, httpserver, deploycheck, secretsdir, cmd/qali tests before implementation | undefined symbols / no non-test files (expected) |
| 2026-10-22 | RLS mutation: policy `USING (true)` | 3 tenancy tests FAIL ("guessed ID ... was readable", "system scope saw 1 tenant rows", "next transaction ... saw 1 rows"); restored, PASS |
| 2026-10-22 | Lint-rule probes: pool import in a feature adapter, `PlatformWrite` in app code, `dbtest` in production code | each reported by depguard/forbidigo; real tree 0 issues |
| 2026-10-22 | `make gate-selftest` | exit 0; 17/17 PASS incl. baseline (fmt, fmt-check, lint, test, test-e2e, build with live Compose), adapter-pool-import, unaudited-platform-write, stale-sqlc, coverage-drop, compose-postgres-port |
| 2026-10-22 | `make test-integration RACE=1 POSTGRES_MAJORS="17 18"` | exit 0 on PostgreSQL 17 and 18, no data races |
| 2026-10-22 | `make cover-check` (unit + integration) | OK: audit 94.8%, db 90.7%, jobs >= 90%, httpserver 90.9%, plus MVP-02 packages |
| 2026-10-22 | `make test-e2e` | 5/5 Playwright against the production binary and a migrated database, incl. `/health/ready` |
| 2026-10-22 | `make test-deploy` | roles bootstrapped, `migrate` exited 0, `qali` healthy and ready through Caddy, only 443/tcp published |
| 2026-10-22 | `make fmt-check`, `make lint` | exit 0; golangci-lint 0 issues, gitleaks clean, govulncheck 0 reachable |

## Failing-first evidence

- All new test files were written before their implementation and failed for
  missing code (see Evidence). Tenancy tests were additionally mutation-checked.
- Test specifications corrected before they ever passed: a non-owner `GRANT`
  only warns in PostgreSQL, so the role test asserts the resulting ACL instead
  of an error; a confusing backoff table entry was rewritten.
- Defects found by the gates and fixed in product code: `migrations/` missing
  from the image build; wall-clock reads in request logging and the worker
  (ADR-0004); vulnerable `x/crypto` and `go-archive` versions reachable through
  the test harness (updated, see `docs/DEPENDENCIES.md`); a gitleaks match on
  fake fixture values (per-line `gitleaks:allow`).

## Notes and open questions

- ADR-0011 records the database role, RLS, audit-chain, and job decisions and
  is `Proposed`; it needs maintainer review. RLS is enabled now rather than
  "after the query model is stable" (SECURITY_ARCHITECTURE section 8).
- Contract changes recorded: `/health/ready` added to OpenAPI; the server now
  requires the database at startup; `tools/devsecrets` writes eight files;
  the Compose stack gained the one-shot `migrate` service; E2E runs through
  `tools/e2eenv` with a real database.
- `Store.PlatformWrite` is the only unaudited write path and is lint-restricted
  to `internal/platform`.
- MVP-03 marked `COMPLETE` on 2026-10-22: every criterion is `PASS`.
