# MVP Execution Plan

Status: active implementation plan  
Execution model: one globally active MVP item, secure vertical slices  
Release outcome: a small team can securely self-host Qali, author cases, execute
manual and automated runs, link defects, inspect essential reports, use a basic
integration, and query project data through a read-only MCP endpoint

## 1. Scope lock

### Included in MVP

- One-command production Compose deployment behind one TLS port; PostgreSQL and
  internal endpoints are not published.
- Local bootstrap/login, optional generic OIDC login, administrator MFA, secure
  sessions, recovery, logout/revocation, and append-only audit.
- Workspaces, invitations, project membership, and fixed roles: Owner,
  Workspace Administrator, QA Lead, Tester, and Viewer.
- Projects, nested suites, test cases, classic action/data/expected steps,
  essential fields/tags, immutable revisions, search, soft deletion, and restore.
- Encrypted local attachments. S3 compatibility is not required for MVP.
- Test plans, environments, configured/express runs, immutable case snapshots,
  assignment, manual execution, step/result status, evidence, and basic defects.
- Project-scoped CI credentials, REST automation ingestion, JUnit XML, native
  JSON, artifact upload, idempotency, a Go CLI, and examples for GitHub Actions,
  GitLab CI/CD, Jenkins, and TeamCity. These examples publish results; Qali does
  not trigger external pipelines in MVP.
- Run progress, pass/fail/blocked counts, history, duration, and CSV export.
- Signed outbound webhooks and one native work-management adapter: Jira Cloud.
  Other providers use links or webhooks until after MVP.
- Versioned REST API/OpenAPI and a read-only MCP endpoint for scoped project,
  case, run, result, and report access using a distinct revocable MCP token.
- Backup/restore documentation, upgrade-safe migrations, health/readiness,
  structured logs, protected metrics, and release artifacts.

### Explicitly deferred

- SAML, SCIM, custom roles, group provisioning, WebAuthn, multiple native OIDC
  provider adapters, and organization-wide identity federation.
- BDD editing, nested/shared steps, shared parameters, mandatory case review,
  rich comments/mentions, scheduled runs, advanced configuration matrices,
  requirements/traceability, query language, dashboard builder, and notifications.
- Native outbound CI triggering and provider adapters beyond Jira Cloud.
- Allure/XCTest and framework-specific reporter SDKs beyond JUnit/native JSON.
- Write-capable MCP, MCP OAuth authorization server, external AI egress, and AI
  provider adapters.
- S3 storage, Helm/HA, external KMS/Vault integration, full-text engine beyond
  PostgreSQL, and arbitrary plugins.

Deferred means forbidden during MVP implementation unless this document is
explicitly amended. Schemas may leave extension points but must not implement
the deferred behavior speculatively.

## 2. Execution rules for agents

1. Only the first incomplete item in section 4 may be active.
2. Global WIP limit is one. Do not start a later backend item while waiting for
   the current frontend, migration, test, or review work.
3. One coordinator owns the active item and its acceptance map. Additional agents
   may receive only named child tasks with disjoint file ownership.
4. Contract and acceptance tests are frozen before parallel child tasks begin.
5. A child agent must not edit another child's files, shared migrations, global
   generators, or acceptance tests unless the coordinator reassigns ownership.
6. Discoveries outside the item become backlog notes. They do not expand the
   current change.
7. Merge/integrate the item and pass its exit gate before selecting the next ID.
8. Security and tests are implementation work inside every item, never a cleanup
   wave at the end.

Recommended multi-agent split, only when an item is large enough:

- Contract agent: OpenAPI/migration proposal and acceptance-test fixtures.
- Backend agent: domain/application/adapters and unit/integration tests.
- Frontend agent: generated client usage, UI, component tests, and accessibility.
- Coordinator: integration, security-negative/E2E tests, docs, and full gates.

The contract agent finishes first. Backend and frontend may then work in
parallel. The coordinator does not mark the item complete with a missing layer.

## 3. Per-item delivery loop

For each item:

1. Confirm dependencies and restate included/excluded behavior.
2. Map every acceptance criterion to one or more named tests.
3. Add/freeze migration and OpenAPI changes when applicable.
4. Add failing behavioral and security-negative tests.
5. Implement domain/application behavior, then adapters, then UI.
6. Run targeted unit tests during development.
7. Run real-database/router/storage integration tests.
8. Run the item's critical E2E journey.
9. Run all repository gates and inspect generated diffs.
10. Record evidence and mark the item complete; otherwise keep it active.

Follow `TESTING_POLICY.md`. When an existing test fails, fix the defect. Do not
change the test to describe the buggy implementation unless the normative
contract is deliberately changed and reviewed first.

## 4. Ordered MVP work items

This registry is the only place where item status is changed. Allowed values are
`NOT_STARTED`, `IN_PROGRESS`, and `COMPLETE`. At most one row may be
`IN_PROGRESS`; rows are advanced strictly from top to bottom.

| Order | ID | Status | Outcome |
|---:|---|---|---|
| 0 | MVP-00 | COMPLETE | Decisions and acceptance language frozen |
| 1 | MVP-01 | COMPLETE | Repository and real quality gates |
| 2 | MVP-02 | COMPLETE | Secure runtime and cryptography |
| 3 | MVP-03 | COMPLETE | Scoped persistence, jobs, and audit |
| 4 | MVP-04 | COMPLETE | Local authentication, MFA, and sessions |
| 5 | MVP-05 | IN_PROGRESS | Workspace/project RBAC (awaits ADR-0013 acceptance; REVIEW-007) |
| 6 | MVP-06 | NOT_STARTED | Generic OIDC login |
| 7 | MVP-07 | NOT_STARTED | Projects, suites, cases, and revisions |
| 8 | MVP-08 | NOT_STARTED | Encrypted attachments |
| 9 | MVP-09 | NOT_STARTED | Plans and run snapshots |
| 10 | MVP-10 | NOT_STARTED | Manual execution and defects |
| 11 | MVP-11 | NOT_STARTED | Automation ingestion |
| 12 | MVP-12 | NOT_STARTED | JUnit CLI and CI examples |
| 13 | MVP-13 | NOT_STARTED | Essential reporting |
| 14 | MVP-14 | NOT_STARTED | Webhooks and Jira Cloud |
| 15 | MVP-15 | NOT_STARTED | Read-only MCP and release |

### MVP-00 — Freeze decisions and acceptance language

Dependencies: none

Deliver:

- Product name/module path/license, supported Go/PostgreSQL/Node/browser matrix,
  URL and versioning conventions, UTC/timezone policy, and MVP data-retention
  defaults as ADRs.
- A machine-readable permission catalog for fixed MVP roles.
- An acceptance-map template linking criterion, threat, test name, and result.

Acceptance and tests:

- No unresolved decision changes a migration, API shape, credential model, or
  role behavior in MVP-01 through MVP-15.
- Documentation link and duplicate-ID checks exist as repository commands and
  fail on violations.

Amendment 2026-10-22 (maintainer decision): the criterion "documentation link
and duplicate-ID checks run in CI" moved to MVP-01, because no repository host
or CI existed during MVP-00. GitHub is the chosen host.

Exit gate: scope and ADR review complete. No application code is started earlier.

### MVP-01 — Repository skeleton and executable quality gates

Dependencies: MVP-00

Deliver:

- Go module, React/TypeScript/Vite app, directory boundaries, Makefile, OpenAPI
  skeleton/generation, linting, formatting, unit/integration/E2E harnesses, CI,
  dependency lock/update policy, secret scanning, and minimal non-root image.

Acceptance and tests:

- All five commands in `AGENTS.md` execute from a clean checkout.
- A deliberately failing Go unit test, frontend unit test, integration test, and
  E2E test each cause the corresponding CI job to fail in a validation fixture.
- CI rejects skipped/focused tests and stale generated files.
- CI runs the MVP-00 documentation checks (`make docs-check`, `make docs-test`).
- Production image contains no source `.env`, test key, compiler, or package
  manager and runs as non-root.

Amendment 2026-10-22 (maintainer decision): no hosted repository exists yet.
The criteria that require the CI workflow to run on GitHub (MVP-00 docs checks
in CI; every CI job failing on an injected defect) are satisfied locally by
`make gate-selftest` for MVP-01 and become a release precondition of MVP-15.

Exit gate: empty application is reproducibly buildable and tests can genuinely
fail the pipeline.

### MVP-02 — Secure runtime, configuration, and cryptography

Dependencies: MVP-01

Deliver:

- Typed configuration with `_FILE` secret inputs; KEK and password/token pepper
  loading; Argon2id service; keyed token verifier; envelope encryption; redacted
  secret types; request IDs; safe errors; security headers; rate/body limits.
- Production Compose networks and reverse proxy with only `443/tcp` published.

Acceptance and tests:

- Unit tests cover crypto round-trip, wrong key/context, tampering, versioning,
  redaction, weak/missing configuration, token verification, and Argon2id rehash.
- Deployment test inspects published ports and proves PostgreSQL/application/
  metrics/debug endpoints are not host-accessible.
- A database-shaped fixture contains no plaintext secret or usable token.
- CSRF/origin, body limit, safe error, and security-header tests use the real router.

Exit gate: later features cannot persist or log an unprotected secret by using
an untyped string API.

### MVP-03 — PostgreSQL, migrations, tenancy, jobs, and audit base

Dependencies: MVP-02

Deliver:

- Migration locking, runtime/migration DB roles, transaction helper, typed SQL,
  workspace-scoped repository primitives, PostgreSQL jobs, audit event writer,
  health/readiness, structured logging, metrics hooks, and graceful shutdown.

Acceptance and tests:

- Real-PostgreSQL tests cover migration from empty DB, concurrent migration lock,
  rollback behavior where supported, transaction rollback, constraints, and job
  claim/retry/dead-letter semantics.
- Repository contract tests prove guessed IDs and wrong workspace never read,
  update, count, search, or delete data.
- Audit events are immutable and redact registered secret types.

Exit gate: no feature repository may be created outside the scoped transaction
and audit primitives.

### MVP-04 — Bootstrap, local authentication, MFA, and sessions

Dependencies: MVP-03

Deliver:

- Race-safe first-owner bootstrap, local login, TOTP for Owner/Administrator,
  recovery codes, secure cookie sessions, CSRF, logout/all-session revocation,
  recovery-code or local operator-assisted password reset, throttling, and
  authentication audit events. MVP recovery does not depend on email delivery.

Acceptance and tests:

- Unit tests cover password policy/hash/rehash, TOTP window, recovery-code
  one-time use, session rotation/expiry, and throttle state transitions.
- Router/integration tests cover bootstrap race, enumeration-safe errors, CSRF,
  fixation, revoked sessions, recovery replay, and secrets absent from logs/DB.
- E2E covers bootstrap, MFA enrollment, logout, login, and recovery.

Exit gate: no unauthenticated feature route or reusable recovery credential.

### MVP-05 — Workspaces, fixed RBAC, invitations, and project access

Dependencies: MVP-04

Deliver:

- Workspaces, invitations, memberships, fixed roles, restricted/public projects,
  direct project membership, authorization middleware plus application policies,
  and protected administration UI. Invitation links are shown once for secure
  out-of-band delivery; email invitation delivery is deferred.

Acceptance and tests:

- Table-driven unit tests cover every role/action pair in the MVP permission
  catalog and the intersection of role, project access, and credential scope.
- Integration tests cover cross-workspace/project ID guessing on get/list/count/
  search/update/delete, expired/replayed invitations, last-owner protection, and
  immediate revocation after role or membership change.
- Tester cannot reach users, roles, security, integration, credential, project-
  access, or project-settings administration through UI or direct API requests.

Exit gate: authorization matrix and negative tests pass before product data exists.

### MVP-06 — Generic OIDC login

Dependencies: MVP-05

Deliver:

- One generic discovery-based OIDC provider, authorization code with PKCE,
  explicit account linking, administrator configuration through encrypted secret
  storage, and optional local-login disablement with protected break-glass access.

Acceptance and tests:

- Protocol fixtures cover state, nonce, PKCE, issuer, audience, signature,
  algorithm, clock, redirect URI, verified-email linking, cancellation, and replay.
- Provider outage cannot lock out the protected break-glass owner.
- Configuration and tokens are never returned or logged in plaintext.

Exit gate: OIDC and local identities resolve to the same authorization principal.

### MVP-07 — Projects, suites, cases, revisions, and search

Dependencies: MVP-05

Deliver:

- Project CRUD/archive, nested suites, case quick/full authoring, essential fields,
  classic steps, tags, immutable revisions, optimistic concurrency, soft delete/
  restore, PostgreSQL text search/filter, and accessible repository UI.

Acceptance and tests:

- Unit tests cover suite-cycle prevention, case validation, status transitions,
  step ordering, revision creation, restore, and conflict policy.
- Integration tests cover uniqueness, ordering, transaction rollback, search
  authorization, stale version conflicts, soft-delete visibility, and tenancy.
- E2E covers project -> suite -> case -> edit -> history -> search -> restore.

Exit gate: a Tester can manage permitted cases but cannot alter project settings.

### MVP-08 — Encrypted local attachments

Dependencies: MVP-07

Deliver:

- Streaming upload/download for case and later result evidence, per-object
  encryption, metadata/checksum, quota/type/size policy, isolated download,
  reference-safe cleanup, and local encrypted volume.

Acceptance and tests:

- Storage contract tests cover round-trip, tampering, wrong workspace/key,
  traversal names, MIME mismatch, oversize, interrupted upload, duplicate content,
  unauthorized download, orphan cleanup, and shared-reference preservation.
- Raw blob volume and database fixtures contain no plaintext attachment content.

Exit gate: attachments are safe for use by subsequent execution features.

### MVP-09 — Plans, environments, and run creation

Dependencies: MVP-07

Deliver:

- Reusable plans, environments, express/configured runs, case selection, ordering,
  assignment, lifecycle, and immutable case-revision snapshots.

Acceptance and tests:

- Unit tests cover selection, duplicate prevention, state transitions, assignment,
  and snapshot rules.
- Integration tests prove later case edits/deletion cannot rewrite a run; creation
  is atomic and cross-project cases cannot enter the run.
- E2E covers selecting cases, creating a run, and seeing assigned immutable cases.

Exit gate: run history has a stable snapshot foundation.

### MVP-10 — Manual execution and internal defects

Dependencies: MVP-08, MVP-09

Deliver:

- Keyboard-usable runner, per-step and overall result, duration, comments,
  evidence, assignment/progress, append-only attempts, and basic internal defects
  linked from negative results. MVP result semantics cover passed, failed,
  blocked, skipped, and untested.

Acceptance and tests:

- Unit tests cover result/step transitions, overall-status calculation, immutable
  superseding attempts, progress, duration, and defect lifecycle.
- Integration tests cover concurrent submission, duplicate retry, permissions,
  evidence access, defect/result linking, and immutable history.
- E2E executes pass/fail/blocked cases, attaches evidence, files a defect, resumes
  the run, and completes it using keyboard navigation.

Exit gate: the complete manual testing loop works without administrator rights.

### MVP-11 — CI credentials and automation ingestion

Dependencies: MVP-08, MVP-09

Deliver:

- Project-scoped CI credentials with one-time display, expiry/rotation/revocation,
  automation run create/reuse, batched native JSON results, artifacts, heartbeat,
  finalize, idempotency, limits, and unmatched-result visibility.

Acceptance and tests:

- Unit tests cover credential scopes, mapping, result normalization, lifecycle,
  idempotency conflict, and partial-error semantics.
- Integration tests cover revoked/expired/wrong-project credentials, replay,
  concurrent batches, payload/artifact limits, rollback, and cross-tenant denial.
- Database dump contains only keyed credential verifiers; raw tokens never appear
  in logs, errors, jobs, audit metadata, or API responses after creation.

Exit gate: an automation client can safely complete a run through the public API.

### MVP-12 — JUnit parser, CLI, and CI examples

Dependencies: MVP-11

Deliver:

- Streaming bounded JUnit XML parser, statically distributed Go CLI, native JSON
  upload, stable machine-readable summary, run URL, and examples for GitHub
  Actions, GitLab CI/CD, Jenkins, and TeamCity.

Acceptance and tests:

- Parser unit/fuzz tests cover suites, retries, skipped/error cases, properties,
  stdout/stderr, malformed XML, entity expansion, encoding, duplicates, huge
  counts/text, and deterministic mapping.
- CLI integration tests use a real API server and prove test-process exit status
  is preserved independently from upload failure.
- Each CI example is syntax-validated and executes against a local fixture in CI;
  no example uses an administrator/provider token.

Exit gate: the four named CI systems have a documented, tested result-publishing
path even though outbound pipeline triggering remains deferred.

### MVP-13 — Essential reporting and export

Dependencies: MVP-10, MVP-11

Deliver:

- Run progress/status counts, pass rate, duration, manual/automated split, recent
  history, defect count, authorized filters, and CSV export.

Acceptance and tests:

- Unit tests cover zero/partial/complete runs, superseded attempts, skipped and
  untested semantics chosen in MVP-00, duration, and division/rounding boundaries.
- Real-PostgreSQL fixtures prove aggregates and exports cannot reveal inaccessible
  project rows, labels, counts, or users and remain correct under pagination.
- E2E checks dashboard values against the manual and automation runs created by
  prior journeys.

Exit gate: essential release status can be understood without raw database access.

### MVP-14 — Signed webhooks and Jira Cloud adapter

Dependencies: MVP-10, MVP-11, MVP-13

Deliver:

- Transactional outbox, signed outbound webhooks, delivery history/retry/dead
  letter, encrypted integration installation, Jira Cloud project allowlist,
  search/create/link issue, and one-way remote-to-local status reconciliation.

Acceptance and tests:

- Unit/contract tests cover signature input, idempotency, state normalization,
  loop/stale update protection, mapping, and retry/dead-letter policy.
- Integration tests cover SSRF/DNS rebinding/redirect denial, provider timeout,
  malformed/oversized response, rate limit, revoked credential, callback replay,
  secret rotation, uninstall, and cross-project mapping denial.
- Testers can use allowed issue linking but cannot install, configure, reveal,
  widen, rotate, or remove the integration.

Exit gate: the provider outage path cannot corrupt a test result or expose a secret.

### MVP-15 — Read-only MCP, production operations, and release

Dependencies: MVP-06, MVP-12, MVP-13, MVP-14

Deliver:

- Read-only MCP resources/tools for scoped project context, cases, runs, results,
  reports, and defects using a distinct hashed/revocable MCP credential.
- Production Compose, migrations-on-start with lock, backup/restore, upgrade and
  rollback instructions, protected diagnostics, SBOM, signed/checksummed image,
  and operator runbook.

Acceptance and tests:

- MCP contract tests cover discovery, pagination, bounded responses, role/scope/
  project denial, revoked token, injection-shaped input, and audit attribution.
- Fresh-install E2E traverses bootstrap -> role/invite -> project/case -> manual
  run/defect -> CI upload -> report -> webhook/Jira link -> MCP read.
- Restore drill recreates the service from database, encrypted blobs, and external
  keys; restore without keys fails closed and reveals no data.
- Port scan/container inspection confirms only TLS 443 is published and the image
  meets runtime-hardening rules.
- All gates in `TESTING_POLICY.md` pass with no skips, flakes, unexplained golden
  changes, high/critical findings, or undocumented exceptions.
- The GitHub Actions workflow, including the `docs` and `gate-selftest` jobs,
  has run green on GitHub for the release commit (moved from MVP-00/MVP-01 by
  amendment).

Exit gate: tag MVP only after the full clean-install and restore journeys pass.

## 5. MVP security coverage matrix

| Control | Introduced | Re-verified by |
|---|---|---|
| Secret/key separation and encryption | MVP-02 | every credential/file item, MVP-15 restore |
| Minimal network exposure | MVP-02 | MVP-14 egress, MVP-15 port inspection |
| Tenant-scoped persistence and audit | MVP-03 | every domain integration test |
| Strong authentication/session controls | MVP-04/MVP-06 | every privileged route |
| RBAC/project/scope intersection | MVP-05 | every feature/API/MCP item |
| Attachment isolation | MVP-08 | manual and automation evidence |
| Machine credential separation | MVP-11 | CLI and MCP items |
| SSRF/replay/provider isolation | MVP-14 | release E2E and security gate |
| Supply-chain/runtime hardening | MVP-01/MVP-02 | MVP-15 release artifacts |

No row may be postponed to MVP-15. The last item re-verifies controls; it does
not introduce them for the first time.

## 6. MVP completion definition

MVP is complete only when all items are closed in order, every acceptance map is
present, all security controls are exercised, clean install and restore succeed,
and the full suite is green without weakening tests. Feature count, screenshots,
or a manually successful demo do not override a failed automated gate.

