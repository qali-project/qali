# Qali Implementation Plan

Status: proposed baseline  
Audience: maintainers and implementation agents  
Product target: a production-ready open-source platform delivered in secure,
deployable increments with a low-friction self-hosted deployment

This is the full post-MVP roadmap. Active implementation order, scope limits,
and release gates are defined in `docs/MVP_PLAN.md`. Agents must not select work
directly from this document until the MVP is complete or the MVP plan explicitly
references the item.

Normative companion documents:

- `docs/PRODUCT_SCOPE.md` defines the complete capability target.
- `docs/INTEGRATIONS.md` defines provider priorities and adapter contracts.
- `docs/SECURITY_ARCHITECTURE.md` defines mandatory security controls.
- `docs/RBAC.md` defines principals, roles, permissions, and sensitive actions.

## 1. Product principles

1. **Useful before broad.** Ship a complete manual and automated testing loop
   before adding a marketplace of integrations.
2. **One binary, one database.** The default release is a Go binary containing
   the API, worker, MCP endpoint, migrations, and embedded web assets. PostgreSQL
   is the only mandatory external service.
3. **API first.** The web UI, CLI/reporters, MCP tools, and integrations use the
   same versioned application services and authorization policies.
4. **Secure multi-tenancy.** Workspace isolation and least privilege are
   invariants, even for single-user installations.
5. **Replaceable edges.** Identity, blob storage, outbound mail, and issue
   trackers are ports around a modular monolith.
6. **Upgrade without fear.** Releases include migrations, backups guidance,
   health checks, and rollback notes.

## 2. Delivery scope

### Complete product target

- Organization, identity, groups, granular roles, project access, OIDC/SAML,
  MFA/WebAuthn, SCIM, sessions, human and machine credentials.
- Full test repository: suites, cases, classic/BDD/nested/shared steps, local and
  shared parameters, revisions, reviews, comments, attachments, custom fields,
  bulk operations, trash, import, and multi-format export.
- Planning and execution: plans, express/configured/scheduled runs, environments,
  configuration matrices, milestones, assignment, manual runner, retest, defects,
  immutable attempts, and mixed manual/automated runs.
- Automation ingestion, multiple result formats, CLI, reporter contract, CI/CD
  templates, source/build links, and optional pipeline triggering.
- Requirements, traceability matrices, structured search/query language, saved
  views, built-in and custom dashboards, reports, notifications, and audit.
- Provider catalog for issue/source/CI/chat/knowledge systems, including native
  Jenkins, TeamCity, GitHub Actions, GitLab CI/CD, Azure Pipelines, Bitbucket
  Pipelines, Jira, Asana, Linear, and other prioritized adapters; signed
  webhooks, complete REST API, and scoped read/write MCP.
- Opt-in external AI integration boundary without embedded AI product features.
- Secure Docker Compose and Helm deployments, backup/restore, upgrade testing,
  observability, key management, and release hardening.

The detailed inventory and cross-cutting behavior are in `PRODUCT_SCOPE.md`.
Implementation is staged by dependency and risk; staged does not mean omitted.

### Deliberately excluded

- Embedded AI generation/advice, generated test code, AI-operated cloud test
  execution, and automatic AI data sharing.
- Subscription billing, seat licensing, plan gates, and a hosted multi-region
  control plane; these are service-business concerns, not self-hosted features.
- Arbitrary in-process user plugins and unnecessary microservices. Integrations
  use compiled adapters or constrained out-of-process protocols.
- Real-time character-level collaborative editing until revisioned optimistic
  concurrency proves insufficient.

## 3. User journeys that define success

1. An administrator starts Qali, creates the first workspace, configures strong
   authentication, invites/groups teammates, assigns least-privilege roles, and
   creates a restricted project without exposing an administrative port.
2. A tester organizes suites and cases, performs a manual run, attaches evidence,
   links a defect, and exports a report.
3. CI creates or reuses a run, uploads JUnit results and artifacts, finalizes the
   run, and receives a stable URL and machine-readable summary.
4. A maintainer configures a signed webhook and an issue provider, can retry
   failures, and can audit every privileged change.
5. An MCP client discovers project/case/run resources and invokes scoped tools
   without bypassing normal authorization.
6. An operator upgrades the container after taking a database backup and can
   verify readiness, migration status, and worker health.
7. A QA lead reviews case changes, schedules regression runs, traces requirements
   to current results, and publishes a release-readiness dashboard.
8. An administrator enables an external AI integration for selected read-only
   projects and can prove which fields and actions were exposed.

## 4. Technical architecture

### 4.1 Runtime topology

```text
Browser / CLI / MCP / callbacks
                |
                | TLS :443 (the only default published port)
                v
         reverse proxy
                |
         private network
                v
 Go process: web + REST + OAuth + MCP + worker
                |
          +-----+--------------------+
          |                          |
 PostgreSQL (private)       encrypted local/S3 blobs
```

The process supports `QALI_MODE=all|api|worker` so larger installations can scale
API and worker replicas independently without changing the codebase.

### 4.2 Backend

- Go modular monolith, one Go module, `net/http` compatible router.
- Baseline libraries: `chi` for routing, `pgx` for PostgreSQL, `sqlc` for typed
  queries, and `goose` for migrations. Pin exact versions in the module lock and
  replace a choice only through an ADR with a migration cost assessment.
- Modules: identity, workspaces, projects, cases, reviews, plans, runs,
  automation, requirements, defects, files, search, dashboards, notifications,
  integrations, audit, reporting, and MCP.
- PostgreSQL migrations plus explicit, type-checked queries. Transactions are
  owned by application use cases.
- REST JSON API under `/api/v1`; OpenAPI 3.1 is the contract. Cursor pagination,
  stable error codes, request IDs, and optimistic concurrency (`version`/ETag).
- PostgreSQL-backed job table using `FOR UPDATE SKIP LOCKED`, bounded retries,
  exponential backoff, dead-letter state, and an admin retry action.
- PostgreSQL full-text/trigram search first. Revisit a dedicated search engine
  only after measured need.
- Server-sent events may update run progress; polling remains supported.

### 4.3 Frontend

- React + TypeScript + Vite SPA embedded into the production Go binary.
- React Router, TanStack Query, React Hook Form with Zod at form boundaries,
  Tailwind CSS tokens, and Radix-based accessible primitives. Vitest plus React
  Testing Library cover components and Playwright covers critical journeys.
- Route-level feature folders, generated API client, query cache for server
  state, and lightweight local state. Do not add a global state framework until
  a concrete cross-route state problem requires it.
- Core screens: sign-in/bootstrap, workspace/project navigation, case tree and
  editor, run dashboard and execution view, reports, integrations, tokens,
  members, audit, and system settings.
- Rich case content is stored as a versioned, sanitized JSON document with a
  plain-text projection for search/export. Do not persist arbitrary HTML.

### 4.4 Identity and authorization

- Bootstrap local administrator is enabled only until initial setup completes.
- Generic OIDC authorization-code flow with PKCE. Provider discovery and strict
  issuer/audience/nonce/state validation are required. Google is documented as
  an OIDC example; GitHub login uses a small OAuth 2 provider adapter because
  GitHub does not offer generic end-user OIDC login.
- Browser authentication uses secure, HTTP-only, same-site cookies and CSRF
  protection. Passwords use Argon2id plus a pepper held outside PostgreSQL.
- SAML 2.0, WebAuthn/MFA, enforced SSO, groups, and SCIM 2.0 are later delivery
  increments but first-class parts of the identity model.
- RBAC supplies broad roles; resource policies enforce workspace/project scope.
  Authorization decisions live in application services and are reused by HTTP,
  jobs, and MCP.
- Token values are shown once; only keyed verifiers and metadata are stored.
  Recoverable provider credentials use envelope encryption with the KEK outside
  PostgreSQL. A database dump alone must not disclose usable credentials.
- The built-in MCP authorization server is a separate boundary: authorization
  code with PKCE, explicit consent, short-lived audience-bound access tokens,
  rotating refresh tokens, client metadata, revocation, and narrowly named MCP
  scopes. It delegates human authentication to the existing browser session but
  never treats a session cookie as an MCP bearer token.

### 4.5 MCP boundary

- Use the official Go MCP SDK and Streamable HTTP. Pin a tested protocol version
  per release and publish compatibility in release notes.
- Treat the MCP endpoint as another adapter over application services, never as
  a direct database interface.
- Initial resources: workspace/project metadata, case details, suite contents,
  run status, and result summaries.
- Initial tools: search/list/get/create/update test cases; create/finalize runs;
  submit results; add comments; link defects. Destructive bulk operations wait
  until explicit confirmation semantics and audit UX are defined.
- Every tool declares read/write behavior, validates bounded input, returns
  structured output, applies normal RBAC, and emits audit/request IDs.
- Remote access uses OAuth-compatible bearer authorization and protected
  resource metadata. Static scoped tokens remain available for controlled CI
  use, not as an OAuth substitute for general MCP clients.

### 4.6 Data model outline

All tenant-owned tables include `workspace_id`, timestamps, creator/updater, and
where applicable `deleted_at` and `version`.

```text
users --< identities / sessions / authenticators
workspaces --< memberships >-- users
workspaces --< groups --< group_memberships
workspaces --< roles --< role_permissions
workspaces --< projects --< project_access
projects --< suites (parent_id) --< test_cases --< case_revisions --< case_steps
workspaces/projects --< shared_steps / shared_parameters
test_cases --< reviews --< review_decisions
projects --< requirements / defects / milestones / environments / configurations
projects --< test_plans --< plan_cases
projects --< test_runs --< run_cases --< result_attempts --< result_steps
test_cases/results/requirements/defects --< attachments
test_runs --< automation_imports / scheduled_run_templates
workspaces --< saved_queries / dashboards / notifications
projects --< integration_installations --< delivery_attempts
workspaces --< credentials / oauth_grants / webhooks / audit_events
```

Important invariants:

- A run case snapshots the selected case revision so later edits cannot rewrite
  historical results.
- A result is append-only; a current-result pointer supports fast display.
- Idempotency keys are unique within credential and endpoint scope.
- File metadata and authorization live in PostgreSQL; content lives behind the
  blob-store port.
- Audit records are append-only and redact secret values.
- Secret-bearing records contain ciphertext and key metadata only; password and
  bearer-token material is non-recoverable without an external pepper/KEK.

## 5. Repository shape

```text
api/openapi.yaml
cmd/qali/
internal/platform/{config,db,httpserver,jobs,logging,metrics,storage}/
internal/{identity,workspaces,projects,cases,reviews,runs,automation,requirements,defects,search,dashboards,notifications,integrations,audit,mcp}/
migrations/
web/src/{app,components,features,generated}/
deploy/{compose,helm}/
docs/{adr,api,operations}/
test/{integration,e2e,fixtures}/
```

## 6. Delivery phases and agent work items

Work item IDs are stable coordination handles. Items in the same wave may run in
parallel only after their listed dependencies are complete.

### Wave 0 — decisions and foundation

#### FND-01 Repository skeleton and quality gates

Dependencies: none

Deliver:

- Go and React/TypeScript workspaces, Makefile, local development Compose file,
  formatting/lint/test/build commands, dependency update policy, and license.
- Multi-stage container build producing a non-root, minimal runtime image.
- CI for generated-file checks, unit tests, integration tests, frontend checks,
  container build, and vulnerability/license scanning.

Acceptance:

- A clean checkout passes all five commands documented in `AGENTS.md`.
- `docker compose up` serves a placeholder UI and `/health/live`.
- The default Compose topology publishes only reverse-proxy port 443; PostgreSQL
  and application-internal listeners have no host port mapping.
- Builds are reproducible and do not require credentials.

#### FND-02 Architecture records and API conventions

Dependencies: none

Deliver ADRs for modular monolith, PostgreSQL jobs, storage abstraction, auth
model, case document format, and API/error/pagination conventions. Create the
OpenAPI skeleton and generation checks.

Acceptance:

- A sample endpoint is generated into a typed frontend client.
- CI fails when generated code differs from the contract.

#### FND-03 Database and observability platform

Dependencies: FND-01

Deliver migration runner with advisory lock, transaction helpers, request IDs,
structured logs, metrics, tracing hooks, health/readiness endpoints, graceful
shutdown, and the job engine.

Acceptance:

- Two replicas cannot race migrations or claim the same job.
- Readiness distinguishes database and migration failures.
- Job retry/dead-letter behavior has integration tests.

#### FND-04 Cryptography and secret platform

Dependencies: FND-01, FND-02

Deliver the typed secret API, external pepper/KEK loading, Argon2id password
service, keyed bearer-token verifier, envelope encryption, key versioning,
redaction types, rotation tooling, and test fixtures described in
`SECURITY_ARCHITECTURE.md`.

Acceptance:

- A database dump and blob-volume copy contain no reusable password, token,
  provider credential, signing key, or plaintext attachment content.
- Missing/weak key material fails closed with an actionable startup error.
- Rotation, corrupted ciphertext, wrong workspace context, and redaction have
  unit and integration tests; no test uses production-style static secrets.

### Wave 0.5 — security perimeter

#### SEC-01 Minimal network and hardened runtime

Dependencies: FND-01, FND-03

Acceptance:

- Automated deployment tests prove that only TCP 443 is published by default.
- PostgreSQL, metrics, debug/profiling, health details, workers, and administration
  have no public listener; privileged diagnostics require RBAC and recent MFA or
  a local operator command.
- The image runs non-root with read-only root filesystem, dropped capabilities,
  no-new-privileges, resource limits, and explicit writable paths.

#### SEC-02 HTTP, egress, upload, and audit defenses

Dependencies: FND-03, FND-04

Acceptance:

- Shared middleware enforces security headers, origin/CSRF policy, body limits,
  deadlines, safe errors, rate limits, request IDs, and secret redaction.
- Egress rejects private/link-local/metadata destinations, DNS rebinding and
  unsafe redirects unless an administrator explicitly allowlists a private host.
- Upload quarantine and content policy plus append-only audit events pass abuse,
  fuzz, cross-tenant, and tamper-evidence tests.

### Wave 1 — identity and tenancy

#### IAM-01 Bootstrap, sessions, and local identity

Dependencies: FND-02, FND-03, FND-04, SEC-02

Acceptance:

- First-run bootstrap is one-time and race-safe.
- Login, logout, rotation, expiry, CSRF, lockout/rate limits, and secret redaction
  have integration tests.

#### IAM-02 OIDC providers

Dependencies: IAM-01

Acceptance:

- Discovery, PKCE, state, nonce, issuer, and audience checks are tested.
- Account linking cannot be triggered solely by an unverified email claim.
- Generic OIDC configuration includes a Google example. GitHub login is an
  isolated OAuth 2 adapter and introduces no provider-specific domain code.

#### IAM-03 Workspaces, membership, and RBAC

Dependencies: IAM-01

Acceptance:

- Owners can invite, revoke, and change roles without removing the last owner.
- A table-driven policy suite covers every role and action.
- Cross-workspace access tests cover reads, writes, searches, and guessed IDs.
- Built-in roles and sensitive-operation step-up match `RBAC.md`; the Tester role
  cannot access workspace/project administration, roles, integrations, or tokens.

#### IAM-04 API and CI tokens

Dependencies: IAM-03

Acceptance:

- Tokens have scopes, optional project restriction, expiry, last-used metadata,
  rotation/revocation, one-time display, and rate limits.

#### IAM-05 OAuth 2.1 authorization for MCP clients

Dependencies: IAM-02, IAM-03

Acceptance:

- Authorization code with PKCE, consent, refresh rotation/reuse detection,
  revocation, protected-resource and authorization-server metadata, audience,
  and scope enforcement pass protocol and negative security tests.
- Client registration/metadata behavior follows the MCP protocol version pinned
  by the release; unsupported clients receive actionable standards-based errors.
- OAuth access tokens cannot be used as browser sessions or CI tokens, and no
  credential type can be exchanged implicitly for another.

#### IAM-06 Groups, MFA, SAML, and SCIM

Dependencies: IAM-02, IAM-03, FND-04

Acceptance:

- WebAuthn/TOTP enrollment, recovery, enforcement, step-up, and administrator
  reset are protected against account takeover and fully audited.
- SAML validation covers signatures, audience/destination, time bounds, replay,
  enforced SSO, and a protected break-glass path.
- SCIM 2.0 user/group lifecycle and group-to-project mapping are idempotent;
  deprovisioning immediately revokes sessions/grants but preserves attribution.

### Wave 2 — test repository

#### CASE-01 Projects and navigation

Dependencies: IAM-03, FND-02

Acceptance: authorized CRUD, archive/restore, stable project codes, searchable
project list, and complete empty/loading/error UI states.

#### CASE-02 Suites and case CRUD

Dependencies: CASE-01

Acceptance:

- Nested suites support move/reorder without cycles.
- Cases support draft/active/deprecated status, priority, type, behavior, tags,
  preconditions, structured steps, expected result, and optimistic concurrency.
- Bulk move/tag/status operations are atomic or return per-item errors.

#### CASE-03 Revisions, custom fields, and reusable steps

Dependencies: CASE-02

Acceptance:

- Every meaningful case edit creates an attributable immutable revision.
- Revision diff/restore works; custom field schemas validate on write.
- Reusable-step revisions are snapshotted by consuming cases.
- Classic, BDD, nested, project-shared and workspace-shared steps plus local and
  shared parameter groups follow the propagation/detach rules in the product scope.

#### CASE-04 Files, import, and export

Dependencies: CASE-02, FND-03

Acceptance:

- Local and S3-compatible storage pass one contract test suite.
- Upload size/type policy, authorized download, checksum, orphan cleanup, and
  path traversal protections are tested.
- CSV and a documented JSON interchange format provide dry-run import and
  deterministic export.

#### CASE-05 Review, trash, and complete interchange

Dependencies: CASE-03, CASE-04, IAM-03

Acceptance:

- Optional/mandatory review supports version-aware approvals, change requests,
  merge/decline/reopen, defaults, self/auto-merge policy, comments, notification
  events, API coverage, and immutable audit.
- Soft-deleted repository content can be restored before retention expiry;
  permanent purge requires elevated permission and recent strong authentication.
- CSV, XLSX, XML, JSON, PDF, and HTML export plus supported import formats are
  deterministic, bounded, authorized, asynchronous where needed, and explicit
  about lossy fields.

### Wave 3 — execution and automation

#### RUN-01 Plans, configurations, and run creation

Dependencies: CASE-03

Acceptance:

- Selection by case/suite/filter creates immutable run-case snapshots.
- Environments, configurations, milestones, assignees, and plan reuse work.

#### RUN-02 Manual execution

Dependencies: RUN-01, CASE-04

Acceptance:

- Authorized users record per-step and overall status, duration, comment,
  and evidence.
- Concurrent updates produce an explicit conflict rather than lost data.
- Keyboard-first next/previous execution is covered by an end-to-end test.

#### AUTO-01 Automation ingestion API

Dependencies: RUN-01, IAM-04

Acceptance:

- CI can create/reuse a run, submit batched results, upload artifacts, and
  finalize it with idempotency keys.
- Mapping by stable automation ID is deterministic; unmatched tests are visible
  and recoverable rather than silently discarded.
- Backpressure, payload limits, partial failures, and retry semantics are
  documented and tested.

#### AUTO-02 CLI and JUnit reporter

Dependencies: AUTO-01

Acceptance:

- A statically distributed CLI uploads JUnit XML and emits both a run URL and a
  machine-readable summary.
- GitHub Actions and generic CI examples handle failed test commands while still
  publishing results.

#### RUN-03 Reporting

Dependencies: RUN-02, AUTO-01

Acceptance: run progress, pass/fail/blocked rate, duration, history, and flaky
candidate queries are correct on seeded datasets and have CSV export.

#### RUN-04 Scheduled runs and execution completeness

Dependencies: RUN-02, FND-03

Acceptance:

- Timezone-aware schedules support preview, pause/resume, edit-future-only,
  missed-run policy, bounded catch-up, and immutable generated-run history.
- Express runs, mixed manual/automated results, configuration/parameter sibling
  navigation, bulk result/assignment, clone-by-filter, and rerun-failed have E2E
  coverage.

#### DEF-01 Internal defects and result linking

Dependencies: RUN-02, CASE-04, IAM-03

Acceptance:

- Authorized users create or link a defect from a negative result and manage its
  lifecycle, severity, assignee, comments, attachments, and related attempts.
- Defect updates never rewrite result history; removal of a link preserves audit
  attribution and does not delete either entity.
- Project access, role permissions, notifications events, search, bulk limits,
  and cross-workspace isolation have integration and E2E coverage.

#### AUTO-03 Reporter and result-format ecosystem

Dependencies: AUTO-01, AUTO-02, IAM-04

Acceptance:

- Native JSON, JUnit, Allure, and XCTest ingestion share fixtures and semantics.
- Reporter SDK contract and the P0 framework adapters in `INTEGRATIONS.md`
  preserve test command exit status, retry safely, and expose no long-lived
  administrator or provider credential.
- Every native reporter passes the shared event-protocol conformance fixtures;
  framework adapters do not duplicate server-side run lifecycle logic.

### Wave 4 — governance and insight

#### GOV-01 Requirements and traceability

Dependencies: CASE-05, DEF-01, RUN-03

Acceptance:

- Hierarchical requirements implement the product scope, including case,
  result, defect, and external requirement links.
- Versioned traceability matrices show coverage, latest authorized result,
  defects, gaps, and stale results with CSV/PDF export.

#### GOV-02 Query language, saved views, and dashboards

Dependencies: RUN-03, IAM-03

Acceptance:

- The documented read-only language supports bounded filters, time functions,
  grouping and aggregates without raw SQL or unbounded scans.
- Saved queries and dashboard widgets are private/shared and apply row-level
  authorization before counts, grouping, export, and cache population.

#### COL-01 Comments and notifications

Dependencies: CASE-05, DEF-01, GOV-01, RUN-02, FND-03

Acceptance:

- Comments/mentions and in-app/email notifications cover the event inventory,
  preferences, digest/quiet hours, retries and bounce visibility.
- Revoked access removes notification content immediately; previews and email
  never leak secret or inaccessible fields.

### Wave 5 — integrations and MCP

#### INT-01 Webhooks and delivery operations

Dependencies: FND-03, FND-04, SEC-02, IAM-03, IAM-04

Acceptance:

- Versioned events use an outbox transaction, signed delivery, bounded retries,
  replay protection guidance, delivery logs, secret rotation, and manual retry.

#### INT-02 Issue provider framework

Dependencies: RUN-02, DEF-01, GOV-01, INT-01

Acceptance:

- Provider contract supports search/create/link/unlink with encrypted secrets.
- Jira Cloud/Data Center, Azure DevOps Boards, GitHub Issues, GitLab Issues,
  Asana, and Linear are P0. YouTrack and Redmine are P1. All pass the shared
  capability/security contract; provider failures never corrupt a test result.
- Installation, repository/project mapping, least provider scopes, secret
  rotation, inbound replay protection, and status-sync loop protection are tested.

#### INT-03 Integration catalog and collaboration providers

Dependencies: INT-01, INT-02, IAM-03

Acceptance:

- The catalog supports install/configure/health/rotate/disable/remove and per-
  project external-resource mappings without exposing stored credentials.
- Slack, Microsoft Teams, Confluence, and Notion adapters implement only the
  bounded capabilities and least-scope rules in `INTEGRATIONS.md`.
- Community adapter compatibility tests and a security review checklist are
  published; arbitrary adapters cannot execute inside the main process.

#### INT-04 CI/CD provider integrations

Dependencies: INT-01, AUTO-03, IAM-03, IAM-04

Acceptance:

- P0 adapters cover GitHub Actions, GitLab CI/CD, Jenkins, TeamCity, Azure
  Pipelines, and Bitbucket Pipelines. Each supports project mapping, discovery,
  authorized trigger, normalized status/link synchronization, health, rotation,
  disable, and uninstall as described in `INTEGRATIONS.md`.
- Result upload uses a separate project CI credential; a provider installation
  token is never exposed to a pipeline, browser, or ordinary tester.
- Pipeline triggering is off by default, separately permissioned, idempotent,
  parameter-schema validated, secret-redacting, allowlisted, and fully audited.
- Callback-capable providers verify signature and replay data; other providers
  use bounded polling with backoff and a terminal timeout.
- P1 adapters for CircleCI, Buildkite, and Bamboo follow the same contract but do
  not block the core release.

#### MCP-01 Read-only MCP server

Dependencies: CASE-03, RUN-03, IAM-04

Acceptance:

- Streamable HTTP discovery plus list/search/get resources and tools work with
  at least two independent MCP clients.
- Every request is scoped, paginated, bounded, observable, and protected by the
  same policies as REST.

#### MCP-02 Write tools and OAuth resource protection

Dependencies: MCP-01, IAM-05, AUTO-01

Acceptance:

- Scoped tools create/update cases and runs and submit results with structured
  responses and idempotency.
- Protected resource metadata and bearer challenges interoperate with a
  standards-compliant client; permission-denied paths are tested.
- Tool actions appear in the audit log with actor, client, scope, and request ID.

#### MCP-03 Complete governed tool surface

Dependencies: MCP-02, DEF-01, GOV-01, GOV-02

Acceptance:

- Resources and bounded tools cover cases, suites, shared assets, reviews, plans,
  runs/results, requirements, defects, milestones, environments, fields, search,
  traceability, and composite CI/triage/regression workflows.
- Compact discovery avoids schema explosion; there is no generic REST/SQL escape
  hatch. Destructive/bulk tools require explicit scope, confirmation and audit.

#### AI-01 External AI integration controls

Dependencies: MCP-03, INT-01, IAM-03

Acceptance:

- Fresh installations have AI egress disabled. Administrators explicitly select
  provider endpoint/model, projects, fields, operations, retention, and approvers.
- Field-level redaction excludes secrets, private comments, user email, audit
  details, attachments, and integration payloads by default.
- AI output is provenance-marked and validated as untrusted input; high-risk or
  bulk writes require human review. Audit metadata is useful without storing
  prompts/responses by default.

### Wave 6 — release hardening

#### OPS-01 Production Compose and first-run UX

Dependencies: SEC-01, SEC-02, all Wave 3 items, INT-01

Acceptance:

- One documented command starts pinned application and PostgreSQL images with
  health checks, restart policies, named volumes, secret/config examples, and no
  source bind mounts.
- Reverse-proxy/TLS examples exist for Caddy and nginx.
- Only reverse-proxy port 443 is published; key/pepper material is mounted as
  secret files, and PostgreSQL is isolated on a private internal network.
- Fresh-install smoke test reaches setup, creates a project/case/run, and uploads
  an automated result.

#### OPS-02 Backup, restore, upgrade, and diagnostics

Dependencies: OPS-01

Acceptance:

- Documented database/blob backup and restore is exercised in CI.
- Upgrade tests cover the oldest supported release to current, including a
  failed migration rehearsal and rollback procedure.
- Admin diagnostics show build version, migration state, worker backlog, storage
  reachability, and sanitized configuration.

#### OPS-03 Helm and external services

Dependencies: OPS-02

Acceptance:

- Helm supports external PostgreSQL, external S3, separate API/worker replicas,
  ingress, probes, resource requests, pod disruption, and migration jobs.
- Chart install/upgrade is tested on a local Kubernetes cluster.

#### REL-01 Security, performance, accessibility, and release

Dependencies: all v1 items

Acceptance:

- Threat model covers database compromise, tenant isolation, OAuth/OIDC/SAML,
  SCIM, credential/key handling, uploads, webhooks, SSRF, stored content, MCP,
  external AI egress, backup/restore, and supply chain.
- No unresolved critical/high dependency or container findings without a written
  exception.
- Representative p95 latency and ingestion throughput budgets pass; database
  query plans are captured for critical lists/reports.
- Critical flows meet WCAG 2.2 AA automated checks plus a keyboard/screen-reader
  manual checklist.
- Release includes SBOM, signed image/artifacts, checksums, changelog, migration
  notes, support policy, and a clean-install verification.

## 7. Dependency graph

Each work item's `Dependencies` field is authoritative. This graph shows the
delivery-level critical paths without pretending that every item in a wave is
strictly sequential.

```text
Foundation -> Security perimeter -> Identity/RBAC -> Repository
Repository -> Manual execution -> Internal defects -> Governance/traceability
Repository + Identity/RBAC -> Automation ingestion -> Reporters
Security + Identity/RBAC -> Webhook/provider platform
Governance + provider platform -> Work-management and collaboration adapters
Reporters + provider platform -> Native CI/CD adapters
Repository + Reporting + OAuth -> MCP -> External AI controls
Secure core -> Compose -> Backup/upgrade -> Helm -> Release hardening
```

## 8. Parallel agent allocation

After Wave 0, use feature lanes with one integration owner:

| Lane | Owns | Avoids |
|---|---|---|
| Platform | FND, jobs, observability, deployment | Feature UI/domain policy |
| Identity | IAM and shared authorization tests | Project/case/run schema |
| Repository | CASE backend and frontend | Session/token internals |
| Execution | RUN/AUTO backend, UI, CLI | Integration provider secrets |
| Extensions | INT/MCP/AI | Direct feature-table access |

At wave boundaries, the integration owner runs the full suite, resolves contract
drift, regenerates clients, and creates a deployable checkpoint. Do not allocate
two agents to migrations touching the same aggregate in the same wave.

## 9. Testing strategy

- **Unit:** domain policies, validators, parsers, status transitions, mapping.
- **Integration:** real PostgreSQL and storage contract tests; HTTP auth and
  tenancy; migration forward/compatibility; job locking; OAuth fixtures.
- **Contract:** OpenAPI request/response validation, integration provider
  contracts, CI trigger/status normalization, reporter conformance, MCP client
  compatibility, webhook fixtures, and CLI/API compatibility.
- **End to end:** bootstrap/login, author case, manual run, CI upload, webhook,
  MCP read/write, backup/restore, and upgrade.
- **Property/fuzz:** importers, structured case documents, filter expressions,
  webhook/MCP payloads, and identifier parsing.
- **Performance:** large suite navigation, filtered case search, run with many
  results, concurrent CI uploads, and reporting queries.

Every bug fix begins with a regression test at the lowest meaningful layer.

## 10. Deployment contract

### Required configuration

- `QALI_PUBLIC_URL`
- `QALI_DATABASE_URL_FILE` or discrete PostgreSQL secret-file fields
- application KEK and password/token pepper supplied as separate mounted secret
  files; production rejects example/default values

### Optional configuration

- OIDC issuer/client credentials
- SAML metadata/certificate and SCIM policy
- SMTP settings
- local blob directory or S3 endpoint/bucket/credentials
- Vault/KMS provider and key identifier
- OpenTelemetry endpoint and log level
- trusted reverse-proxy and upload/retention limits

### Container behavior

- Runs as non-root with a read-only root filesystem where the platform permits.
- Writes only to the configured local blob/temp paths.
- Listens on one private HTTP socket for web, API, OAuth callbacks, and MCP.
  Liveness/readiness use private probes. Metrics/build/diagnostics require
  operator authorization and are never published on a separate host port.
- Handles termination gracefully; stops accepting traffic before draining work.
- Automatic migrations are safe for single-host installs. Cluster deployments
  use an explicit migration job.

### Release support

- Semantic versioning for the product and `/api/v1` compatibility policy.
- Support upgrades from at least the previous minor release; expand after v1.
- Deprecations are announced in API headers, documentation, and release notes.
- PostgreSQL support window and tested browser matrix are published per release.

## 11. Post-MVP roadmap milestone cut lines

These milestones are inactive while `docs/MVP_PLAN.md` is in progress. They are
retained only to sequence the broader product after the MVP release.

- **M0 Secure developer preview:** foundation, cryptography, network perimeter,
  IAM-01/IAM-03, and CASE-01/CASE-02.
- **M1 Manual testing alpha:** CASE-03/CASE-04, reviews, RUN-01/RUN-02, defects,
  baseline reports, and production Compose smoke tests.
- **M2 Automation beta:** IAM-04, AUTO-01/AUTO-02, RUN-03/RUN-04, signed
  webhooks, notifications, and CI templates.
- **M3 Governance beta:** IAM-02/IAM-06, requirements/traceability, query language,
  saved views, dashboards, retention, and audit export.
- **M4 Ecosystem release candidate:** P0 CI/CD and work-management providers,
  Slack/Teams and knowledge links, reporter ecosystem, complete MCP with IAM-05,
  and opt-in external AI controls.
- **v1.0:** all scope marked for the release and Wave 6 hardening are complete;
  no acceptance criterion or security gate is waived silently.

## 12. Decisions required before implementation starts

Resolve these in FND-01/FND-02 and record them as ADRs:

1. Project name, module path, license (Apache-2.0 is the proposed default), and
   governance/security-reporting policy.
2. The structured case editor implementation. The baseline libraries above are
   decided; replacements require an ADR rather than parallel framework spikes.
3. Supported PostgreSQL and browser versions.
4. Whether local password login remains available after OIDC is configured.
5. Data retention defaults for audit, artifacts, and soft-deleted assets.
6. Public API compatibility and extension/provider stability guarantees.

Until these decisions are recorded, agents may build spikes but must not commit
competing frameworks or irreversible schemas.

