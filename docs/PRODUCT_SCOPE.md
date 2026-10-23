# Product Scope and Capability Decomposition

Status: product baseline  
Audience: product, design, architecture, and implementation agents

## 1. Product boundary

Qali is an open-source quality management workspace for designing tests, running
manual and automated validation, connecting results to requirements and defects,
and exposing the same governed workflows to humans, CI systems, integrations,
and MCP clients.

The product includes a broad integration surface for external AI assistants but
does not include an embedded AI authoring, analysis, code-generation, or cloud
test-execution product. AI providers receive no data unless an administrator
installs and explicitly scopes an integration.

Commercial subscription billing, seat metering, and plan-gated product behavior
are outside the self-hosted product boundary. Usage and storage visibility are
included for operations, not billing.

## 2. Capability map

### 2.1 Organization and identity

- Organizations/workspaces with isolated data, settings, and audit history.
- Users, invitations, deactivation/reactivation, ownership transfer, groups, and
  group-based project access.
- Local bootstrap, local login when enabled, generic OIDC, SAML 2.0, enforced
  SSO, domain discovery, session policy, MFA/WebAuthn, recovery codes, and
  emergency break-glass access.
- SCIM 2.0 users and groups for provisioning, deprovisioning, and access mapping.
- Built-in and custom roles with granular create/read/update/delete/execute/
  configure/admin permissions.
- Public and private projects. Effective access is always the intersection of
  workspace role, project membership, group membership, and token scope.
- Personal API tokens, project CI credentials, service accounts, OAuth clients,
  and MCP grants with separate lifecycles and scopes.
- User profile, locale/timezone, notification preferences, active sessions, and
  credential revocation.

### 2.2 Project and test repository

- Projects with stable codes, visibility, members/groups, defaults, repository
  policy, result policy, automation behavior, and project-level integrations.
- Nested suites/folders with drag/reorder, move, clone, archive, and bulk action.
- Quick case capture and full case authoring.
- Case identifiers, title, description, status, severity, priority, type, layer,
  behavior, automation state, flaky/muted flags, assignee, milestone, tags,
  preconditions, postconditions, attachments, and custom fields.
- Classic action/data/expected steps, BDD/Gherkin content, nested steps, and
  project/workspace shared steps with usage tracking and safe detach/delete.
- Local and workspace shared parameters, independent values and row-based
  parameter groups, bounded combination expansion, and preview before run.
- Immutable revisions, word/field diff, history, restore, comments, mentions,
  favorites, links, and external issue/requirement references.
- Optional or mandatory review workflow: reviewers, required approvals, change
  requests, version-aware approval invalidation, merge, decline, reopen,
  self-merge policy, default reviewers, auto-merge, notifications, and audit.
- Bulk field update, move, clone, archive/delete, restore from trash, permanent
  purge by retention policy, import dry-run, and deterministic export.
- CSV, XLSX, XML, JSON, PDF, and HTML interchange/export where the format can
  preserve the selected data; lossy conversions must be explicit.

### 2.3 Planning and execution

- Reusable test plans with case selection, ordering, per-case assignment, and
  revision-aware membership.
- Express runs from selected cases and configured runs from repository selection,
  plans, or saved queries.
- Run context: title, description, environment, milestone, configuration matrix,
  custom fields, tags, assignees, external links, and manual/automated/mixed mode.
- Configuration groups produce bounded combinations with an up-front instance
  count and administrator-configurable safety limit.
- Point-in-time case snapshots, parameter/configuration instances, workload
  distribution, progress, time tracking, and start/pause/complete/abort lifecycle.
- Manual runner with per-step state, overall result, elapsed time, comments,
  attachments, defects, hotkeys, filters, sibling navigation, and resume state.
- Result states including passed, failed, blocked, skipped, invalid, in progress,
  and untested; projects may extend labels without changing semantic categories.
- Bulk results, reassignment, retest, run clone by status/filter, and rerun failed.
- Scheduled run templates with timezone-aware recurrence, pause/resume, missed-run
  policy, next-fire preview, and immutable history.
- Immutable result attempts and step results. Corrections append a superseding
  attempt instead of rewriting audit history.

### 2.4 Automation and CI/CD

- Versioned ingestion API for creating/reusing runs, streaming/batching results,
  uploading artifacts, heartbeats, completing runs, and querying summaries.
- Stable automation IDs, case linking, optional auto-create/update guarded by
  project policy, unmatched-result queue, idempotency, retries, and partial error
  reporting.
- Parsers for JUnit XML, Allure results, XCTest, and a documented native JSON
  event format; additional formats use the same parser interface.
- CLI that can wrap a test command, preserve its exit status, upload reports and
  artifacts, and print a stable run URL plus machine-readable summary.
- Reporter SDK contract and first-party adapters for common ecosystems, staged by
  demand: JavaScript/TypeScript, Java/Kotlin, Python, Go, .NET, and Ruby.
- Native CI/CD integrations for GitHub Actions, GitLab CI/CD, Jenkins, TeamCity,
  Azure Pipelines, and Bitbucket Pipelines, plus a vendor-neutral CLI/container
  path. CircleCI, Buildkite, and Bamboo follow after the primary set.
- Optional outbound pipeline triggering from a configured run. Trigger permission
  is separate from result-submission permission and is disabled by default.
- Run linking to commit, branch, pull/merge request, build, job, and artifact URLs.
- Result publishing and outbound pipeline triggering are separate capabilities:
  publishing uses project-bound CI credentials, while triggering uses an
  administrator-installed provider connection and a distinct permission.

### 2.5 Requirements, defects, and traceability

- Hierarchical requirements with type, status, rich description, attachments,
  owner, milestone, custom fields, and links to cases and external requirements.
- Internal defects with lifecycle, severity, assignee, comments, attachments,
  related result attempts, and external issue links.
- Create or link a defect directly from a negative test result.
- Configurable one-way or two-way external issue status mapping with loop and
  conflict protection.
- Versioned traceability matrices across requirements, cases, latest results,
  runs, and defects; coverage gaps and stale-result detection.
- CSV/PDF traceability export and release/milestone coverage views.

### 2.6 Search, analytics, and reporting

- Fast text search, structured filters, selected columns, sorting, grouping, and
  reusable saved views throughout repository, runs, defects, and requirements.
- A documented read-only query language spanning cases, plans, runs, results,
  defects, requirements, users, milestones, tags, and custom fields.
- Boolean expressions, date/time helpers, current-user context, aggregation,
  grouping, and bounded result/export size. Queries compile to parameterized SQL;
  users cannot submit raw SQL.
- Private/shared saved queries with permission-aware results.
- Built-in dashboards for execution health, automation coverage, case growth,
  failure trends, duration, workload, flaky candidates, requirement coverage,
  and release readiness.
- Dashboard builder with counters, distributions, time series, tables, saved-query
  widgets, layout, date filters, sharing, cloning, and export.
- Every aggregate applies row-level authorization before computation to prevent
  counts or labels from leaking inaccessible projects.

### 2.7 Collaboration and notifications

- Comments and mentions on cases, reviews, runs, results, defects, requirements,
  and plans where appropriate.
- In-app notification inbox, unread state, per-event preferences, and optional
  email delivery.
- Events for assignments, mentions, reviews, run lifecycle, defects, schedules,
  integration failures, token/security activity, and administrative changes.
- Batched/digested delivery, retry, bounce visibility, and quiet-hours support.
- User-authored content is sanitized; notification previews never expose secrets
  or content the recipient can no longer access.

### 2.8 Integrations

- Integration catalog, installation lifecycle, per-project enablement, credential
  rotation, health status, audit history, and explicit external-resource access
  mapping.
- Provider interfaces for issue trackers, source control, CI/CD, chat, knowledge
  bases, identity providers, object storage, email, and AI assistants.
- Primary work-management providers: Jira Cloud/Data Center, Asana, Linear,
  Azure DevOps Boards, GitHub Issues, and GitLab Issues. YouTrack and Redmine are
  secondary self-hosted-friendly providers; additional adapters are community-
  led and do not block the core release.
- Primary chat providers: Slack and Microsoft Teams through narrowly scoped app
  credentials or incoming webhooks.
- Knowledge/requirements links for Confluence and Notion without bulk mirroring
  by default.
- Signed, versioned outbound webhooks with filters, replay, rotation, delivery
  logs, backoff, dead-letter state, and optional destination allowlists.
- Inbound provider callbacks share the public HTTPS listener and verify state,
  signature, issuer, timestamp, and replay identifiers before parsing payloads.
- Provider priority, capability contracts, credentials, and acceptance criteria
  are normative in `docs/INTEGRATIONS.md`.

### 2.9 API and MCP

- Complete versioned REST API with OpenAPI, typed clients, pagination, filtering,
  optimistic concurrency, idempotency, stable errors, and rate-limit metadata.
- MCP over the same HTTPS listener using the official Go SDK and normal domain
  services; it never reads tables directly.
- MCP resources for project context and entity details; read, search, write, and
  composite tools for repository, execution, result upload, defect triage, and
  regression setup.
- Tool discovery remains compact: generic entity reads/search plus tool-help or
  grouped workflows are preferred over hundreds of near-duplicate schemas.
- No unrestricted REST escape-hatch tool. Every tool has a fixed schema,
  bounded effect, explicit read/write annotation, scope, authorization check,
  audit event, and idempotency behavior.

### 2.10 External AI integrations

- AI connectivity is opt-in and disabled in a fresh installation.
- Supported paths: scoped MCP access to Qali, REST service accounts, outbound
  signed webhooks to an operator-controlled gateway, and optional provider
  adapters using an OpenAI-compatible API boundary.
- Administrators select allowed projects, entity types, fields, operations,
  provider endpoint, model allowlist, retention policy, and whether write tools
  require human confirmation.
- Default policy denies attachment contents, secrets, private comments, user
  email addresses, audit details, and integration payloads from AI egress.
- Prompt/response content logging is off by default. Metadata audit records retain
  provider, model, actor, scopes, entity IDs, token estimate, and outcome.
- AI output is always untrusted input: validate schemas, sanitize rich text,
  enforce normal permissions, mark provenance, and require review for bulk or
  destructive changes.
- No background training, provider data reuse assumption, or silent provider
  fallback. A provider must be explicitly configured and its data policy shown.

### 2.11 Administration and operations

- Workspace settings, security policies, roles, users/groups, fields, tags,
  integrations, attachments/storage, retention, audit, and diagnostics are an
  isolated administration area hidden and forbidden for ordinary testers.
- Project administration is independently permissioned from test authoring and
  execution.
- Append-only audit log for UI, API, automation, SCIM, OAuth, MCP, integration,
  and operator events with export and retention controls.
- Storage usage, job queues, delivery failures, configuration validation, version,
  migration state, backup age, and dependency health.
- Backup/restore, upgrade/rollback, data export, retention, legal hold, and secure
  workspace deletion procedures.

## 3. Cross-cutting product rules

- Historical runs and results reference immutable snapshots.
- Deactivation preserves attribution; deletion never silently erases audit links.
- All lists, search, export, dashboard, notification, API, and MCP paths enforce
  the same authorization model.
- Bulk actions are bounded, previewable, idempotent where retry is possible, and
  report per-item outcomes.
- Destructive operations use soft delete and retention unless the security or
  privacy policy explicitly requires immediate purge.
- Accessibility, keyboard use, responsive behavior, timezone correctness, and
  internationalization readiness are acceptance criteria for every feature.

## 4. Delivery grouping

- **Core:** identity/RBAC, projects, repository, plans/runs, manual execution,
  automation ingestion, baseline reporting, audit, API, secure Compose deploy.
- **Governance:** reviews, requirements, traceability, groups, SAML/SCIM,
  advanced audit/retention, custom roles, dashboards/query language.
- **Ecosystem:** provider catalog, broad integrations, reporter SDKs, pipeline
  triggering, notifications, complete MCP and external AI controls.
- **Scale:** Helm, external key management, HA workers, large-dataset tuning,
  compliance evidence, and disaster-recovery exercises.

The implementation plan may stage these groups across releases, but agents must
not design Core schemas or permissions in a way that blocks later groups.

