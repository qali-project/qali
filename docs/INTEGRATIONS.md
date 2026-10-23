# Integration Strategy and Support Matrix

Status: normative product and architecture design  
Audience: integration, automation, security, and release agents

## 1. Integration principles

1. Integrations extend the product; they never bypass domain services, RBAC,
   project access, audit, rate limits, or tenant isolation.
2. Result publishing, pipeline triggering, issue synchronization, notifications,
   and identity provisioning are different capabilities with different
   credentials and permissions.
3. Every provider advertises a capability manifest. UI and API behavior is based
   on advertised capabilities, not provider-name conditionals.
4. The generic CLI, REST ingestion API, signed webhooks, and documented report
   formats work without a native provider adapter.
5. Native adapters are prioritized by broad practical use. A long tail of
   low-demand chat and task tools must not delay core CI/CD and work-management
   integrations.
6. Provider failures are isolated in jobs and delivery attempts; they never roll
   back or corrupt a committed test result.

## 2. Capability model

Do not create one oversized provider interface. Use focused contracts:

| Contract | Representative capabilities |
|---|---|
| Result publisher | create/reuse run, submit attempts/steps, attach artifacts, complete run |
| Pipeline provider | list projects/pipelines, validate parameters, trigger, poll/callback status, cancel when supported |
| Source provider | resolve repository, commit, branch, pull/merge request, build links |
| Work-item provider | search/get/create/link/unlink, comments, fields, status mapping, callback reconciliation |
| Chat provider | select destination, publish bounded event card, validate installation |
| Knowledge provider | search/link a page or requirement; no bulk content mirror by default |
| Identity provider | OIDC/SAML authentication or SCIM users/groups; isolated from project integrations |

An installation is workspace-scoped and contains provider type, encrypted
credential references, declared provider scopes, health, key version, and audit
metadata. Project mappings define the exact external organizations, repositories,
projects, pipelines, channels, or spaces visible to each internal project.
One vendor installation may implement several focused contracts—for example,
source links, issues, and pipelines—but each capability is enabled, scoped, and
authorized independently. Sharing an installation must not imply sharing every
provider permission or exposing its credential to CI jobs.

## 3. CI/CD integration matrix

### 3.1 Universal baseline

Available before any native adapter:

- CLI/container usable in any pipeline.
- REST ingestion with project-scoped CI credentials and idempotency keys.
- JUnit XML, Allure, XCTest, and native JSON result formats.
- Commit, branch, build, job, and artifact URL metadata.
- Exit-code preservation: upload failure and test failure are reported separately.
- Signed outbound event when a run completes.

### 3.2 Native providers

`P0` is required for the ecosystem release candidate. `P1` follows without
blocking the core release.

| Provider | Priority | Publish results | Trigger from Qali | Status/link sync | Authentication preference |
|---|---:|---:|---:|---:|---|
| GitHub Actions | P0 | CLI/action | workflow dispatch | callback plus polling | GitHub App installation token |
| GitLab CI/CD | P0 | CLI/template | pipeline API | webhook plus polling | OAuth/app or scoped project/group token |
| Jenkins | P0 | CLI/plugin step | job/build API | queue/build polling; optional callback | dedicated least-privilege API token |
| TeamCity | P0 | CLI/build step | build queue REST API | webhook or bounded polling | dedicated bearer access token |
| Azure Pipelines | P0 | CLI/task | pipelines/runs API | service hook plus polling | OAuth/service principal or scoped PAT fallback |
| Bitbucket Pipelines | P0 | CLI/pipe | pipeline API | webhook plus polling | workspace access token/OAuth |
| CircleCI | P1 | CLI/orb | pipeline API | webhook plus polling | scoped personal or organization token |
| Buildkite | P1 | CLI/plugin | build API | webhook plus polling | cluster/API access token |
| Bamboo | P1 | CLI/task | queue REST API | webhook/plugin or polling | dedicated service credential |

Native integration means more than documentation. Each P0 provider must support:

- administrator install, credential validation, rotation, disable, and removal;
- project-to-external-project/repository/pipeline allowlist mapping;
- pipeline/job discovery without exposing provider credentials to ordinary users;
- schema-driven parameter validation and secret-parameter redaction;
- authorized triggering with idempotency and a stable external execution link;
- queued/running/succeeded/failed/canceled state normalization;
- callback signature/replay validation where the provider supports it, otherwise
  bounded polling with backoff and a terminal timeout;
- result publication from the pipeline through a separate project CI credential;
- installation health, delivery diagnostics, and audit events.

### 3.3 Framework and reporter coverage

| Ecosystem | P0 frameworks/formats | Later additions |
|---|---|---|
| Universal | JUnit XML, Allure, native JSON | TAP and additional standard formats |
| JavaScript/TypeScript | Playwright, Cypress, Jest/Vitest, WebdriverIO, Mocha, CucumberJS | TestCafe and Newman |
| Python | pytest, Robot Framework, Behave | Tavern |
| JVM | JUnit 4/5, TestNG, Cucumber JVM | additional build-tool helpers |
| Go | `go test` JSON and SDK | common BDD frameworks |
| .NET | NUnit, xUnit.net, MSTest/TRX | SpecFlow-compatible mapping |
| Apple | XCTest result bundle | richer simulator/device metadata |
| PHP | PHPUnit | Pest and Codeception |

Reporter libraries share one protocol and conformance fixture suite. Framework-
specific code maps native events to that protocol; it does not reproduce run,
retry, or authorization business rules.

## 4. Work-management and issue integrations

### 4.1 Provider priorities

| Provider | Priority | Required capabilities |
|---|---:|---|
| Jira Cloud | P0 | search/create/link work item, field mapping, comments, attachments, two-way status sync |
| Jira Data Center | P0 | same contract with self-hosted URL and explicit private-network allowlist |
| Azure DevOps Boards | P0 | search/create/link work item, work-item field/status mapping |
| GitHub Issues | P0 | repository allowlist, search/create/link issue, comments and state sync |
| GitLab Issues | P0 | group/project allowlist, search/create/link issue, notes and state sync |
| Asana | P0 | workspace/project allowlist, search/create/link task, comments and status mapping |
| Linear | P0 | team allowlist, search/create/link issue, comments and state sync |
| YouTrack | P1 | project allowlist, search/create/link issue and state mapping |
| Redmine | P1 | self-hosted project allowlist, issue linking/creation and state mapping |

The core release is not blocked by low-demand task-board adapters. Community
providers may be added after they pass the same security and contract suites.

### 4.2 Linking and synchronization rules

- Cases, runs, results/defects, and requirements may link to external work items.
- Creating an external work item is an explicit action; viewing a linked item
  must not silently broaden provider access.
- Store provider object IDs and canonical URLs, not mutable titles as identity.
- The provider remains source of truth for its work item; Qali remains source of
  truth for test assets, runs, and result history.
- Status mappings are per installation/project and validate both directions.
  Every synchronization carries an origin and version/delivery ID to prevent
  update loops and stale overwrites.
- Ambiguous conflicts enter a visible reconciliation queue. They are never
  resolved by last-write-wins without policy.
- Deleting or disabling an installation preserves internal history and labels
  links unavailable; it does not delete remote objects.

## 5. Collaboration and knowledge integrations

Primary supported providers:

- Slack: selected workspace/channel notifications using a scoped app or incoming
  webhook; no message-history read permission is required.
- Microsoft Teams: selected channel/workflow notifications with bounded cards;
  no tenant-wide directory or chat-history permission is required.
- Confluence: search and link authorized pages/requirements; content import is an
  explicit bounded action.
- Notion: search and link pages/databases explicitly shared with the installation;
  no workspace-wide crawl.

Additional chat/task-board adapters are not part of the initial roadmap. Generic
signed webhooks cover teams that need simple event delivery.

## 6. Credentials and authorization

- Installing, reauthorizing, rotating, or removing a provider requires workspace
  integration-administration permission and recent strong authentication.
- Project administrators may configure mappings and notification rules only for
  an already installed provider and only when explicitly granted that permission.
- Testers may link/search allowed work items when their role permits it, but
  cannot view credentials, widen mappings, trigger pipelines, or change sync.
- Pipeline triggering uses `runs:trigger_pipeline`; result publishing uses a
  separate project-bound CI credential with append-oriented scopes.
- Prefer provider apps, OAuth, service principals, and short-lived installation
  tokens. Personal access tokens are a documented fallback, not the default.
- Recoverable credentials use envelope encryption and are never returned after
  installation. UI shows provider, owner/service identity, scopes, expiry,
  rotation state, and last use—not the secret.

## 7. Network and self-hosted providers

- All inbound callbacks use the main TLS listener on port 443; integrations add
  no public listener or port.
- Outbound provider clients use the common restricted egress layer with DNS,
  redirect, timeout, response-size, and TLS controls.
- Private Jira Data Center, Jenkins, TeamCity, GitLab, Redmine, or other internal
  endpoints require an administrator-defined host/CIDR allowlist. Allowlisting a
  destination does not exempt it from TLS verification or response limits.
- Provider-specific proxy configuration references an administrator-managed
  proxy profile; arbitrary per-user proxy URLs are forbidden.

## 8. Contract and release gates

Every provider adapter must pass shared tests for:

- capability discovery and unsupported-operation behavior;
- least scopes and role/project mapping;
- credential encryption, rotation, expiry, and revocation;
- pagination, rate limits, retries, idempotency, and terminal failure;
- timeout, malformed/oversized response, redirect, DNS rebinding, and TLS error;
- webhook signature, timestamp, replay, duplicate, reordering, and unknown event;
- status normalization, loop prevention, stale update, and conflict handling;
- cross-workspace/project isolation, audit redaction, and provider uninstall;
- documented minimum provider version and a recorded compatibility fixture.

An adapter is not marked supported until its install, happy path, revocation,
provider outage, and permission-denied paths pass end-to-end tests.

