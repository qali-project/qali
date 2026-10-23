# ADR-0003: HTTP API, URL, and versioning conventions

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

`api/openapi.yaml` is the source of truth for the public HTTP API (AGENTS.md),
and every MVP item from MVP-04 onward adds endpoints. Conventions for paths,
payloads, errors, pagination, concurrency, idempotency, and versioning must be
fixed before the first endpoint so the generated client and every consumer (UI,
CLI, CI, MCP adapter) see one consistent shape.

## Decision

### Listener and route families

All traffic uses one listener behind the reverse proxy
(`docs/SECURITY_ARCHITECTURE.md` section 2). Route families:

| Prefix | Purpose | Authentication |
|---|---|---|
| `/api/v1/` | Public REST API described by OpenAPI | Session cookie or bearer credential, per operation |
| `/auth/` | Browser login, logout, OIDC redirect and callback | Flow-specific |
| `/mcp` | Read-only MCP endpoint (MVP-15) | MCP bearer token only |
| `/health/live`, `/health/ready` | Private probes; public output is a boolean status | None |
| `/internal/` | Protected diagnostics and metrics | Operator permission plus recent MFA; never published separately |
| everything else | Embedded single-page application | Application decides |

### Resource paths

- Workspace-owned resources: `/api/v1/workspaces/{workspaceId}/<collection>/{id}`.
- Project-owned resources:
  `/api/v1/workspaces/{workspaceId}/projects/{projectId}/<collection>/{id}`.
- At most two further nested levels below a project (for example
  `.../runs/{runId}/cases/{runCaseId}/attempts`). Deeper data belongs in the
  parent representation.
- The workspace and project in the path are authorization inputs, never trusted
  alone: the application verifies that the addressed resource belongs to them
  and returns `404` when it does not.
- CI ingestion uses `/api/v1/automation/...`; the project is derived from the
  CI credential, never from client input.
- Collections are plural kebab-case nouns (`test-cases`, `test-runs`).
  Path identifiers are UUIDs (ADR-0009).
- Non-CRUD state changes are sub-resource actions using `POST` and a verb:
  `POST .../runs/{runId}/complete`, `POST .../test-cases/{caseId}/restore`.

### Representation

- Media type `application/json; charset=utf-8`. Field names are `camelCase`.
- Timestamps follow ADR-0004. Durations are integer milliseconds named
  `...Ms` (for example `durationMs`).
- Enumerations are lowercase `snake_case` strings. Clients must tolerate unknown
  enum values added in a compatible release.
- Absent optional values are omitted or `null` as declared in OpenAPI; empty
  collections are `[]`, never `null`.
- Unknown request fields are rejected with `400` (strict decoding) so that
  typos and mass-assignment attempts fail loudly.

### Errors

- Errors use RFC 9457 problem details (`application/problem+json`) with members
  `type`, `title`, `status`, `detail`, plus `code` (stable machine-readable
  `snake_case` identifier) and `requestId`.
- Validation errors add `errors: [{ "pointer": "/field", "code": "...",
  "message": "..." }]` using JSON Pointer.
- Responses never contain stack traces, SQL text, internal hostnames, secrets,
  or whether a resource exists in another workspace.
- Status code policy:
  - `400` malformed request or validation failure;
  - `401` missing or invalid authentication;
  - `403` authenticated and the resource is visible, but the action is denied;
  - `404` the resource does not exist **or** the caller may not know it exists;
  - `409` state conflict or idempotency-key reuse with a different payload;
  - `412` `If-Match` version mismatch; `428` `If-Match` required but missing;
  - `413` body too large; `415` unsupported media type; `429` rate limited
    with `Retry-After`;
  - `500` unexpected failure, with `requestId` only.
- Enumeration safety: authentication and invitation endpoints return the same
  status, body, and comparable timing for unknown and known identities.

### Pagination, filtering, sorting

- Cursor pagination only: `?limit=<n>&cursor=<opaque>`; response
  `{ "items": [...], "nextCursor": "..." | null }`.
- `limit` defaults to 50 and is capped at 200. Cursors are opaque, bound to the
  query parameters and principal, and rejected with `400` if tampered with.
- Total counts are not returned by default; endpoints that need them expose an
  explicit, authorized count.
- Filters are named query parameters declared in OpenAPI; sorting uses
  `?sort=field` or `?sort=-field` over a declared allowlist. No free-form query
  language in the MVP.

### Optimistic concurrency

- Mutable resources expose an integer `version` and an `ETag` (`"<version>"`).
- `PATCH`, `PUT`, and `DELETE` on such resources require `If-Match`; a
  mismatch returns `412` with the current version in the problem details.
- `PATCH` uses JSON Merge Patch (RFC 7396) semantics.

### Idempotency

- Retryable `POST` operations accept `Idempotency-Key` (1-255 visible ASCII
  characters). Operations that the MVP plan marks idempotent (bulk, ingestion,
  webhook handling) require it.
- Keys are unique per credential (or session principal) and operation.
- A replay with the same request fingerprint returns the original status and
  body; a different fingerprint returns `409` with code `idempotency_conflict`.
- Retention follows ADR-0005.

### Versioning and compatibility

- The product uses Semantic Versioning. The REST API major is in the path
  (`/api/v1`). Within v1 only additive, backward-compatible changes are allowed:
  new endpoints, optional request fields, new response fields, and new enum
  values.
- Removing or changing the meaning of a field, tightening validation of an
  existing field, or changing a status code requires `/api/v2`.
- Deprecated operations send `Deprecation` and `Sunset` headers and are listed
  in release notes at least one minor release before removal in the next major.
- OpenAPI 3.1 is the contract; the generated client and server types are
  checked in CI for drift (MVP-01).

### Browser requests

- Browser mutations require the session cookie, a matching `Origin`, and the
  CSRF token header `X-CSRF-Token`. Bearer credentials are never accepted from
  browser cookies, and session cookies are never accepted on `/mcp` or
  `/api/v1/automation/`.

## Consequences

- One generated TypeScript client serves all screens; the CLI and MCP adapter
  reuse the same application services rather than calling REST internally.
- `404` for unauthorized existence makes some debugging harder; `requestId`
  plus server logs compensate.

## Alternatives considered

- Offset pagination: rejected; unstable under concurrent writes and leaks totals.
- Flat paths without workspace (`/api/v1/projects/{id}`): rejected; workspace
  scoping by construction is a product rule.
- `snake_case` JSON: rejected; the primary consumer is TypeScript.
- Header-based API versioning: rejected; harder to route, cache, and document.
