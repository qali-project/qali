# ADR-0007: MVP roles, project access, and permission catalog

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

`docs/RBAC.md` describes the full role model, including roles and permission
families that the MVP defers. MVP-00 must deliver a machine-readable permission
catalog for the fixed MVP roles (Owner, Workspace Administrator, QA Lead,
Tester, Viewer) so MVP-05 can generate table-driven tests for every role/action
pair and later items cannot reinterpret the matrix.

## Decision

### Catalog

- [`docs/rbac/permission-catalog.json`](../rbac/permission-catalog.json) is the
  normative source for MVP permissions, role grants, project access levels, and
  credential types. [`docs/rbac/permission-matrix.md`](../rbac/permission-matrix.md)
  is generated from it and must not be edited by hand.
- MVP-05 generates the Go policy table and test cases from the catalog; a
  runtime role grant that is not in the catalog is a defect.
- The catalog contains only MVP capabilities. Deferred families (`reviews`,
  `requirements`, `roles`, `ai_integrations`, SCIM, scheduling, pipeline
  triggering, write MCP tools) are added by the item that introduces them.
- Permission flags:
  - `administrative`: never granted to QA Lead, Tester, or Viewer;
  - `sensitive`: requires MFA within 10 minutes (ADR-0006), a CSRF-protected
    browser flow, and a high-severity audit event;
  - `ownerOnly`: granted only to Owner;
  - `kind`: `read` or `write`; Viewer holds only `read`.
- Grant conditions: `all`, `own` (resources the principal created), and
  `assigned` (run cases assigned to the principal or unassigned).

### Roles

- Exactly five MVP roles. Project Administrator and Developer from `RBAC.md`
  are not MVP roles; their duties are covered by Workspace Administrator and
  QA Lead respectively. Custom roles are deferred.
- Owner holds every permission. Workspace Administrator holds every permission
  except owner-only ones. The last active Owner cannot be demoted, deactivated,
  or removed.
- Invitations default to the Tester role.
- Notable Tester limits: deletes and restores only own repository items, edits
  only own plans and runs, executes and records results only for assigned or
  unassigned run cases, cannot delete defects, cannot issue MCP tokens.
- MCP tokens (`mcp.connect`) are available to Owner, Workspace Administrator,
  and QA Lead in the MVP. Tester and Viewer are excluded because the Tester
  role must not hold token permissions (AGENTS.md).

### Project access

- Project visibility is `public` (visible to all active workspace members) or
  `restricted` (visible only to direct project members).
- Direct project membership carries an access level: `contributor` (role
  grants apply) or `viewer` (only `read`-kind grants apply). Members of a
  public project without a direct membership are treated as `contributor`.
- Effective permission = role grant AND project visibility/membership AND
  access-level cap AND credential scope AND resource-state rule. It is never
  a union.
- Owner sees every project. Workspace Administrator sees public projects and
  restricted projects where they are a direct member; adding themselves to a
  restricted project uses `projects.manage_access` and is audited.
- Users who cannot see a project receive `404` for any of its resources
  (ADR-0003).
- Display names of project members are visible with `projects.read` for
  assignment; emails and roles require `members.read`.

### Machine credentials

- CI credentials are bound to one project and hold only the scopes listed in
  the catalog. They never act as a human role and cannot read the repository
  in bulk.
- MCP tokens act for the issuing human with the intersection of the token's
  `mcp:read` scope and the human's current role, project access, and status,
  evaluated on every request.

## Consequences

- Any change to a grant is a catalog change reviewed like a contract change and
  regenerates the matrix and MVP-05 tests.
- The documentation check rejects catalogs that give administrative
  permissions to QA Lead, Tester, or Viewer, give owner-only permissions to
  anyone but Owner, or use ambiguous token prefixes.

## Alternatives considered

- Including all seven `RBAC.md` roles: rejected; the MVP scope lock names five.
- Union of role and project membership: rejected by `RBAC.md` section 6.
- YAML catalog: rejected; JSON needs no parser dependency in the tooling and Go.
