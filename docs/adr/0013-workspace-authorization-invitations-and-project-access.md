# ADR-0013: Workspace authorization, invitations, and project access

Status: Proposed  
Date: 2026-10-22  
Work item: MVP-05

## Context

MVP-05 delivers memberships, fixed roles, invitations, public and restricted
projects, direct project membership, authorization middleware plus
application policies, and administration UI. ADR-0007 froze roles, grants,
conditions, and access levels; ADR-0012 created the workspace and
membership tables. This record fixes how authorization is evaluated and what
the MVP-05 API covers, before feature data exists (MVP-07+).

## Decision

### Evaluation

- `tools/permgen` generates `internal/authz/catalog_gen.go` from
  `docs/rbac/permission-catalog.json`; `make fmt-check` rejects a stale file.
  The catalog stays the single source of truth.
- `internal/authz` is a pure policy package. `Decide(principal, permission,
  resource)` allows only if every factor allows: active membership, role grant,
  project visibility and membership, access-level cap (a `viewer` level allows
  only `read` permissions), grant condition (`own`, `assigned`), credential
  scope, and the recent-MFA rule for sensitive permissions (10 minutes,
  ADR-0006). Anything unknown denies.
- Owners see every project at full level; a project membership level never
  narrows an Owner, so an Owner cannot be locked out of managing access. For
  every other role the level caps the role (intersection, ADR-0007).
- Routes under `/api/v1/workspaces/{workspaceId}` resolve the caller's
  membership on every request (no cache), so role and membership changes
  apply to the next request. Non-members and deactivated members get `404`;
  a project the caller cannot see is `404`; a visible resource with an
  insufficient permission is `403 forbidden`; a sensitive action without
  recent MFA is `403 recent_mfa_required`.
- Application services call `authz.Decide`; HTTP handlers only translate
  results. The UI hides controls but the server remains authoritative.
  Workspace and project representations carry the caller's `permissions`
  (catalog IDs, ignoring the recent-MFA factor) for hiding controls only.
- `workspace_members` has a `member_self` policy (a user sees their own
  memberships everywhere) that PostgreSQL OR's with workspace isolation.
  Membership queries in workspace scope therefore filter on
  `qali.current_workspace()` explicitly; RLS alone is not sufficient for this
  table. `test/integration/workspace_tenancy_test.go` guards it.
- A promotion into Owner or Workspace Administrator, or accepting such an
  invitation with an existing account, takes effect at the next request, and
  so does its MFA requirement (ADR-0012 amendment): the session must enroll
  or verify TOTP before it may use the new permissions.
- The UI binds every workspace page to the workspace in the URL
  (`/w/{workspaceId}/...`) with an explicit workspace picker; workspace-less
  links open the last chosen or first workspace (REVIEW-006).
- Module adapters do not import each other. `internal/assembly` combines the
  identity and workspace handlers into the generated server interface; the
  identity adapter's session writer is injected for invitation sign-in.

### Workspaces and members

- `GET /api/v1/workspaces` lists the caller's active workspaces and roles.
- Members: list (`members.read`), change role (`members.update_role`,
  sensitive), deactivate or reactivate (`members.deactivate`). Updates use
  `If-Match` on the membership version.
- Only an Owner may grant or remove the `owner` role (ownership transfer is
  `workspace.transfer_ownership`, owner-only; its dedicated flow is deferred).
  A Workspace Administrator cannot change an Owner's membership.
- The last active Owner cannot be demoted or deactivated (`409 last_owner`).
- Deactivating a member blocks that workspace immediately; the user's
  sessions remain valid for other workspaces. Deactivation is
  workspace-local by design (one identity, several workspaces); credentials
  bound to the workspace (CI in MVP-11, MCP in MVP-15) must stop working with
  the membership. The permission catalog states the same (REVIEW-008).

### Invitations

- An invitation binds an email, a role (default `tester`; never `owner`), an
  inviter, and a `qali_inv_` token stored as a keyed verifier (ADR-0006). It is
  valid for 7 days and single use. The raw link is returned once to the
  inviter for out-of-band delivery.
- Inviting with an administrative role (`workspace_admin`) also requires
  `members.update_role`, and therefore recent MFA.
- Acceptance is public with the token: a new email creates the account
  (display name and password) and signs in; an existing account must sign in
  first and accept with an active session whose email matches. Expired,
  revoked, used, or mismatched invitations answer `410 invitation_invalid`
  without revealing which.
- Inviters can list pending invitations (no tokens) and revoke them.
  Creating an invitation revokes earlier pending invitations for the same
  email.
- A link is redeemed before the caller knows its workspace, so a global
  `invitation_lookups` table maps the token's public lookup ID to the
  workspace only (no verifier, email, or role). The invitation itself stays
  workspace-isolated and is verified in workspace scope.
- New-account acceptance for an email that already has an account answers
  `409 account_exists` (shown only to the holder of a valid token for that
  email). An existing or deactivated member answers `409 already_member`;
  reactivation is an administrator action, not an invitation.
- The link carries the token in the URL fragment (`/invite#qali_inv_...`), so
  it never reaches server logs or Referer headers; the UI posts it.

### Projects (access objects only in MVP-05)

- Projects have a UUID, a workspace-unique `code` (ADR-0009), a name,
  `public` or `restricted` visibility, and a creator. MVP-05 provides create
  (`projects.create`), list visible projects, get one, and direct project
  members with an access level (`projects.manage_access`). Update, archive,
  and repository content are MVP-07.
- A non-Owner who creates a restricted project becomes its contributor, so
  the project does not vanish from their view.
- Lists use keyset cursors bound to the listing and principal with a keyed
  MAC (`internal/platform/pagination`); `nextCursor` is `null` on the last
  page (ADR-0003).
- Project tables are workspace-isolated with RLS (ADR-0011).

### Step-up

- `POST /api/v1/auth/mfa/step-up` with a TOTP code records recent MFA and
  rotates the session (RBAC.md: session IDs rotate on step-up).
- A password change keeps the previous session's MFA time: a password is not
  strong authentication and must not refresh recent MFA.

## Consequences

- MVP-07 adds project editing on the same tables and reuses `authz.Decide`.
- Feature items add permissions only through the catalog and regeneration.

## Alternatives considered

- Hand-written Go permission tables: rejected; they would drift from the
  reviewed catalog.
- `403` for non-members: rejected; it reveals that a workspace or project
  exists (ADR-0003).
- Email-based invitation delivery: deferred by the MVP scope lock.
