# MVP-05 acceptance map

Item: MVP-05 — Workspaces, fixed RBAC, invitations, and project access  
Status: IN_PROGRESS  
Coordinator: implementation agent  
Dependencies verified: MVP-04 COMPLETE (2026-10-22)

## Scope

Included (design in ADR-0013):

- Permission catalog code generation and the `internal/authz` policy engine.
- Workspace listing, members (list, role change, deactivate/reactivate),
  last-owner protection, and step-up MFA for sensitive actions.
- Invitations with one-time links, acceptance for new and existing accounts,
  listing, and revocation.
- Projects as access objects: create, list visible, get, and direct project
  members with access levels.
- Membership resolution middleware, application policies, and an
  administration UI hidden from roles without permission.

Excluded (later items):

- Project editing, archive, and repository content (MVP-07); OIDC (MVP-06).
- Ownership transfer flow, custom roles, groups, email delivery.
- Credential types beyond human sessions in practice (CI in MVP-11, MCP in
  MVP-15); the engine already evaluates credential scopes.

## Threats

| Threat ID | Threat | Control |
|---|---|---|
| MVP-05.T-01 | A Tester or Viewer reaches administration (users, roles, security, integrations, credentials, project access, project settings) | Catalog-driven policy in the application layer; route and UI tests |
| MVP-05.T-02 | Guessed workspace, project, member, or invitation IDs expose or change data in another tenant | Membership resolution per request, RLS, 404 for invisible resources |
| MVP-05.T-03 | A permissive project membership elevates a restrictive role (union instead of intersection) | Access-level cap and intersection rules in `authz.Decide` |
| MVP-05.T-04 | Invitations are replayed, used after expiry or revocation, or redeemed by another account | Single-use keyed tokens, expiry, email binding |
| MVP-05.T-05 | The workspace loses its last Owner, or an Administrator takes over Owner powers | Last-owner rule; owner-only role changes |
| MVP-05.T-06 | Removed or downgraded members keep access through cached decisions | Membership read on every request; no authorization cache |
| MVP-05.T-07 | Sensitive role changes without recent strong authentication | Recent-MFA check (10 minutes) and step-up with session rotation |
| MVP-05.T-08 | Code-level permission tables drift from the reviewed catalog | Generated catalog, stale-file check |

## Criteria

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| MVP-05.AC-01 | Every role/permission pair in the catalog is decided as the catalog specifies, with hand-checked invariants for administrative and owner-only permissions | MVP-05.T-01, MVP-05.T-08 | `internal/authz/authz_test.go` | PASS |
| MVP-05.AC-02 | Role, project visibility, access level, condition, credential scope, and recent MFA intersect (never union) | MVP-05.T-03, MVP-05.T-07 | `internal/authz/authz_test.go` | PASS |
| MVP-05.AC-03 | The generated catalog is current | MVP-05.T-08 | `make fmt-check`; `tools/gateselftest/run.sh::stale-permission-catalog` | PASS |
| MVP-05.AC-04 | Guessed IDs across workspaces and projects never get, list, count, search, update, or delete | MVP-05.T-02 | `test/integration/workspace_tenancy_test.go` | PASS |
| MVP-05.AC-05 | Expired, revoked, replayed, and mismatched invitations are rejected | MVP-05.T-04 | `test/integration/invitations_test.go` | PASS |
| MVP-05.AC-06 | The last Owner cannot be demoted or deactivated; Administrators cannot change Owners | MVP-05.T-05 | `test/integration/members_test.go` | PASS |
| MVP-05.AC-07 | Role and membership changes apply to the very next request | MVP-05.T-06 | `test/integration/members_test.go` | PASS |
| MVP-05.AC-08 | Sensitive actions require recent MFA; step-up rotates the session | MVP-05.T-07 | `test/integration/members_test.go` | PASS |
| MVP-05.AC-09 | Tester (and Viewer) get 403 or 404 on every administrative operation through the API | MVP-05.T-01 | `test/integration/admin_denial_test.go` | PASS |
| MVP-05.AC-10 | The UI hides administration from Testers and shows a not-permitted page on direct navigation | MVP-05.T-01 | `web/src/features/admin/*.test.tsx`; `web/e2e/admin.spec.ts` | PASS |
| MVP-05.AC-11 | E2E: owner invites a tester, the tester accepts, signs in, and cannot reach administration; the owner changes the role and the change applies immediately | MVP-05.T-01, MVP-05.T-06 | `web/e2e/admin.spec.ts` | PASS |

## Evidence

| Date (UTC) | Command | Result |
|---|---|---|
| 2026-10-22 | `go test -cover ./internal/authz/ ./internal/workspace/domain/ ./internal/platform/pagination/` | PASS, 100.0% each |
| 2026-10-22 | `make fmt` then `make fmt-check` | PASS (includes the permgen stale check) |
| 2026-10-22 | `make lint` | PASS: golangci-lint 0 issues, testguard OK, gitleaks clean, govulncheck 0 reachable, npm audit 0, typecheck, ESLint |
| 2026-10-22 | `make test POSTGRES_MAJORS="17 18"` | PASS: Go unit, 21 frontend tests, integration on PostgreSQL 17 and 18, `covercheck: OK` with new thresholds (authz 90, pagination 90, workspace domain 90, app/adapters 80) |
| 2026-10-22 | `make test-e2e` | PASS 7/7: `auth` suite (6) and `admin` suite (`admin.spec.ts`), each on its own server and fresh database; axe clean |
| 2026-10-22 | `make build` | PASS: binary, image, imagecheck, deploy-check, live Compose smoke test |
| 2026-10-22 | `make gate-selftest` | PASS 18/18, including `stale-permission-catalog`. The first run failed `e2e-failure`: per-suite `testMatch` silently skipped spec files no suite claimed. Fixed in `web/playwright.config.ts` (the default suite runs every unclaimed spec); re-run PASS. |

## Failing-first evidence

- `internal/authz/authz_test.go`, `tools/permgen/main_test.go`,
  `internal/workspace/domain/domain_test.go`, and
  `internal/platform/pagination/pagination_test.go` failed to build before
  their packages existed ("no non-test Go files").
- The integration tests (`members_test.go`, `invitations_test.go`,
  `workspace_tenancy_test.go`, `admin_denial_test.go`) were written against
  the contract before the workspace module; the first runs failed for
  missing behavior (500/404 from unimplemented operations) and then exposed
  real defects:
  - **Cross-workspace privilege leak.** `TestGuessedIDsNeverCrossWorkspaces`
    showed a user who owns workspace B acting as Owner in workspace A (200 on
    get, list, and update). Cause: the `member_self` policy is OR'ed with
    workspace isolation, so a membership lookup by user ID returned the
    caller's row from another workspace. Fixed by filtering membership
    queries on `qali.current_workspace()`; recorded in ADR-0013.
  - Invitation preview used a locking read inside a read-only transaction
    (500); fixed with a non-locking read.
  - `TestEveryTenantTableIsIsolated` (backlog item from MVP-03) runs on every
    migration.
- `TestRoutePolicyMatchesTheContract` failed when the contract gained the
  public invitation routes, until the route policy listed them.
- Frontend: `admin.test.tsx` and `admin.spec.ts` were written alongside the
  pages rather than strictly before them. Two assertions initially failed
  and were corrected in the product markup (explicit accessible names on
  row action buttons) and in the test (scoping the "no Owner option" check
  to the invitation role picker, since Owners may grant ownership in the
  member table).

## Notes and open questions

- ADR-0013 is `Proposed` and needs maintainer review. The status returned to
  `IN_PROGRESS` on 2026-10-23 (security review REVIEW-007): completion was
  recorded before that review gate. All acceptance criteria and gates pass
  again after the review fixes (see the resolution log in
  `docs/reviews/MVP-00-05-security-review-2026-10-23.md`).
- Review fixes that changed MVP-05 behavior: promotion into an
  MFA-requiring role takes effect together with its MFA requirement
  (REVIEW-002); the UI is bound to the workspace in the URL (REVIEW-006);
  deactivation is workspace-local in every normative document (REVIEW-008).
- Test changes to earlier items, with reasons:
  - `routes_test.go` parsed every key under a path as an operation; the
    contract now has path-level `parameters`, so the parser skips non-method
    keys. The reachability test now fills path parameters with well-formed
    UUIDs: with literal `{workspaceId}` the router rejects the malformed ID
    (400) before authentication, which is still a rejection but not the
    property under test.
  - E2E: `tools/e2eenv` creates one database per suite and the Playwright
    config runs one server per suite, because `auth.spec.ts` requires a fresh
    installation.
- Security, integration, credential, and project-settings administration have
  no endpoints yet; their denial for Testers and Viewers is proven at the
  policy level by the catalog matrix (AC-01) and must be re-proven through
  the API by the items that add them.
- Identity also gained: `StepUp`, recent-MFA on the request session, a
  password change that no longer refreshes recent MFA, and the account
  interface used by invitation acceptance.
