# Security review: MVP-00 through MVP-05

Date: 2026-10-23  
Reviewer: Codex  
Scope: repository state implementing MVP-00 through MVP-05  
Disposition: open; MVP-04 and MVP-05 should not be treated as release-ready
until the critical and high findings below are resolved and covered by
security-negative tests.

## Executive summary

The implementation has strong baseline structure, typed boundaries, tenant
RLS, generated contracts, and substantial test coverage. The review found two
critical authorization/bootstrap defects, two high-risk control gaps, and
several contract and UI inconsistencies.

The highest-priority sequence is:

1. Protect first-owner bootstrap from remote takeover.
2. Require MFA after promotion to Owner or Workspace Administrator.
3. Enforce TOTP throttling on every TOTP-verifying operation.
4. Make audit metadata redaction safe for every accepted value shape.

## Findings

### REVIEW-001 — Critical — Public first-owner takeover

`POST /api/v1/setup/owner` is public in
`internal/identity/adapter/httpapi/routes.go`. The service only checks whether
the singleton installation row already exists. On a new Compose deployment,
the first remote caller can therefore create the Owner account and permanently
claim the installation.

Required outcome:

- Require a one-time bootstrap secret generated or supplied by the local
  operator, or restrict the claim operation to an equivalent local-only
  channel.
- Do not expose an unclaimed installation through the public proxy without
  that proof.
- Add an integration/deployment test proving an unauthenticated remote caller
  without the bootstrap proof cannot create the Owner.

Relevant locations:

- `internal/identity/adapter/httpapi/routes.go:21-22`
- `internal/identity/app/service.go:189-216`
- `deploy/compose/compose.yaml`

### REVIEW-002 — Critical — Privileged-role promotion bypasses mandatory MFA

`internal/workspace/app.Service.UpdateMember` changes the membership role but
does not revoke or downgrade the target user's existing sessions. A Tester
with an active non-MFA session can be promoted to `workspace_admin` or
`owner`, and that same session immediately receives the new administrative
permissions.

`test/integration/members_test.go:55-67` currently enshrines the defect by
promoting a Tester to Workspace Administrator and expecting the old session to
list members successfully. This contradicts ADR-0012, which requires Owners
and Workspace Administrators to enroll in MFA before their session becomes
active.

Required outcome:

- On transition into a role requiring MFA, revoke existing sessions or move
  them to an MFA enrollment/challenge state before privileged access is
  granted.
- Re-evaluate whether a session satisfies current role MFA requirements during
  authentication or authorization, rather than trusting only its creation-time
  state.
- Replace the current positive integration assertion with security-negative
  tests proving the old session cannot use administrative permissions until
  MFA is completed.

Relevant locations:

- `internal/workspace/app/service.go:269-328`
- `test/integration/members_test.go:55-67`
- `docs/adr/0012-bootstrap-sessions-mfa-and-recovery.md:58-59`

### REVIEW-003 — High — TOTP throttle state is recorded but not enforced

`ConfirmTOTPEnrollment` and `RegenerateRecoveryCodes` call `mfaFailure` after
an invalid code, which updates throttle state, but neither operation calls
`checkThrottle` before the next verification. The progressive account delay
therefore has no effect on these endpoints. The generic per-IP HTTP limiter is
not a substitute for the account-level MFA control specified by ADR-0012.

Required outcome:

- Enforce the account throttle before every TOTP verification operation.
- Add integration tests that reach the threshold and receive `429` with
  `Retry-After` on enrollment confirmation and recovery-code regeneration.
- Account for parallel attempts so multiple requests cannot all pass a
  non-locking pre-check.

Relevant locations:

- `internal/identity/app/service.go:705-715`
- `internal/identity/app/service.go:749-759`

### REVIEW-004 — High — Audit redaction can be bypassed by typed containers

`audit.redactValue` recursively recognizes only `map[string]any` and `[]any`.
Nested `map[string]string`, structs, `json.RawMessage`, or other container
types fall through to JSON marshaling without sensitive-key inspection. For
example, a value shaped as
`map[string]any{"details": map[string]string{"token": rawToken}}` stores the
token unchanged.

Required outcome:

- Restrict audit metadata to a closed, safe value model, or normalize values
  into a JSON tree and recursively redact every object key before persistence.
- Reject opaque/raw JSON that cannot be inspected safely.
- Add tests for typed maps, nested structs, arrays, raw JSON, and secret values.

Relevant location:

- `internal/platform/audit/audit.go:139-176`

### REVIEW-005 — Medium — Password-reset bearer token accepted in URL query

`ResetPasswordPage` initializes the reset token from `?token=...`. This places
a reusable bearer credential in browser history and potentially in upstream
proxy/access logs. Invitation tokens correctly use a URL fragment instead.

Required outcome:

- Prefer manual entry or a fragment-based handoff that is cleared from the
  address bar before redemption.
- Add a frontend test proving the token is not read from or retained in the
  query string.

Relevant location:

- `web/src/features/auth/pages.tsx:336-345`

### REVIEW-006 — Medium — Frontend silently selects one arbitrary workspace

`useWorkspace` requests `limit: 1` and uses the first workspace ordered by
UUID. A user can belong to several workspaces through invitations, but the UI
has no workspace selector or workspace-aware route. After accepting an
invitation, it may continue operating on a different workspace.

Required outcome:

- Add explicit workspace selection and bind workspace/project routes and query
  keys to the selected workspace ID.
- Add tests for a user belonging to at least two workspaces.

Relevant location:

- `web/src/features/admin/workspace.ts:21-32`

### REVIEW-007 — Medium — Completion and normative-document status conflict

`docs/acceptance/MVP-05.md` and the MVP registry mark MVP-05 `COMPLETE`, while
ADR-0013 remains `Proposed` and the acceptance map explicitly says maintainer
review is still required. The completion claim therefore precedes its own
documented review gate.

Required outcome:

- Complete and record maintainer review of ADR-0013 before treating MVP-05 as
  complete.
- Re-run the relevant acceptance and repository gates after resolving this
  review's blocking findings.

Relevant locations:

- `docs/acceptance/MVP-05.md:4`
- `docs/acceptance/MVP-05.md:100-102`
- `docs/adr/0013-workspace-authorization-invitations-and-project-access.md:3`

### REVIEW-008 — Medium — Deactivation semantics contradict the catalog

The machine-readable permission catalog says `members.deactivate` revokes
sessions and tokens immediately. ADR-0013 and the integration test instead
state that the user's session remains valid for other workspaces. Both cannot
be normative simultaneously.

Required outcome:

- Decide whether deactivation is workspace-local or identity-wide.
- Update the catalog, ADR, application behavior, and tests together so the
  security contract is unambiguous.

Relevant locations:

- `docs/rbac/permission-catalog.json:23`
- `docs/adr/0013-workspace-authorization-invitations-and-project-access.md:62`
- `test/integration/members_test.go:86-97`

### REVIEW-009 — Low — Untracked stale OpenAPI package is not checked

The tree contains an obsolete generated package at
`internal/platform/httpserver/internal/platform/httpserver/openapi/openapi.gen.go`.
The normal generated-file consistency gate checks only
`internal/platform/httpserver/openapi/openapi.gen.go`, so this stale copy can
remain indefinitely and confuse maintenance or tooling.

Required outcome:

- Remove the obsolete generated package after confirming it is not an intended
  source.
- Extend the generated-file check to reject unexpected generated copies.

## Verification performed

- `make fmt-check` using the documented Git Bash shell: PASS.
- `make docs-check`: PASS.
- `go test -count=1 ./...`: PASS for unit-test packages.
- `npm run --silent test` in `web`: PASS, 21 tests.
- Integration test execution was attempted but the local environment could
  not create the PostgreSQL container: `rootless Docker is not supported on
  Windows`. This is an environment limitation, not a product-test result.
- No Git repository metadata is available in this workspace, so historical
  claims about failing-first tests, branches, commits, and clean-checkout CI
  could not be independently verified.

## Resolution (2026-10-23)

Each fix started with a test that failed for the reported reason; the test
then passed with the fix. Commands and results are listed under Evidence.

| Finding | Resolution | Proving tests |
|---|---|---|
| REVIEW-001 | Bootstrap requires a one-time `qali_setup_` token issued on the server with `qali setup-token` (1 hour, single use, keyed verifier in `qali.setup_tokens`, migration 00006). Missing, forged, expired, or used tokens answer `403 setup_token_invalid` before any hashing or writes. ADR-0012 amended; operator steps in `docs/DEVELOPMENT.md`. | `test/integration/setup_token_test.go`; `bootstrap_test.go` (one token per racer); `web/e2e/auth.spec.ts` (guessed token rejected, CLI token accepted) |
| REVIEW-002 | `identity.Authenticate` re-evaluates the MFA requirement on every request for sessions that never completed MFA: holding an Owner or Workspace Administrator membership turns them into `mfa_enrollment`/`mfa_challenge` (`domain.EffectiveState`). Applies to promotion and to invitation acceptance. The positive assertion in `members_test.go` was replaced by a security-negative one. | `TestPromotionToPrivilegedRoleRequiresMFA`, `TestRoleAndMembershipChangesApplyToTheNextRequest`, `TestEffectiveStateRequiresMFAForCurrentRoles`; `web/e2e/admin.spec.ts` (promoted tester must enroll) |
| REVIEW-003 | Every TOTP operation (challenge, step-up, enrollment confirmation, recovery-code regeneration) reserves the attempt under the throttle row lock before verifying (`reserveMFAAttempt`); a correct code clears the count. | `test/integration/mfa_throttle_test.go` (429 with `Retry-After` per operation; 20 parallel guesses, at most 5 verified) |
| REVIEW-004 | `audit.Redact` encodes metadata, decodes it into a plain JSON tree, and redacts every object key, so typed maps, structs, pointers, and raw JSON are inspected; unparseable raw JSON is rejected. | `TestRedactInspectsEveryValueShape` |
| REVIEW-005 | The reset page no longer reads the token from the URL; operators hand over the token only, users paste it. | `web/src/features/auth/reset.test.tsx` |
| REVIEW-006 | Workspace pages live under `/w/{workspaceId}/...` with an explicit workspace picker; query keys and requests use that ID; workspace-less links open the remembered or first workspace; an unknown ID shows "Workspace not found". | `web/src/features/admin/workspaces.test.tsx` |
| REVIEW-007 | MVP-05 returned to `IN_PROGRESS` until ADR-0013 is accepted by the maintainer; all gates were re-run after the fixes. | `docs/MVP_PLAN.md`, `docs/acceptance/MVP-05.md` |
| REVIEW-008 | Deactivation is workspace-local by decision; catalog, ADR-0013, and RBAC.md now say the same, matching the behavior and tests. | `TestRoleAndMembershipChangesApplyToTheNextRequest` (session stays valid, workspace blocked) |
| REVIEW-009 | The stray package was removed; `tools/gencheck/gencheck.sh` in `make fmt-check` rejects generated Go files outside known generator outputs. | `tools/gateselftest/run.sh::stray-generated` |

Also fixed while verifying: client-cancelled requests were logged as
internal errors with status 500, which would hide real failures; both HTTP
adapters now log them at info level with status 499
(`internal/workspace/adapter/httpapi/handler_test.go`).

### Evidence

| Date (UTC) | Command | Result |
|---|---|---|
| 2026-10-23 | `make fmt` then `make fmt-check` | PASS (includes the new generated-file guard) |
| 2026-10-23 | `make lint` | PASS: 0 issues, gitleaks clean, govulncheck 0 reachable, npm audit 0 |
| 2026-10-23 | `make test POSTGRES_MAJORS="17 18"` | PASS: unit, 25 frontend tests, integration on PostgreSQL 17 and 18, `covercheck: OK` |
| 2026-10-23 | `make test-e2e` | PASS 7/7 (`auth` and `admin` suites) |
| 2026-10-23 | `make build` | PASS, including the live Compose smoke test |
| 2026-10-23 | `make gate-selftest` | PASS 19/19, including the new `stray-generated` case |

Disposition: critical and high findings resolved. MVP-05 remains open only
for the maintainer's acceptance of ADR-0013.
