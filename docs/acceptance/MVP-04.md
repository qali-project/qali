# MVP-04 acceptance map

Item: MVP-04 — Bootstrap, local authentication, MFA, and sessions  
Status: COMPLETE  
Coordinator: implementation agent  
Dependencies verified: MVP-03 COMPLETE (2026-10-22)

## Scope

Included (design in ADR-0012):

- Race-safe first-owner bootstrap creating the first user, a minimal workspace,
  and the owner membership.
- Local login with enumeration-safe errors and throttling; logout and log out
  everywhere; cookie sessions with rotation, idle and absolute expiry.
- TOTP enrollment and challenge, mandatory for Owner and Workspace
  Administrator; ten single-use recovery codes.
- Recovery without email: recovery codes and an operator CLI that issues a
  single-use reset token.
- Session-bound CSRF tokens on unsafe requests.
- Authentication audit events.
- Frontend pages for setup, login, MFA enrollment and challenge, recovery, and
  password reset, with the E2E journey.

Excluded (later items):

- Invitations, other roles, projects, and permission enforcement (MVP-05).
- OIDC (MVP-06), WebAuthn, email delivery.
- Administrative session management for other users (MVP-05).

## Threats

| Threat ID | Threat | Control |
|---|---|---|
| MVP-04.T-01 | Two concurrent bootstrap requests create two owners, or bootstrap is replayed after setup | Single-row installation flag set transactionally; setup closed afterwards |
| MVP-04.T-02 | Login responses or timing reveal which accounts exist | Generic errors, dummy verification, identical throttling |
| MVP-04.T-03 | Credential stuffing or online guessing | Per-account and per-IP progressive throttling without permanent lockout |
| MVP-04.T-04 | Session fixation or a stolen pre-MFA session reaching protected data | New session ID on every state change; restricted pre-MFA states |
| MVP-04.T-05 | Cross-site request forgery with the session cookie | Session-bound synchronizer token plus origin checks |
| MVP-04.T-06 | Revoked, expired, or logged-out sessions keep working | Server-side session state checked on every request |
| MVP-04.T-07 | Recovery codes or reset tokens reused | Single-use consumption in the same transaction; expiry |
| MVP-04.T-08 | TOTP codes replayed within their window | Last accepted step stored per user |
| MVP-04.T-09 | Passwords, codes, TOTP secrets, or tokens leak through the database or logs | Argon2id with pepper, keyed verifiers, envelope encryption, redacted logs and audit |
| MVP-04.T-10 | A feature route is reachable without authentication | Contract-wide router test over every OpenAPI operation |

## Criteria

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| MVP-04.AC-01 | Password policy, hashing, and rehash on login behave as specified | MVP-04.T-09 | `internal/identity/domain/password_test.go`; `test/integration/auth_test.go` | PASS |
| MVP-04.AC-02 | TOTP accepts the current and adjacent steps only and rejects replay | MVP-04.T-08 | `internal/identity/domain/totp_test.go`; `test/integration/auth_test.go` | PASS |
| MVP-04.AC-03 | Recovery codes are single use and regeneration invalidates the old set | MVP-04.T-07 | `internal/identity/domain/recovery_test.go`; `test/integration/recovery_test.go` | PASS |
| MVP-04.AC-04 | Sessions rotate on state changes and expire by idle and absolute limits | MVP-04.T-04, MVP-04.T-06 | `internal/identity/domain/session_test.go`; `test/integration/session_test.go` | PASS |
| MVP-04.AC-05 | Throttling delays grow, cap, reset on success, and never lock out permanently | MVP-04.T-03 | `internal/identity/domain/throttle_test.go`; `test/integration/auth_test.go` | PASS |
| MVP-04.AC-06 | Concurrent bootstrap creates exactly one owner; setup is closed afterwards | MVP-04.T-01 | `test/integration/bootstrap_test.go` | PASS |
| MVP-04.AC-07 | Unknown and known accounts get identical errors and throttling | MVP-04.T-02 | `test/integration/auth_test.go` | PASS |
| MVP-04.AC-08 | CSRF tokens are required and session-bound; fixation is prevented | MVP-04.T-04, MVP-04.T-05 | `test/integration/session_test.go` | PASS |
| MVP-04.AC-09 | Logout, log out everywhere, password change, and recovery revoke sessions immediately | MVP-04.T-06 | `test/integration/session_test.go`; `test/integration/recovery_test.go` | PASS |
| MVP-04.AC-10 | Recovery codes and operator reset tokens cannot be replayed | MVP-04.T-07 | `test/integration/recovery_test.go` | PASS |
| MVP-04.AC-11 | No password, code, TOTP secret, or token appears in the database, logs, or audit | MVP-04.T-09 | `test/integration/secrets_test.go` | PASS |
| MVP-04.AC-12 | Every OpenAPI operation without `security: []` rejects unauthenticated and pre-MFA requests | MVP-04.T-10 | `test/integration/routes_test.go` | PASS |
| MVP-04.AC-13 | Authentication events are audited with attribution | MVP-04.T-09 | `test/integration/auth_test.go` | PASS |
| MVP-04.AC-14 | E2E: bootstrap, MFA enrollment, logout, login with TOTP, recovery | MVP-04.T-04 | `web/e2e/auth.spec.ts` | PASS |

## Evidence

| Date (UTC) | Command | Result |
|---|---|---|
| 2026-10-22 | `go vet ./internal/identity/domain/` before implementation | no non-test Go files (expected) |
| 2026-10-22 | `go vet -tags integration ./test/integration/` with auth tests before the identity module existed | package `internal/identity/adapter/httpapi` not found (expected) |
| 2026-10-22 | `TestUserScopeSeesOnlyOwnMemberships` before the store set `qali.user_id` | FAIL "user scope saw 0 memberships, want own 2" (expected) |
| 2026-10-22 | Mutation: `CheckCSRF` accepts a missing token | `TestCSRFTokenIsRequiredAndSessionBound` FAIL "missing token: 204"; restored, PASS |
| 2026-10-22 | Mutation: rotation does not revoke the previous session | `TestSessionIDRotatesOnEveryStateChange` FAIL "the pre-enrollment session survived enrollment"; restored, PASS |
| 2026-10-22 | `go test ./internal/identity/domain/` | PASS, 99.1% coverage; TOTP matches RFC 6238 vectors |
| 2026-10-22 | `make test-integration RACE=1 POSTGRES_MAJORS="17 18"` | exit 0 on PostgreSQL 17 and 18, no data races |
| 2026-10-22 | `make cover-check` | OK: identity domain 99.1%, app >= 80%, httpapi >= 80%, postgres 94.6%, plus earlier packages |
| 2026-10-22 | `make test-e2e` | 6/6 Playwright incl. the owner journey (bootstrap, TOTP enrollment, recovery codes, sign-out, sign-in with TOTP, recovery, replay rejected) with axe checks |
| 2026-10-22 | `make fmt-check`, `make lint` | exit 0; golangci-lint 0 issues, ESLint clean |
| 2026-10-22 | `make gate-selftest` | exit 0; 17/17 PASS incl. baseline of all five commands with live Compose |

## Failing-first evidence

- Backend acceptance tests (bootstrap, auth, session, recovery, secrets,
  routes) and domain unit tests were written before the implementation and
  failed for missing packages; key controls were additionally mutation-checked.
- Written after implementation, as coverage of existing behavior:
  `test/integration/auth_edge_test.go`, the frontend unit tests, and the E2E
  journey (UI and API were built together).
- Test specifications corrected before they ever passed: the route test
  treated a business `invalid_code` as an authentication rejection; the
  absolute-expiry loop used 165 h instead of more than 168 h; the rehash test
  first relied on a test-only production method and was rewritten to store a
  weaker hash with the real pepper; E2E waited too little for recovery codes,
  matched a section heading as a field label, and counted expected 401 console
  messages as CSP violations.
- Defects found and fixed in product code: migration Down order (policy
  dependency); CSRF tokens could not be re-read after a page reload (now a
  keyed MAC of the session token); error logs lacked the root cause.

## Notes and open questions

- ADR-0012 was accepted by the maintainer on 2026-10-22.
- Contract changes recorded: the home page requires a session; E2E home
  checks now cover the public shell; `GET /api/v1/auth/session` returns the
  derived CSRF token; migrations tests derive the expected versions.
- Coverage: `internal/identity/app` uses the 80% application-layer threshold
  from `docs/TESTING_POLICY.md` section 6 (90% was initially set here and
  exceeded the policy); the identity domain with session and throttle state
  transitions uses 90%. The remaining uncovered lines are database-error
  propagation inside transactions.
- Secure `__Host-` cookies work over `http://127.0.0.1` in Chromium during
  E2E; production always uses HTTPS.
- MVP-04 marked `COMPLETE` on 2026-10-22: every criterion is `PASS`.

## Post-completion review (2026-10-23)

The security review `docs/reviews/MVP-00-05-security-review-2026-10-23.md`
found three defects in this item's scope: a public first-owner takeover
(REVIEW-001), MFA bypass through later promotion (REVIEW-002), and an
unenforced TOTP throttle (REVIEW-003). All three are fixed with
security-negative tests and an ADR-0012 amendment; see the review's
resolution log for tests and evidence.
