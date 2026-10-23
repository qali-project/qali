# ADR-0012: Bootstrap, sessions, MFA, and account recovery

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-04

## Context

MVP-04 delivers first-owner bootstrap, local login, TOTP for Owner and
Workspace Administrator, recovery codes, cookie sessions, CSRF, revocation,
recovery without email, throttling, and authentication audit events.
ADR-0006 fixed token formats and lifetimes; this record fixes the data model
and flows that later items (MVP-05 RBAC, MVP-06 OIDC) build on.

## Decision

### Identity data

- `users` are global identities (not workspace-owned): normalized email
  (NFKC, lower case, unique), display name, Argon2id password hash, status,
  encrypted TOTP secret, last accepted TOTP step, MFA enrollment time, and a
  `version` for optimistic concurrency.
- Bootstrap creates the first user, a minimal `workspaces` row, and an
  `owner` row in `workspace_members`. MVP-05 adds invitations, other roles,
  projects, and permission checks to these tables; MVP-04 only writes the
  bootstrap owner. `workspace_members` is workspace-isolated (ADR-0011).
- Bootstrap is race-safe through a single-row `installation` table whose
  `bootstrapped_at` is set in the same transaction; a second attempt gets
  `409 already_bootstrapped`. The setup endpoints answer only while the
  installation is not bootstrapped.

### Sessions

- `sessions` store the `qali_sess_` lookup ID and keyed verifier (ADR-0006), a
  separate CSRF token verifier, state, idle and absolute expiry, MFA time, and
  revocation time. Raw values exist only in the cookie and in responses.
- States: `mfa_enrollment` (password verified, privileged user without TOTP;
  only enrollment endpoints allowed), `mfa_challenge` (password verified,
  TOTP required), and `active`. Any state change issues a new session ID and
  revokes the old one (fixation defense).
- Cookie `__Host-qali_session`: `Secure`, `HttpOnly`, `SameSite=Lax`,
  `Path=/`, no `Domain`. Idle 12 h, absolute 7 days.
- CSRF: a per-session synchronizer token derived as a keyed MAC of the session
  token (stored only as a digest), returned by session endpoints and
  sent as `X-CSRF-Token` on unsafe requests that carry the session cookie;
  login and bootstrap (no session yet) rely on the origin checks (MVP-02).
- Logout revokes the current session; "log out everywhere" revokes all
  sessions of the user. A password change or recovery revokes all sessions.
- Every `/api/v1` operation requires an `active` session unless the OpenAPI
  operation declares `security: []`; a router test enforces this for every
  operation in the contract.

### MFA

- TOTP per ADR-0006 (SHA-1, 6 digits, 30 s, +/-1 step, no step reuse). The
  secret (160 bits) is envelope-encrypted with an installation DEK stored in
  `encryption_keys` and bound to the user ID as associated data.
- Owner and Workspace Administrator must enroll before their session becomes
  `active`. Users who enrolled voluntarily are always challenged.
- Confirming enrollment returns 10 recovery codes once.

### Recovery without email

- Recovery code format `XXXX-XXXX-XXXX-XXXX` (base32): the first group is a
  lookup ID, the rest is hashed with the password service (Argon2id + pepper).
  Each code is single use; using one resets the password, consumes the code,
  and revokes all sessions. Regenerating codes invalidates the old set.
- Operator-assisted reset: `qali reset-password <email>` (local command inside
  the container) prints a single-use `qali_reset_` token valid 30 minutes; the
  user redeems it at the reset page. The command writes an operator audit
  event.

### Throttling

- Failed login, MFA, recovery, and reset attempts update throttle rows keyed
  by HMAC of the normalized account identifier and by client IP. After 5
  failures per account (20 per IP) each further attempt waits
  `2^(n-5)` seconds, capped at 15 minutes; success resets the account key.
  There is no permanent lockout. Throttled requests get `429` with
  `Retry-After` and the same body for existing and unknown accounts.
- Unknown accounts run a dummy password verification so timing does not
  reveal account existence.

### Audit

Authentication events (`auth.bootstrap`, `auth.login`, `auth.login_failed`,
`auth.mfa_enroll`, `auth.mfa_challenge_failed`, `auth.logout`,
`auth.logout_all`, `auth.recovery_used`, `auth.password_reset_issued`,
`auth.password_reset`) go to the system chain with the user ID as target and
never include passwords, codes, or tokens.

## Consequences

- MVP-05 extends existing workspace and membership tables instead of creating
  them; the bootstrap owner keeps working.
- OIDC (MVP-06) resolves to the same `users` row and session model.

## Alternatives considered

- Email-based recovery: excluded from the MVP scope lock.
- Storing recovery codes without a lookup ID: every attempt would need up to
  ten Argon2id verifications.
- Double-submit CSRF cookies: a server-side synchronizer token bound to the
  session is simpler to rotate and revoke.

## Amendment 2026-10-23 (security review REVIEW-001..003)

The security review in `docs/reviews/MVP-00-05-security-review-2026-10-23.md`
found three gaps in this design; the following now apply:

- First-owner bootstrap requires a one-time `qali_setup_` token issued on the
  server with `qali setup-token` (1 hour, single use, stored as a keyed
  verifier in `qali.setup_tokens`). Without it `POST /api/v1/setup/owner`
  answers `403 setup_token_invalid`; a remote caller cannot claim a fresh
  installation.
- The MFA requirement follows the user's current roles, not the session's
  creation-time state: an active session that never completed MFA is treated
  as `mfa_enrollment` (or `mfa_challenge` if TOTP is enrolled) on every
  request once the user holds an Owner or Workspace Administrator membership.
- Every TOTP-verifying operation (challenge, step-up, enrollment
  confirmation, recovery-code regeneration) reserves the attempt under the
  account throttle's row lock before verifying, so parallel guesses cannot
  share one pre-check; a correct code clears the count.
- A password change keeps the previous session's MFA time (ADR-0013).
