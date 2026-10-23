# ADR-0006: Credential model and token format

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

AGENTS.md and `docs/SECURITY_ARCHITECTURE.md` section 4 require distinct
credential types with least-privilege scopes, non-recoverable storage, and key
separation. MVP-02, MVP-04, MVP-05, MVP-06, MVP-11, and MVP-15 implement
credentials; their storage, format, and lifetimes must not be re-decided per item.

## Decision

### Credential types in the MVP

| Type | Prefix | Holder | Transport | Default lifetime |
|---|---|---|---|---|
| Browser session | `qali_sess_` | Human | `__Host-qali_session` cookie, `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/` | Idle 12 h, absolute 7 days |
| Password reset | `qali_reset_` | Human (operator-assisted or recovery flow) | One-time link or code | 30 minutes, single use |
| Invitation | `qali_inv_` | Invitee | One-time link shown once | 7 days, single use |
| CI credential | `qali_ci_` | Automation for one project | `Authorization: Bearer` | Default 90 days, maximum 365 days |
| MCP token | `qali_mcp_` | Human, for an MCP client | `Authorization: Bearer` on `/mcp` | Default 30 days, maximum 90 days |
| Recovery code | none; 10 codes of 16 base32 characters | Human with MFA | Login form | Single use, until regenerated |

Reserved for later items, with no MVP issuance: `qali_pat_` personal API
tokens, `qali_svc_` service accounts, and `qali_oat_`/`qali_ort_` OAuth access and
refresh tokens. Personal API tokens are not part of the MVP scope lock; humans
use the REST API through the browser session in the MVP. Webhook signing
secrets are not bearer tokens and use envelope encryption (below).

The machine-readable list lives in `docs/rbac/permission-catalog.json`
(`credentialTypes`) and is checked for unambiguous prefixes.

### Token format and verification

- Bearer value: `<prefix><lookupId>_<secret>` where `lookupId` is 16 lowercase
  base32 characters (80 random bits, non-secret, indexed) and `secret` is 43
  base64url characters (256 random bits) from a CSPRNG.
- Storage: `lookupId`, `verifier = HMAC-SHA-256(K_type, prefix || lookupId || secret)`,
  `keyVersion`, type, scopes, project, holder, `createdAt`, `expiresAt`,
  `lastUsedAt`, `revokedAt`. Raw tokens are never stored, logged, placed in jobs
  or audit metadata, or returned after creation.
- `K_type` is derived per credential type with HKDF-SHA-256 from the token pepper
  (`info = "qali/token/<type>/v<keyVersion>"`). The pepper is a mounted secret file,
  never stored in PostgreSQL. Verification uses constant-time comparison.
- Each type has its own table or partition-by-type with a type check, its own
  audience, and its own route allowlist; a token of one type is rejected
  everywhere another type is expected. No credential can be exchanged for another.
- Session IDs rotate on login, MFA completion, privilege change, and step-up.

### Passwords and recovery codes

- Argon2id with per-record salt and encoded parameters; installation defaults
  `m = 64 MiB, t = 3, p = 1`, never below `m = 19 MiB, t = 2`. Parameters are
  rehashed on successful login when below current defaults.
- KDF input is `HMAC-SHA-256(password_pepper, password)`; the password pepper is
  a separate mounted secret from the token pepper.
- Password length 12-256 characters (Unicode NFKC normalized), no composition
  rules, rejected if equal to the email/username.
- Recovery codes are hashed like passwords; each is single use and every use is
  audited.

### MFA and step-up

- TOTP (RFC 6238, SHA-1, 6 digits, 30 s step, +/-1 step tolerance, no reuse of
  an accepted step) is mandatory for Owner and Workspace Administrator before
  any administrative permission is usable.
- Sensitive operations (permission catalog `sensitive: true`) require MFA
  verification within the last 10 minutes.

### Local login and OIDC (IMPLEMENTATION_PLAN decision 4)

- Local password login is enabled by default. An administrator may disable it
  for ordinary users after OIDC is configured and verified.
- Owners always retain a protected break-glass local login with password and
  TOTP, even when local login is disabled for others. Using it raises a
  high-severity audit event.
- OIDC identities link to an existing user only through an explicit, logged-in
  linking flow or a verified email claim from the configured issuer.

### Recoverable secrets

- Integration secrets, OIDC client secrets, and webhook signing secrets use
  envelope encryption: AES-256-GCM, 96-bit random nonce, per-workspace DEK
  wrapped by the KEK from a mounted file, associated data
  `workspaceId|ownerType|ownerId|secretType|schemaVersion`.
- Stored columns: ciphertext, nonce, algorithm identifier, DEK ID, KEK version.
  The KEK, token pepper, and password pepper are three distinct mounted files.

## Consequences

- A database dump cannot validate guessed tokens or passwords without the
  separately mounted peppers, and cannot decrypt secrets without the KEK.
- Losing the peppers invalidates all tokens and passwords; losing the KEK makes
  integration secrets unrecoverable. MVP-15 documents key backup.

## Alternatives considered

- Hashing tokens with plain SHA-256: rejected; a dump would allow offline
  verification of leaked candidates.
- JWT access tokens for CI/MCP: rejected; revocation requires server state
  anyway, and opaque tokens avoid algorithm-confusion risks.
- `SameSite=Strict` session cookie: rejected; it breaks the OIDC redirect
  return. CSRF tokens plus origin checks cover mutations.
