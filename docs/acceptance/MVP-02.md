# MVP-02 acceptance map

Item: MVP-02 — Secure runtime, configuration, and cryptography  
Status: COMPLETE  
Coordinator: implementation agent  
Dependencies verified: MVP-01 COMPLETE (2026-10-22)

## Scope

Included:

- Typed configuration (`internal/platform/config`). Secrets are read only from
  `<NAME>_FILE` paths; plain environment variables for secrets are rejected.
  Required: `QALI_PUBLIC_URL`, `QALI_DATABASE_URL_FILE`, `QALI_KEK_FILE`,
  `QALI_TOKEN_PEPPER_FILE`, `QALI_PASSWORD_PEPPER_FILE` (ADR-0006: three distinct
  key files).
- Redacted secret types (`internal/platform/secret`) that never print, log, or
  serialize their value.
- Cryptography (`internal/platform/crypto`): envelope encryption with versioned
  KEK, per-workspace DEK, AES-256-GCM, and bound associated data; keyed bearer
  token generation and verification; Argon2id password hashing with pepper and
  rehash detection (ADR-0006).
- HTTP hardening middleware on the real router: request IDs, panic-safe RFC 9457
  errors, security headers, body limit, per-client rate limit, and origin /
  Fetch-Metadata checks for unsafe browser requests.
- Production Compose (`deploy/compose`) with edge, app, and internal data
  networks; reverse proxy publishing only `443/tcp`; secrets as mounted files.
- Coverage gate for the security packages (backlog item from MVP-01).

Excluded (later items):

- Database access, migrations, roles, readiness, logging pipeline, metrics
  (MVP-03). PostgreSQL runs in Compose but the application does not connect yet.
- Sessions, session-bound CSRF tokens, login, MFA (MVP-04). This item provides
  the origin/Fetch-Metadata layer that MVP-04 combines with CSRF tokens.
- KMS/Vault key providers (deferred), key-rotation tooling beyond decrypting
  data sealed under an older KEK version.

## Threats

| Threat ID | Threat | Control |
|---|---|---|
| MVP-02.T-01 | Database dump discloses usable secrets, tokens, or passwords | Envelope encryption, keyed token verifiers, peppered Argon2id; keys only in mounted files |
| MVP-02.T-02 | Ciphertext is moved to another workspace, owner, or secret type and decrypts there | AES-GCM associated data binds workspace, owner, secret type, and schema version |
| MVP-02.T-03 | Secrets leak through logs, errors, JSON, or `fmt` output | `secret.Value` redacts in every formatting path; config holds secrets only as typed values |
| MVP-02.T-04 | Weak, missing, reused, or example key material starts a production instance | Fail-closed configuration validation |
| MVP-02.T-05 | Cross-site request forgery against browser endpoints | Origin and Fetch-Metadata checks on unsafe methods |
| MVP-02.T-06 | Resource exhaustion through large bodies or request floods | Body limit (413) and per-client rate limit (429) |
| MVP-02.T-07 | Error responses disclose stack traces or internals | Panic recovery to problem details with request ID only |
| MVP-02.T-08 | Clickjacking, MIME sniffing, mixed content, data leakage via referrer | Security headers on every response |
| MVP-02.T-09 | Database, application, metrics, or debug ports reachable from the host network | Compose publishes only the proxy's 443/tcp; data network is internal |
| MVP-02.T-10 | Token forgery, guessing, or cross-type reuse | 256-bit secrets, per-type HKDF keys, constant-time verification, prefix checks |

## Criteria

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| MVP-02.AC-01 | Envelope encryption round-trips; wrong KEK, wrong context, tampered ciphertext/nonce/wrapped DEK, and unknown versions fail | MVP-02.T-01, MVP-02.T-02 | `internal/platform/crypto/envelope_test.go` | PASS |
| MVP-02.AC-02 | Secret values are redacted in `fmt` verbs, `slog`, JSON, and errors | MVP-02.T-03 | `internal/platform/secret/secret_test.go` | PASS |
| MVP-02.AC-03 | Missing, weak, reused, example, or plain-environment secret configuration fails closed with an actionable error | MVP-02.T-04 | `internal/platform/config/config_test.go` | PASS |
| MVP-02.AC-04 | Tokens verify only with the right pepper, type, and value; malformed, cross-type, and tampered tokens fail | MVP-02.T-10 | `internal/platform/crypto/token_test.go` | PASS |
| MVP-02.AC-05 | Argon2id hashes verify with the pepper only, and weaker parameters report rehash | MVP-02.T-01 | `internal/platform/crypto/password_test.go` | PASS |
| MVP-02.AC-06 | A database-shaped fixture contains no plaintext secret or usable token | MVP-02.T-01 | `internal/platform/crypto/dbfixture_test.go` | PASS |
| MVP-02.AC-07 | Origin/Fetch-Metadata, body limit, safe error, rate limit, request ID, and security headers work through the real router | MVP-02.T-05, MVP-02.T-06, MVP-02.T-07, MVP-02.T-08 | `internal/platform/httpserver/middleware_test.go` | PASS |
| MVP-02.AC-08 | Deployment publishes only 443/tcp and PostgreSQL/application/metrics/debug are not host-accessible | MVP-02.T-09 | `tools/deploycheck/deploycheck_test.go`; `make test-deploy` | PASS |
| MVP-02.AC-09 | Security packages meet the 90% coverage threshold | MVP-02.T-01 | `make test` coverage gate (`tools/covercheck`) | PASS |

## Evidence

| Date (UTC) | Command | Result |
|---|---|---|
| 2026-10-22 | `go test ./internal/platform/secret/` before `secret.go` existed | build failed: no non-test Go files (expected) |
| 2026-10-22 | `go vet ./internal/platform/crypto/` before implementation | no non-test Go files (expected) |
| 2026-10-22 | `go vet ./internal/platform/config/` before implementation | no non-test Go files (expected) |
| 2026-10-22 | `go vet ./internal/platform/httpserver/` with new middleware tests | `undefined: httpserver.Options` (expected) |
| 2026-10-22 | `go vet ./tools/deploycheck/`, `./tools/covercheck/` before implementation | `undefined: CheckCompose`, `undefined: Parse` (expected) |
| 2026-10-22 | DB-fixture mutation: token verifier with the pepper ignored | `TestDatabaseShapedFixtureContainsNoUsableSecret` FAIL: "session verifier validated without the pepper"; restored, PASS |
| 2026-10-22 | `make test-unit` | exit 0; coverage secret 100%, config 98.1%, crypto 91.0%, httpserver 89.8%; `covercheck: OK` |
| 2026-10-22 | `make test-e2e` | exit 0; 4/4 Playwright (liveness, CSP with no console errors, client route, axe) |
| 2026-10-22 | `make deploy-check` | `deploycheck: static configuration OK`; injected postgres `ports` → finding, exit 1 |
| 2026-10-22 | `make test-deploy` | exit 0; stack up on 18443, liveness and security headers through Caddy, PostgreSQL healthy as uid 70 with `cap_drop: ALL`, only proxy 443/tcp published, stack removed |
| 2026-10-22 | `make gate-selftest` | exit 0; 14/14 PASS incl. baseline (fmt, fmt-check, lint, test, test-e2e, build with live Compose), coverage-drop, compose-postgres-port |
| 2026-10-22 | `make test-integration POSTGRES_MAJORS="17 18"` | exit 0 on PostgreSQL 17 and 18 |
| 2026-10-22 | `make fmt-check`, `make lint` | exit 0; golangci-lint 0 issues, testguard OK, gitleaks no leaks, govulncheck 0 reachable (5 unreachable in required modules), npm audit 0 |

## Failing-first evidence

- Every new test file was written before its implementation and failed for
  missing code (see Evidence). The DB-shaped fixture test (AC-06) exercises
  behavior that already existed when it was written, so it was mutation-checked
  instead: removing the pepper from token verification makes it fail.
- `tools/devsecrets` was written together with its test (developer tooling);
  its postgres-password behavior was then added test-first.
- Defects found while wiring and fixed in code, not by weakening tests: shared
  rate-limit budget in the HTTP test fixture (fixture split into generous and
  strict options), De Morgan simplification, unchecked helper returns.

## Notes and open questions

- Contract change recorded: unsafe HTTP methods now require same-origin
  evidence (Origin, Referer, or `Sec-Fetch-Site: same-origin`) unless the
  request carries an `Authorization` header (`docs/SECURITY_ARCHITECTURE.md`
  section 6). `server_test.go` sends `Origin` for its 405 check accordingly.
- Client-supplied `X-Request-ID` is ignored; the server always generates the ID.
- The reverse proxy (Caddy) runs as the image's root user with `cap_drop: ALL`
  plus `NET_BIND_SERVICE`, `no-new-privileges`, and a read-only root
  filesystem; the strict non-root rule applies to the Qali image and PostgreSQL
  (uid 70).
- KEK and pepper rotation are supported by the crypto API (versioned keyrings,
  `Rewrap`); configuration loads a single version until a rotation item adds
  multi-version files.
- `gosec` rules G101/G117/G304 are excluded for `_test.go` fixtures, and
  G304/G703 for `tools/` (paths from their own command line); `gitleaks` still
  scans tests.
- govulncheck reports 5 vulnerabilities in required modules that the code does
  not call (container and test dependencies); the gate fails only on reachable
  findings.
- MVP-02 marked `COMPLETE` on 2026-10-22: every criterion is `PASS`.
