# Dependency Lock and Update Policy

Status: normative for every change that adds or updates a dependency  
Introduced by: MVP-01

## 1. Locking

| Ecosystem | Lock | Verified by |
|---|---|---|
| Go application | `go.mod`, `go.sum` | `go mod verify` and `go mod tidy -diff` in `make lint` / `make fmt-check` |
| Go developer tools | `tools/mod/<tool>.mod` and `.sum`, one file per tool | `go tool -modfile=...` resolves only locked versions |
| Frontend | `web/package.json` (exact versions), `web/package-lock.json` | `npm ci` in every gate |
| Container images | Tag plus `@sha256:` digest in `Dockerfile` and `test/integration` | Docker refuses mismatched digests |
| GitHub Actions | Full commit SHA with the release tag as a comment | GitHub resolves only that commit |
| Go toolchain | `toolchain` directive in `go.mod`; `GOTOOLCHAIN=local` in CI and image builds | Build fails on a different toolchain |

Rules:

- Versions are exact. No ranges in `package.json`, no floating image tags, no
  action tags without a SHA.
- Each Go developer tool has its own modfile so tool dependencies never change
  the versions used by the application (`go.mod`), and tools cannot conflict
  with each other.
- Dependencies used only by tests or tools are kept out of production code;
  the production image contains only the static binary (`Dockerfile`).

## 2. Admission of a new dependency

A new direct dependency needs, in the same change:

1. a reason it is needed and why the standard library or an existing dependency
   is insufficient;
2. a license compatible with Apache-2.0 (ADR-0001);
3. an active maintenance record and no unresolved high or critical advisory;
4. consistency with the preferred choices in `AGENTS.md`, or an ADR.

## 3. Updates

- Dependabot proposes weekly grouped updates for Go modules, npm, GitHub
  Actions, and Docker images (`.github/dependabot.yml`).
- **Cooldown:** a release is adopted only after it has been public for 14 days,
  to reduce exposure to compromised or quickly retracted releases. Security
  fixes for an advisory affecting Qali are exempt and applied promptly.
- Developer tools in `tools/mod/` are not covered by Dependabot; maintainers
  review them monthly with `go get -modfile=tools/mod/<tool>.mod -tool <path>@<version>`.
- An update passes the full gate set; major upgrades include release-note
  review and, when behavior changes, test updates justified per
  `docs/TESTING_POLICY.md`.

## 4. Scanning

- `govulncheck` runs in `make lint` and fails on reachable vulnerabilities.
- `npm audit --audit-level=high` runs in `make lint` and fails on high or
  critical advisories in the frontend dependency tree.
- `gitleaks` runs in `make lint` and fails on secrets in the tree.
- Container and license scanning of release artifacts, SBOM, and signing are
  delivered with MVP-15.

## 5. Recorded exceptions

| Date | Dependency | Exception | Reason |
|---|---|---|---|
| 2026-10-22 | `typescript` 5.9.3 | Not the newest major (6.x/7.x) | `openapi-typescript` 7.13.0 requires TypeScript 5.x; `typescript-eslint` 8.71 supports < 6.1 |
| 2026-10-22 | `playwright-core` 1.64.0 | Explicit dev dependency | Keeps `@axe-core/playwright`'s peer on the same version as `@playwright/test` to avoid duplicate, type-incompatible copies |
| 2026-10-22 | `golang.org/x/crypto` 0.56.0, `github.com/moby/go-archive` 0.3.0 | Adopted without the 14-day cooldown | Security fixes GO-2026-6354, GO-2026-6355, GO-2026-6253 became reachable when the test harness moved into `internal/platform/db/dbtest` |
