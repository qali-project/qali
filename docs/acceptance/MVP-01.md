# MVP-01 acceptance map

Item: MVP-01 — Repository skeleton and executable quality gates  
Status: COMPLETE  
Coordinator: implementation agent  
Dependencies verified: MVP-00 COMPLETE (2026-10-22)

## Scope

Included:

- Go module `github.com/qali-project/qali` (ADR-0001, ADR-0002) with the
  directory boundaries from AGENTS.md: `cmd/qali`, `internal/<module>/{domain,app,adapter}`,
  `internal/platform`, `api`, `migrations`, `web`, `test`.
- An empty application: one binary serving the embedded web placeholder and
  `GET /health/live` described in the OpenAPI skeleton.
- React/TypeScript/Vite placeholder that calls the API through the generated
  client.
- OpenAPI skeleton plus generation of Go server types and the TypeScript client.
- `make fmt`, `make lint`, `make test`, `make test-e2e`, `make build`, plus
  `make fmt-check` for CI and `make gate-selftest` for the validation fixture.
- Go and TypeScript formatting and static analysis, architecture-boundary lint
  for domain packages, a direct-clock lint (ADR-0004).
- Unit, integration (disposable PostgreSQL container), and Playwright E2E harnesses.
- GitHub Actions workflow, dependency lock and update policy, secret scanning,
  vulnerability scanning, minimal non-root production image, `LICENSE`, and
  `SECURITY.md`.

Excluded (later items):

- Typed configuration, secrets, cryptography, security headers, Compose
  deployment, reverse proxy (MVP-02).
- Migrations runner, database roles, readiness, logging, metrics, jobs (MVP-03).
- Router, TanStack Query, forms, Tailwind tokens, and Radix primitives in the
  frontend (introduced by the first feature item that needs them).
- Coverage thresholds: no domain or application package exists yet; the
  threshold gate is added with the first such package (see Notes).

## Threats

| Threat ID | Threat | Control |
|---|---|---|
| MVP-01.T-01 | Gates that cannot fail let defects merge with a green pipeline | Validation fixture injects failures into every gate and asserts failure |
| MVP-01.T-02 | Skipped or focused tests silently reduce coverage | `testguard` in lint; Vitest `allowOnly: false`; Playwright `forbidOnly` |
| MVP-01.T-03 | Generated API code drifts from the OpenAPI contract | `make fmt-check` regenerates into a temporary directory and compares |
| MVP-01.T-04 | Secrets committed to the repository | `gitleaks` in lint |
| MVP-01.T-05 | Production image ships a shell, compiler, package manager, source `.env`, or test keys, or runs as root | Distroless static base, `imagecheck` in build |
| MVP-01.T-06 | Unpinned or vulnerable dependencies enter the build | Lockfiles, `npm ci`, `go mod verify`, `govulncheck`, Dependabot policy |
| MVP-01.T-07 | Domain code imports HTTP/SQL frameworks, eroding boundaries | `depguard` rules for `internal/*/domain` |

## Criteria

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| MVP-01.AC-01 | All five commands in AGENTS.md execute from a clean checkout | MVP-01.T-01 | `tools/gateselftest/run.sh::baseline` | PASS |
| MVP-01.AC-02 | A deliberately failing Go unit, frontend unit, integration, and E2E test each make the corresponding gate fail | MVP-01.T-01 | `tools/gateselftest/run.sh::go-unit-failure`, `::web-unit-failure`, `::integration-failure`, `::e2e-failure` | PASS |
| MVP-01.AC-03 | Skipped and focused tests are rejected | MVP-01.T-02 | `tools/testguard/testguard_test.go`; `tools/gateselftest/run.sh::go-skip`, `::web-focus` | PASS |
| MVP-01.AC-04 | Stale generated files and unformatted code are rejected | MVP-01.T-03 | `tools/gateselftest/run.sh::stale-generated`, `::unformatted-go` | PASS |
| MVP-01.AC-05 | Production image contains no source `.env`, test key, compiler, shell, or package manager and runs as non-root | MVP-01.T-05 | `tools/imagecheck/imagecheck_test.go`; `make build` runs `imagecheck` on the built image | PASS |
| MVP-01.AC-06 | CI runs the MVP-00 documentation checks | - | `.github/workflows/ci.yml` job `docs`; moved to MVP-15 by plan amendment, see Notes | N/A |
| MVP-01.AC-07 | Secrets in the tree fail lint | MVP-01.T-04 | `tools/gateselftest/run.sh::secret` | PASS |
| MVP-01.AC-08 | Domain packages cannot import HTTP, SQL, or router frameworks | MVP-01.T-07 | `tools/gateselftest/run.sh::domain-boundary` | PASS |
| MVP-01.AC-09 | The OpenAPI sample endpoint is generated into Go server types and a typed frontend client used by the UI | MVP-01.T-03 | `internal/platform/httpserver/server_test.go`; `web/src/App.test.tsx`; `web/e2e/home.spec.ts` | PASS |
| MVP-01.AC-10 | Dependencies are locked and verified; update policy is documented | MVP-01.T-06 | `make lint` (`go mod verify`, `govulncheck`), `npm ci`; `docs/DEPENDENCIES.md`; `.github/dependabot.yml` | PASS |
| MVP-01.AC-11 | The application binary and web bundle build reproducibly | MVP-01.T-01 | `tools/gateselftest/run.sh::reproducible-build` | PASS |
| MVP-01.AC-12 | Every CI job fails on a deliberately failing test in a validation fixture on GitHub | MVP-01.T-01 | `.github/workflows/ci.yml` job `gate-selftest`; moved to MVP-15 by plan amendment, see Notes | N/A |

## Evidence

| Date (UTC) | Command | Result |
|---|---|---|
| 2026-10-22 | `go test ./tools/...` before `testguard`/`imagecheck` existed | build failed: `undefined: Scan`, `undefined: CheckFilesystem` (expected) |
| 2026-10-22 | `go test ./internal/...` before `httpserver` existed | build failed: no non-test Go files (expected) |
| 2026-10-22 | `npx vitest run` before `App.tsx` existed | failed: cannot resolve `./app/product` (expected) |
| 2026-10-22 | `make gate-selftest` | exit 0; 12/12 cases PASS: baseline, go-unit-failure, web-unit-failure, integration-failure, e2e-failure, go-skip, web-focus, stale-generated, unformatted-go, secret, domain-boundary, reproducible-build |
| 2026-10-22 | `make fmt-check` | exit 0 |
| 2026-10-22 | `make lint` | exit 0; golangci-lint 0 issues, testguard OK, gitleaks no leaks, `go mod verify` OK, govulncheck no vulnerabilities, `npm audit` 0 vulnerabilities, typecheck and ESLint clean, doccheck OK |
| 2026-10-22 | `make test POSTGRES_MAJORS="17 18"` | exit 0; Go unit packages ok, Vitest 3/3, doccheck tests 43/43, integration ok on PostgreSQL 17.11 and 18.6 |
| 2026-10-22 | `make test-e2e` | exit 0; Playwright 3/3 on Chromium (liveness, client route, axe WCAG 2.2 AA) |
| 2026-10-22 | `make build` | exit 0; image `qali:dev`, user 65532:65532, `imagecheck` OK |
| 2026-10-22 | `make gate-selftest` (re-verification after the session break) | exit 0; 12/12 cases PASS |
| 2026-10-22 | `go run ./tools/imagecheck node:24-bookworm-slim` | exit 1; 2003 findings (negative control) |

## Failing-first evidence

- `testguard`, `imagecheck`, the HTTP server, and the frontend `App` tests were
  written first and failed for missing code (see Evidence).
- `TestLogTimestampsAreUTC` was added with the UTC log fix; reverting the fix
  makes it fail with `time = "2026-10-22T07:03:00+05:00"`.
- Defects found by the new gates and fixed in product or tooling, not by
  weakening tests: missing error response in the OpenAPI contract (typed client
  claimed liveness cannot fail), local-time log timestamps (ADR-0004),
  `oapi-codegen` ignoring `-o` when the config sets an output (stale check
  compared a file with itself), POSIX temp paths unusable by native Windows Go,
  Hyper-V reserved E2E port, testcontainers reaper on Docker Desktop, and a
  SIGPIPE in the fixture's random-key generation.

## Notes and open questions

- AC-06 and AC-12 are `N/A`: on 2026-10-22 the maintainer amended
  `docs/MVP_PLAN.md` so the first green GitHub Actions run becomes an MVP-15
  release precondition, because no hosted repository exists. Locally the same
  make targets pass, and `make gate-selftest` proves each gate fails on an
  injected defect. The Linux `RACE=1` CI path has not run yet; tracked in
  `docs/BACKLOG.md`.

- No git repository exists by maintainer decision. The validation fixture
  simulates a clean checkout by copying the tree without ignored build outputs.
  AC-06 and AC-12 need the workflow to run on GitHub and stay `PENDING` until then.
- Coverage thresholds from `docs/TESTING_POLICY.md` section 6 apply to domain,
  application, and security packages; none exist yet. Recorded in the backlog
  for the first item that adds one (MVP-02).
- MVP-01 marked `COMPLETE` on 2026-10-22: every criterion is `PASS` or `N/A`.
