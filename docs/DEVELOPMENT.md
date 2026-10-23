# Development Guide

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Go | per `go.mod` `toolchain` | Older local Go downloads it automatically with `GOTOOLCHAIN=auto` |
| Node.js | 24 LTS (`web/.nvmrc`) | Build-time only |
| Docker | Engine running | Integration tests start disposable PostgreSQL containers; `make build` builds the image |
| GNU Make and Bash | any recent | On Windows, use Git Bash |

No other local service is required.

## Commands

```bash
make help
```

| Command | What it does |
|---|---|
| `make fmt` | Formats Go and TypeScript, tidies `go.mod`, regenerates OpenAPI code and the permission matrix |
| `make fmt-check` | Fails on unformatted code, untidy modules, or stale generated files including sqlc output (CI) |
| `make lint` | golangci-lint (including architecture boundaries and the clock rule), testguard, gitleaks, `go mod verify`, govulncheck, `npm audit`, TypeScript typecheck, ESLint, documentation checks |
| `make test` | Go and frontend unit tests, documentation checker tests, integration tests, then coverage thresholds on the combined profiles |
| `make test-e2e` | Builds the production binary and runs Playwright against it with a disposable, migrated PostgreSQL (`tools/e2eenv`) |
| `make build` | Builds the binary and the production image, checks the image, validates the Compose file, and starts the stack once to probe its exposure |
| `make gate-selftest` | Proves every gate fails on an injected defect (slow) |

Useful variables: `POSTGRES_MAJORS="17 18"` runs integration tests against
both supported majors; `RACE=1` enables the race detector (needs a C
compiler); `QALI_E2E_PORT` changes the first E2E server port. Each E2E suite
(`auth`, `admin`) runs its own server on consecutive ports over its own fresh
database, so every journey starts from an empty installation.

## Configuration

The process reads typed configuration at startup and refuses to start when
anything is missing or weak (`internal/platform/config`). Secrets are accepted
only as files; setting `QALI_KEK`, `QALI_TOKEN_PEPPER`, `QALI_PASSWORD_PEPPER`, or
`QALI_DATABASE_URL` directly is an error.

| Variable | Required | Meaning |
|---|---|---|
| `QALI_PUBLIC_URL` | yes | External origin, `https://...` (http only for localhost with `QALI_ENV=development`) |
| `QALI_DATABASE_URL_FILE` | yes | File with a `postgres://` URL; remote hosts need `sslmode=verify-full` or `verify-ca` |
| `QALI_KEK_FILE` | yes | Key-encryption key: base64 of 32 random bytes |
| `QALI_TOKEN_PEPPER_FILE` | yes | Token verifier pepper: base64 of 32 random bytes |
| `QALI_PASSWORD_PEPPER_FILE` | yes | Password pepper: base64 of 32 random bytes |
| `QALI_ENV` | no | `production` (default) or `development` |
| `QALI_HTTP_ADDR` | no | Listen address, default `:8080` |
| `QALI_TRUSTED_PROXIES` | no | Comma-separated CIDRs allowed to set `X-Forwarded-For` |

`qali migrate up` reads only `QALI_MIGRATION_DATABASE_URL_FILE` (the
`qali_migrator` role); the server never needs it. `qali healthcheck` exits 0 when
the local instance answers `/health/ready` with 200.

## Authentication

On first start the web UI asks for the owner account (`/setup`), then for
TOTP enrollment; ten single-use recovery codes are shown once. Owners and
workspace administrators must use TOTP (ADR-0012), including users promoted
into those roles later: their next request asks them to enroll or verify.

Claiming the installation needs a one-time setup token, so nobody who can
merely reach the URL can become the owner. Issue it on the server (valid for
one hour, single use) and paste it into the setup page:

```bash
docker compose -f deploy/compose/compose.yaml exec qali /usr/local/bin/qali setup-token
```

Account recovery without email:

- A user with a recovery code uses "Use a recovery code" on the sign-in page.
- Otherwise an operator issues a single-use reset token valid for 30 minutes
  from inside the container and hands it over out of band:

```bash
docker compose -f deploy/compose/compose.yaml exec qali /usr/local/bin/qali reset-password owner@example.org
```

  The user enters the token at `/reset-password`. Both paths sign out every
  session of the account.

Every `/api/v1` operation requires an active session unless the OpenAPI
operation declares `security: []`; operations available before MFA list the
allowed states in `x-qali-session-states`. When adding an operation, update
`internal/identity/adapter/httpapi/routes.go` only for public or pre-MFA
operations; `test/integration/routes_test.go` enforces the match.

The three keys must differ. Generate each with `openssl rand -base64 32`, or
create a complete throwaway set with `go run ./tools/devsecrets <dir>`.
Losing the KEK makes stored integration secrets unrecoverable; losing a pepper
invalidates all passwords or tokens. Back the key files up separately from the
database.

## Deployment

`deploy/compose/compose.yaml` runs Caddy, Qali, and PostgreSQL. Only Caddy
publishes a host port (`443/tcp`); Qali and PostgreSQL use internal networks,
all services drop Linux capabilities and run with read-only root filesystems.

```bash
cp deploy/compose/.env.example deploy/compose/.env
```

Edit `.env`, put the secret files into `QALI_SECRETS_DIR` with mode 0600
(`go run ./tools/devsecrets <dir>` generates a throwaway set): `kek`,
`token_pepper`, `password_pepper`, `postgres_password` (bootstrap superuser),
`migrator_password`, `app_password`, `database_url` (as `qali_app`), and
`migration_database_url` (as `qali_migrator`). Then start the stack:

```bash
docker compose -f deploy/compose/compose.yaml --env-file deploy/compose/.env up -d
```

`QALI_TLS=internal` uses Caddy's local CA; an email address obtains a public
certificate through the TLS-ALPN challenge on port 443, so port 80 stays
closed. On start, PostgreSQL creates the roles, the one-shot `migrate` service
applies migrations and exits, and `qali` starts once it has succeeded.

## Database

PostgreSQL has two application roles (ADR-0011): `qali_migrator` owns schema
`qali` and applies migrations; `qali_app` only reads and writes data. The
bootstrap script `deploy/postgres/initdb/10-qali-roles.sh` creates them; the
integration tests and the E2E environment run the same script.

- Migrations live in `migrations/` (goose, append-only, embedded in the binary).
- Queries live next to their package in `queries.sql`; `make generate` runs
  sqlc (needs a C compiler, because sqlc links the PostgreSQL parser).
- Repositories receive a `db.Querier` or `db.WriteTx` from `db.Store.Read` or
  `db.Store.Write`. A write commits only after recording an audit event.
- Tenant tables call `SELECT qali.enable_workspace_isolation('qali.<table>')` in
  their migration so row-level security filters by workspace.

## API changes

`api/openapi.yaml` is the source of truth. After editing it, run
`make generate` and commit the regenerated
`internal/platform/httpserver/openapi/openapi.gen.go` and
`web/src/generated/api.ts`. The frontend calls the backend only through
`web/src/api/client.ts`; ESLint rejects direct `fetch` elsewhere.

## Test rules

Read `docs/TESTING_POLICY.md`. `testguard` rejects skipped, focused, and
pending tests. A temporary exception needs an issue and an expiry date on the
same line, for example a trailing comment `testguard:allow QALI-12 2026-11-30`;
after the expiry the gate fails again.

## Windows notes

- `make` sets `TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=//var/run/docker.sock` so
  the testcontainers reaper works with Docker Desktop.
- Hyper-V reserves port ranges that change between boots. If the E2E server
  cannot bind, pick another port with `QALI_E2E_PORT` (check reserved ranges with
  `netsh interface ipv4 show excludedportrange protocol=tcp`).
