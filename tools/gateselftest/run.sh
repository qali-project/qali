#!/usr/bin/env bash
# Validation fixture for MVP-01: proves the quality gates can fail.
#
# 1. Copies the tree without build outputs or dependencies (a clean checkout).
# 2. baseline: all AGENTS.md commands must pass on the unmodified copy.
# 3. Each later case injects one defect, runs the gate that must catch it,
#    requires a non-zero exit AND a case-specific marker in the output (so the
#    gate failed for the intended reason), then removes the defect.
# 4. reproducible-build: two builds must produce identical artifacts.
#
# Logs are kept in bin/gate-selftest/. Exit status is non-zero if any case fails.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
logs="$root/bin/gate-selftest"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rm -rf "$logs"
mkdir -p "$logs"

tar -C "$root" \
  --exclude=./.git \
  --exclude=./bin \
  --exclude=./web/node_modules \
  --exclude=./web/playwright-report \
  --exclude=./web/test-results \
  --exclude=./internal/platform/webui/dist/app \
  -cf - . | tar -C "$work" -xf -
cd "$work"

failures=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s: %s (log: %s)\n' "$1" "$2" "$logs/$1.log"; failures=$((failures + 1)); }

# expect_success <case> <command...>
expect_success() {
  local name=$1; shift
  if "$@" >>"$logs/$name.log" 2>&1; then return 0; fi
  fail "$name" "'$*' failed on an unmodified clean checkout"
  return 1
}

# expect_failure <case> <marker> <make target...>
expect_failure() {
  local name=$1 marker=$2; shift 2
  if make "$@" >"$logs/$name.log" 2>&1; then
    fail "$name" "make $* passed despite the injected defect"
  elif ! grep -qF -- "$marker" "$logs/$name.log"; then
    fail "$name" "make $* failed, but not with marker '$marker'"
  else
    pass "$name"
  fi
}

# Markers and patterns are assembled at runtime so this script never contains
# a skipped/focused test or a secret that the gates would flag in the repo.
skip_call="t.""Skip(\"selftest\")"
only_call="it.""only"

# --- baseline -------------------------------------------------------------
baseline_ok=1
for target in fmt fmt-check lint test test-e2e build; do
  expect_success baseline make "$target" || { baseline_ok=0; break; }
done
[ "$baseline_ok" = 1 ] && pass baseline

# --- injected defects -----------------------------------------------------
cat >internal/platform/httpserver/zz_selftest_test.go <<'EOF'
package httpserver_test

import "testing"

func TestSelftestInjectedFailure(t *testing.T) { t.Fatal("SELFTEST-GO-UNIT") }
EOF
expect_failure go-unit-failure SELFTEST-GO-UNIT test-unit
rm internal/platform/httpserver/zz_selftest_test.go

cat >web/src/zz-selftest.test.ts <<'EOF'
import { expect, it } from "vitest";

it("injected failure", () => {
  expect("SELFTEST-WEB-UNIT").toBe("expected value");
});
EOF
expect_failure web-unit-failure SELFTEST-WEB-UNIT test-unit
rm web/src/zz-selftest.test.ts

cat >test/integration/zz_selftest_test.go <<'EOF'
//go:build integration

package integration_test

import "testing"

func TestSelftestInjectedIntegrationFailure(t *testing.T) { t.Fatal("SELFTEST-INTEGRATION") }
EOF
expect_failure integration-failure SELFTEST-INTEGRATION test-integration
rm test/integration/zz_selftest_test.go

cat >web/e2e/zz-selftest.spec.ts <<'EOF'
import { expect, test } from "@playwright/test";

test("SELFTEST-E2E injected failure", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Not the real heading" })).toBeVisible({ timeout: 2000 });
});
EOF
expect_failure e2e-failure SELFTEST-E2E test-e2e
rm web/e2e/zz-selftest.spec.ts

printf 'package httpserver_test\n\nimport "testing"\n\nfunc TestSelftestSkip(t *testing.T) { %s }\n' "$skip_call" \
  >internal/platform/httpserver/zz_skip_test.go
expect_failure go-skip "skipped Go test" lint
rm internal/platform/httpserver/zz_skip_test.go

printf 'import { it } from "vitest";\n\n%s("focused", () => {});\n' "$only_call" >web/src/zz-focus.test.ts
expect_failure web-focus "focused, skipped, or pending test" lint
rm web/src/zz-focus.test.ts

cp api/openapi.yaml "$work/openapi.yaml.orig"
sed -i 's/summary: Liveness probe/summary: Liveness probe SELFTEST/' api/openapi.yaml
expect_failure stale-generated "stale: internal/platform/httpserver/openapi/openapi.gen.go" fmt-check
cp "$work/openapi.yaml.orig" api/openapi.yaml

mkdir -p internal/platform/zzfmt
printf 'package zzfmt\n\nfunc   Badly( ) int {return 1}\n' >internal/platform/zzfmt/zzfmt.go
expect_failure unformatted-go "zzfmt.go" fmt-check
rm -r internal/platform/zzfmt

mkdir -p internal/platform/zzsecret
# Read a finite random sample: piping /dev/urandom into head would end tr with
# SIGPIPE, which pipefail turns into a script failure.
key="AKIA$(head -c 4096 /dev/urandom | LC_ALL=C tr -dc 'A-Z2-7' | cut -c1-16)"
printf 'aws_access_key_id = %s\n' "$key" >internal/platform/zzsecret/credentials.txt
expect_failure secret "leaks found" lint
rm -r internal/platform/zzsecret

mkdir -p internal/zzselftest/domain
cat >internal/zzselftest/domain/domain.go <<'EOF'
package domain

import "net/http"

// StatusOK leaks an HTTP concern into the domain layer.
const StatusOK = http.StatusOK
EOF
expect_failure domain-boundary "depguard" lint
rm -r internal/zzselftest

mkdir -p internal/zzfeature/adapter internal/zzfeature/app
cat >internal/zzfeature/adapter/repo.go <<'EOF2'
package adapter

import "github.com/jackc/pgx/v5/pgxpool"

// Pool bypasses the scoped primitives.
var Pool *pgxpool.Pool
EOF2
expect_failure adapter-pool-import "not allowed from list 'feature-adapters'" lint
rm -r internal/zzfeature/adapter

cat >internal/zzfeature/app/app.go <<'EOF2'
package app

import (
	"context"

	"github.com/qali-project/qali/internal/platform/db"
)

// Sneak writes without an audit event.
func Sneak(ctx context.Context, s *db.Store) error {
	return s.PlatformWrite(ctx, func(context.Context, db.Querier) error { return nil })
}
EOF2
expect_failure unaudited-platform-write "PlatformWrite skips the audit requirement" lint
rm -r internal/zzfeature

cp docs/rbac/permission-catalog.json "$work/permission-catalog.json.orig"
sed -i '0,/"projects.manage_access": "all"/s//"projects.manage_access": "own"/' docs/rbac/permission-catalog.json
expect_failure stale-permission-catalog "stale: internal/authz/catalog_gen.go" fmt-check
cp "$work/permission-catalog.json.orig" docs/rbac/permission-catalog.json

mkdir -p internal/platform/httpserver/internal/platform/httpserver/openapi
cp internal/platform/httpserver/openapi/openapi.gen.go internal/platform/httpserver/internal/platform/httpserver/openapi/
expect_failure stray-generated "unexpected generated file" fmt-check
rm -r internal/platform/httpserver/internal

cp internal/platform/jobs/queries.sql "$work/queries.sql.orig"
sed -i 's/^-- name: CompleteJob :execrows$/-- name: CompleteJobSelftest :execrows/' internal/platform/jobs/queries.sql
expect_failure stale-sqlc "sqlc" fmt-check
cp "$work/queries.sql.orig" internal/platform/jobs/queries.sql

cat >internal/platform/crypto/zz_untested.go <<'EOF2'
package crypto

// selftestUntested adds statements without tests to lower coverage.
func selftestUntested(n int) int {
	total := 0
	for i := range n {
		switch {
		case i%2 == 0:
			total += i
		case i%3 == 0:
			total -= i
		case i%5 == 0:
			total *= 2
		default:
			total++
		}
		if total > 1000 {
			total = 0
		}
		if total < -1000 {
			total = 0
		}
	}
	for i := range n {
		total += i * 2
		total -= i
		total += i % 7
		total -= i % 11
		total += i % 13
		total -= i % 17
		total += i % 19
		total -= i % 23
	}
	return total
}
EOF2
expect_failure coverage-drop "below threshold" test
rm internal/platform/crypto/zz_untested.go

cp deploy/compose/compose.yaml "$work/compose.yaml.orig"
sed -i 's|^    secrets: \[postgres_password, migrator_password, app_password\]|&\n    ports: ["5432:5432"]|' deploy/compose/compose.yaml
expect_failure compose-postgres-port "postgres publishes host ports" deploy-check
cp "$work/compose.yaml.orig" deploy/compose/compose.yaml

# --- reproducibility ------------------------------------------------------
digest() {
  { sha256sum bin/qali*; find internal/platform/webui/dist/app -type f -print0 | sort -z | xargs -0 sha256sum; } \
    | sed 's/ \*/  /'
}
if expect_success reproducible-build make build-binary; then
  first="$(digest)"
  make clean >/dev/null
  if expect_success reproducible-build make build-binary; then
    second="$(digest)"
    if [ "$first" = "$second" ]; then
      pass reproducible-build
    else
      diff <(echo "$first") <(echo "$second") >>"$logs/reproducible-build.log" || true
      fail reproducible-build "two builds produced different artifacts"
    fi
  fi
fi

echo
if [ "$failures" -gt 0 ]; then
  echo "gate-selftest: $failures case(s) failed"
  exit 1
fi
echo "gate-selftest: all cases passed"
