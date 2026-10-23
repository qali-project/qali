# MVP-00 acceptance map

Item: MVP-00 — Freeze decisions and acceptance language  
Status: COMPLETE  
Coordinator: implementation agent; maintainer review required  
Dependencies verified: none required

## Scope

Included:

- ADRs for product name, module path, license, supported Go/PostgreSQL/Node/
  browser matrix, URL and versioning conventions, UTC/timezone policy, and MVP
  data-retention defaults.
- Additional ADRs for decisions that later items would otherwise make
  inconsistently: credential model, roles and project access, result
  semantics, identifiers and case content, acceptance-map process.
- A machine-readable permission catalog for the fixed MVP roles.
- An acceptance-map template linking criterion, threat, test name, and result.
- Documentation link and duplicate-ID checks.

Excluded:

- Any application code, Go module, frontend project, migration, or OpenAPI
  document (MVP-01 and later).
- Hosted CI configuration: no hosting service is chosen yet.

## Threats

| Threat ID | Threat | Control |
|---|---|---|
| MVP-00.T-01 | An unresolved decision lets later items diverge on schema, API shape, credentials, or roles, causing rework or insecure defaults | ADR-0001 to ADR-0010; maintainer review before COMPLETE |
| MVP-00.T-02 | The role catalog grants administrative, owner-only, or token permissions to QA Lead, Tester, or Viewer | Catalog validation in `make docs-check` |
| MVP-00.T-03 | Ambiguous token prefixes let one credential type be parsed or accepted as another | Prefix-ambiguity check; ADR-0006 type separation |
| MVP-00.T-04 | Broken references or duplicate IDs make acceptance evidence unverifiable | Link, anchor, and duplicate-ID checks |
| MVP-00.T-05 | An item is marked COMPLETE without passing criteria | COMPLETE-requires-PASS check |

## Criteria

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| MVP-00.AC-01 | Product name, module path, license, platform matrix, URL/versioning conventions, UTC policy, and retention defaults are recorded as ADRs | MVP-00.T-01 | `tools/doccheck/doccheck.test.mjs::the real repository documentation passes every check`; maintainer review of ADR-0001 to ADR-0005 | PASS |
| MVP-00.AC-02 | A machine-readable permission catalog exists for the fixed MVP roles | MVP-00.T-02, MVP-00.T-03 | `tools/doccheck/doccheck.test.mjs`: catalog tests (duplicate permission, family.action format, unknown permission, unknown condition, administrative grant per role, owner-only, owner completeness, MVP role set, viewer access level, token prefixes, stale matrix, matrix rendering) | PASS |
| MVP-00.AC-03 | An acceptance-map template links criterion, threat, test name, and result | MVP-00.T-04, MVP-00.T-05 | `tools/doccheck/doccheck.test.mjs`: acceptance-map tests (duplicate criterion, foreign item, undefined threat, unknown result, missing test, unknown item, COMPLETE without PASS, COMPLETE without map) | PASS |
| MVP-00.AC-04 | No unresolved decision changes a migration, API shape, credential model, or role behavior in MVP-01 to MVP-15 | MVP-00.T-01 | Maintainer review of ADR-0001 to ADR-0010 against every MVP item; open questions below | PASS |
| MVP-00.AC-05 | Documentation link and duplicate-ID checks exist and fail on violations | MVP-00.T-04 | `tools/doccheck/doccheck.test.mjs`: link, anchor, code-fence, external-link, registry, and ADR tests | PASS |
| MVP-00.AC-06 | Documentation link and duplicate-ID checks run in CI | MVP-00.T-04 | Moved to MVP-01 by plan amendment; see Notes | N/A |
| MVP-00.AC-07 | No application code is started before the exit gate | MVP-00.T-01 | Repository tree contains no `go.mod`, `package.json`, `cmd/`, `internal/`, `web/`, `api/`, or `migrations/` (see Evidence) | PASS |

## Evidence

| Date (UTC) | Command | Result |
|---|---|---|
| 2026-10-22 | `node --test "tools/doccheck/*.test.mjs"` before `doccheck.mjs` existed | exit 1, `ERR_MODULE_NOT_FOUND` (expected) |
| 2026-10-22 | `make docs-test` | exit 0, 43 tests passed, 0 skipped |
| 2026-10-22 | `make docs-check` | exit 0, `doccheck: OK` |
| 2026-10-22 | `ls go.mod package.json cmd internal web api migrations` | none exist |
| 2026-10-22 | Maintainer review of ADR-0002 to ADR-0010 | all accepted; statuses set to `Accepted` |

## Failing-first evidence

- All checker tests were written before `tools/doccheck/doccheck.mjs`; the first
  run failed with `ERR_MODULE_NOT_FOUND`.
- After implementation, 41 fixture tests passed and
  `the real repository documentation passes every check` failed because
  `docs/adr/README.md`, `docs/rbac/permission-catalog.json`,
  `docs/rbac/permission-matrix.md`, and `docs/acceptance/TEMPLATE.md` were
  missing. It passed once those deliverables were added.
- The first full check then reported template paths such as
  `docs/acceptance/MVP-NN.md` as missing files. Classified as a valid test
  exposing missing behavior in the checker: the test
  `backticked placeholder paths with NN segments are patterns, not references`
  was added, observed failing, and then fixed in the checker; it also asserts
  that a real missing path is still reported.

## Notes and open questions

- The public product display name is open (ADR-0001). It is presentation-only
  and does not block AC-04 because the technical identifier `qali` is frozen.
- ADR-0001 to ADR-0010 are `Accepted` after maintainer review on 2026-10-22.
- AC-06 is `N/A`: on 2026-10-22 the maintainer chose GitHub as the host and
  amended `docs/MVP_PLAN.md` to move "checks run in CI" into MVP-01, where the
  CI pipeline is created. No hosted repository existed during MVP-00.
- MVP-00 marked `COMPLETE` on 2026-10-22: every criterion is `PASS` or `N/A`.
