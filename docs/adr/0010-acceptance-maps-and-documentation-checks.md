# ADR-0010: Acceptance maps and documentation checks

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

`docs/TESTING_POLICY.md` requires each item to record an
acceptance-criterion-to-test map. MVP-00 requires an acceptance-map template
linking criterion, threat, test name, and result, and documentation link and
duplicate-ID checks that run in CI.

## Decision

### Identifier scheme

| Kind | Format | Defined in |
|---|---|---|
| Work item | `MVP-NN` | `docs/MVP_PLAN.md` registry and one `### MVP-NN — Title` section |
| Decision record | `ADR-NNNN` | `docs/adr/NNNN-slug.md`, listed in `docs/adr/README.md` |
| Acceptance criterion | `MVP-NN.AC-NN` | `docs/acceptance/MVP-NN.md` |
| Threat | `MVP-NN.T-NN` | `docs/acceptance/MVP-NN.md` |
| Permission | `family.action` | `docs/rbac/permission-catalog.json` |
| Credential scope | `resource:action` | `docs/rbac/permission-catalog.json` |

Test names or doc comments reference the criterion they prove, for example a
Go test comment `// Proves MVP-04.AC-03.`

### Acceptance maps

- Every item has `docs/acceptance/MVP-NN.md` created from
  [the template](../acceptance/TEMPLATE.md) when the item starts.
- Each criterion row names at least one test and a result: `PASS`, `FAIL`,
  `PENDING`, or `N/A` (with a reason in the notes).
- The registry may mark an item `COMPLETE` only if its map exists and every
  criterion is `PASS` or `N/A`. The check enforces this.

### Documentation checks

`tools/doccheck/doccheck.mjs` (Node.js, no dependencies) runs via
`make docs-check` and verifies:

- relative Markdown links and heading anchors resolve, and backticked
  `docs/...` paths exist; external URLs are not fetched, to keep the check
  deterministic and offline;
- the MVP registry has unique IDs, consecutive order, valid statuses, at most one
  `IN_PROGRESS` item, strictly top-to-bottom advancement, one section per ID,
  and dependencies only on earlier items;
- ADR numbers are unique and match titles, statuses are valid, and every ADR is
  indexed;
- the permission catalog has unique, well-formed IDs, exactly the MVP roles,
  no administrative grants to QA Lead/Tester/Viewer, no owner-only grants
  outside Owner, a complete Owner grant set, a read-only viewer access level,
  and unambiguous credential prefixes;
- the generated permission matrix is up to date;
- acceptance maps have unique IDs of their own item, defined threats, named
  tests, and valid results.

The checker's own tests run via `make docs-test`.

### CI

The checks are packaged as `make` targets so that the CI pipeline created in
MVP-01 calls them unchanged.

Amendment 2026-10-22 (maintainer): GitHub is the chosen host, but no hosted
repository exists yet. The criterion "checks run in CI" moved from MVP-00 to
MVP-01 by an amendment to `docs/MVP_PLAN.md`.

## Consequences

- Broken cross-references and duplicate IDs fail fast and locally.
- The checker is tooling, not application code, and is replaced or extended in
  MVP-01 only through reviewed changes to its tests.

## Alternatives considered

- Third-party Markdown link checkers: rejected; they add dependencies and fetch
  external URLs, making the check network-dependent.
- A Go checker: deferred; the Go module is created in MVP-01, and Node.js is
  already a required build tool (ADR-0002).
