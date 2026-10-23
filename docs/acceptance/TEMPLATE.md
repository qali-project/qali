# Acceptance map template

Copy this file to `docs/acceptance/MVP-NN.md` when an item becomes
`IN_PROGRESS`, replace `NN`, and keep it current until the item is complete.
Rules and ID formats are defined in ADR-0010; `make docs-check` validates the
tables.

---

# MVP-NN acceptance map

Item: MVP-NN — Title  
Status: IN_PROGRESS  
Coordinator: name or agent  
Dependencies verified: list items and their status

## Scope

Included:

- Restate included behavior from `docs/MVP_PLAN.md`.

Excluded:

- Restate excluded or deferred behavior that must not be implemented.

## Threats

One row per threat this item introduces or must control. IDs are
`MVP-NN.T-NN`.

| Threat ID | Threat | Control |
|---|---|---|
| (ID) | What an attacker or failure could do | How the item prevents or detects it |

## Criteria

One row per acceptance criterion. IDs are `MVP-NN.AC-NN`. "Threat IDs" lists
threat IDs from the table above, comma separated, or `-`. "Tests" names every
test that proves the criterion, as `path::TestName` or the exact test title.
"Result" is `PASS`, `FAIL`, `PENDING`, or `N/A` (explain in Notes).

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| (ID) | Observable behavior | (threat IDs) | `path::TestName` | PENDING |

## Evidence

Record every command run for the gate with its result and date.

| Date (UTC) | Command | Result |
|---|---|---|
| YYYY-MM-DD | `make test` | exit 0, N tests |

## Failing-first evidence

For each new test, the failing run before implementation and the reason it
failed.

## Notes and open questions

- Decisions deferred to review, `N/A` reasons, and backlog entries created.
