# ADR-0008: Result status semantics and report arithmetic

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

MVP-10 records manual results, MVP-11/12 ingest automated results, and MVP-13
reports counts and rates. MVP-13 explicitly relies on "skipped and untested
semantics chosen in MVP-00". Without one definition, manual and automated
results and reports would disagree.

## Decision

### Statuses

| Status | Meaning | Counts as executed | In pass-rate denominator |
|---|---|---|---|
| `passed` | Verified to meet expectations | yes | yes |
| `failed` | Did not meet expectations, including automation errors | yes | yes |
| `blocked` | Could not be executed because of an external impediment | yes | yes |
| `skipped` | Intentionally not executed in this run | yes | no |
| `untested` | No result recorded yet | no | no |

- `untested` is the implicit state of a run case with no attempt; it is never
  submitted as an attempt.
- Automation `error` (JUnit `<error>`) maps to `failed` with
  `failureKind = "error"`; assertion failures use `failureKind = "failure"`.
- Statuses are a closed set in the MVP. Custom labels are deferred.

### Attempts

- Result attempts are append-only. The current result of a run case is its
  latest accepted attempt by server sequence; earlier attempts are
  `superseded` and remain readable.
- A correction is a new attempt; nothing is updated in place.
- Automation retries within one upload produce one attempt per execution; the
  last execution determines the current status, and `retryCount` plus earlier
  failures stay visible.

### Step results

- Steps use the same statuses except `blocked` requires a comment.
- The overall status is chosen by the tester, subject to validation: it cannot
  be `passed` if any step is `failed` or `blocked`. If any step is `failed`, the
  UI proposes `failed`.

### Report arithmetic

- `total` = run cases in the snapshot. Counts per status use current attempts.
- `progress` = (total - untested) / total.
- `passRate` = passed / (passed + failed + blocked).
- Rates are returned as integer basis points (0-10000), rounded half up, and
  `null` when the denominator is zero. The UI shows one decimal place.
- Duration of a run case is the `durationMs` of its current attempt; run
  duration is the sum over current attempts; wall-clock elapsed time is
  `completedAt - createdAt` and reported separately.
- Manual/automated split is by the source of the current attempt.
- Aggregates are computed only over rows the requester may read (ADR-0007).

## Consequences

- Reports exclude `skipped` from pass rate so intentional skips do not hide
  failures or inflate success.
- One normalization function maps JUnit, native JSON, and manual inputs to
  these statuses, with unit tests for every mapping.

## Alternatives considered

- Counting `blocked` outside the pass-rate denominator: rejected; blocked work
  is a release risk that should lower the rate.
- Floating-point percentages in the API: rejected; rounding would differ
  between clients.
