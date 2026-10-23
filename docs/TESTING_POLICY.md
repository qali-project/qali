# Test Integrity Policy

Status: normative for every implementation change  
Goal: tests detect product defects instead of being adapted to conceal them

## 1. Core rule

A failing test is evidence to investigate. The default response is to correct
production code. Changing a test is permitted only when the written acceptance
criterion, security rule, migration contract, or public API contract is itself
incorrect or intentionally changed. That contract change and its rationale must
appear in the same reviewed change before the test is updated.

## 2. Forbidden ways to obtain a green build

Agents must not:

- delete, comment out, skip, quarantine, mark pending, or focus only a failing
  test without an approved issue and expiry;
- weaken an assertion, remove an important case, widen a tolerance, accept an
  additional status, or change an expected value merely to match current output;
- blindly update snapshots or golden files;
- replace real domain behavior with a mock of the unit under test;
- mock authorization, tenancy, cryptography, transaction, parser, or persistence
  behavior in the integration test intended to verify it;
- add retries, sleeps, unordered assertions, or large timeouts to hide a race or
  nondeterministic result;
- catch and ignore an error, return a constant, or add a test-only production
  branch solely to satisfy a test;
- reduce coverage thresholds or exclude changed security/domain code;
- treat a manually observed UI result as a substitute for an automated test.

## 3. Failure triage protocol

For every unexpected failure:

1. Reproduce it with the smallest existing command without editing code or test.
2. Read the assertion, fixture, acceptance criterion, and public contract.
3. Classify it as one of:
   - product defect;
   - valid test exposing missing behavior;
   - invalid/outdated test specification;
   - environment/tooling defect;
   - flaky/race defect.
4. Record evidence for the classification in the work-item notes.
5. For the first, second, fourth, or fifth classification, fix implementation or
   infrastructure and keep the behavioral assertion intact.
6. For an invalid test specification, change the normative requirement first,
   explain why the old requirement is wrong, and request review of that decision.
7. Run the isolated test repeatedly where race/flakiness is suspected, then run
   the full gate. A flaky test is a defect and blocks completion.

An agent may not self-approve a behavior-contract change whose only justification
is that the implementation currently behaves differently.

## 4. Test design rules

- Test observable behavior and invariants, not private function structure.
- Use table-driven unit tests for domain policies, transitions, validation,
  authorization decisions, and boundary conditions.
- Every happy path has at least one relevant negative or failure-path test.
- Every tenant-owned use case tests wrong-workspace and missing-project access.
- Every privileged use case tests insufficient role, insufficient scope, and
  stale/revoked credential behavior as applicable.
- Every mutation with retry potential tests idempotency and conflicting input.
- Every parser tests malformed, oversized, duplicate, and adversarial input.
- Time, UUID, randomness, and external effects enter through explicit interfaces
  so unit tests are deterministic; production implementations remain real.
- Mocks/fakes stand in only for a boundary dependency. A test must assert the
  resulting state or behavior, not merely that a mocked method was called.
- Prefer state-based assertions over implementation-coupled call counts.
- Regression tests must fail against the faulty behavior before the fix.

## 5. Required layers

### Unit tests

Fast, deterministic tests for domain and application behavior. They require no
network, database, filesystem, wall clock, or process-global state. Required for
every policy, transition, validation rule, calculation, parser core, and use-case
branch introduced by an item.

### Integration tests

Use a real supported PostgreSQL instance and real migrations for repositories,
transactions, constraints, row scoping, job claims, and database error mapping.
Use real cryptographic implementations with ephemeral test keys. Storage and
provider adapters use shared contract suites; HTTP tests exercise middleware and
serialization through the actual router.

### End-to-end tests

Playwright covers only critical user journeys named by the MVP plan. It must
assert persisted outcomes through the UI or public API, not only element
visibility. E2E tests are not a substitute for domain unit tests.

### Security-negative tests

Each item adds applicable tests for cross-workspace/project access, ID guessing,
role/scope denial, CSRF, replay, redaction, secret non-disclosure, body/size
limits, injection, unsafe redirects/SSRF, and revoked credentials.

## 6. Minimum gate for an MVP item

The item may close only when:

1. New acceptance tests were observed failing for the intended reason before the
   implementation or the item documents why an existing test already covered it.
2. Targeted unit and integration tests pass without skips.
3. Security-negative tests relevant to the item pass.
4. `make fmt`, `make lint`, `make test`, `make test-e2e`, and `make build` pass.
5. Go tests pass with race detection for concurrency-sensitive packages.
6. Generated API/client/schema output is clean and reproducible.
7. No snapshot/golden change is unexplained.
8. The item records commands, results, and the acceptance-criterion-to-test map.

Coverage is evidence, not the goal. Initial repository thresholds are 80% line
coverage for domain/application packages and 90% for authorization, token,
crypto, tenancy, and state-transition packages. A high percentage never replaces
missing behavioral assertions. Threshold exceptions require a written rationale
and follow-up item; security-critical packages receive no exception.

## 7. Test review checklist

- Would the test fail if the feature were removed or the policy were inverted?
- Does it assert the user-visible/domain outcome and important persisted state?
- Does it include boundary and denial cases rather than only a happy path?
- Can it pass because a mock returns the expected answer without exercising the
  implementation?
- Does it rely on ordering, time, retries, shared state, or external availability?
- Does a changed expected value correspond to an approved contract change?
- Would a malicious cross-tenant or lower-privilege request still be rejected?

If the first or last answer is no, or a middle risk is unexplained, the test does
not provide adequate evidence for completion.

