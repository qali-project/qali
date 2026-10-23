# Backlog

Findings recorded during MVP work that are outside the active item. Entries do
not expand the active item's scope (AGENTS.md workflow step 6).

| Found in | Finding | Needed by |
|---|---|---|
| MVP-00 | GitHub is the chosen host (2026-10-22), but no git or GitHub repository exists yet. The first green run of `.github/workflows/ci.yml` (including `docs`, `gate-selftest`, and `RACE=1` on Linux) is an MVP-15 release precondition by plan amendment. Run it as soon as the repository exists. | First push; MVP-15 |
| MVP-00 | The public product display name is undecided (ADR-0001). Presentation-only; update the single UI/backend display-name constants once chosen. | Before MVP-15 release |
| MVP-00 | `docs/RBAC.md` and `docs/PRODUCT_SCOPE.md` describe seven roles and personal API tokens; ADR-0006 and ADR-0007 restrict the MVP to five roles and no personal API tokens. Reconcile wording when the post-MVP roadmap resumes. | Post-MVP |
| MVP-01 | Coverage thresholds had no gate. Resolved in MVP-02: `tools/covercheck` in `make test-unit`; each new domain, application, or security package must be added to `COVER_THRESHOLDS`. | Resolved |
| MVP-01 | The validation fixture simulates a clean checkout by copying the tree, because no git repository exists. Switch it to `git clone`/`git worktree` once the repository exists. | When git is introduced |
| MVP-00 | `tools/doccheck` is a Node.js script because the Go module did not exist yet. Resolved in MVP-01: kept as is, because Node.js is a required build tool (ADR-0002); any future port must keep its tests. | Resolved |
| MVP-02 | Configuration loads one KEK and pepper version; rotation needs multi-version key files and a rewrap command (crypto API already supports versions). | Key-rotation item |
| MVP-02 | `qali` container had no healthcheck. Resolved in MVP-03: `qali healthcheck` probes `/health/ready`. | Resolved |
| MVP-03 | Each new tenant table must call `qali.enable_workspace_isolation`; add a contract test that fails when a table with `workspace_id` lacks the policy. Resolved in MVP-05: `TestEveryTenantTableIsIsolated`. | Resolved |
| MVP-03 | Retention cleanup jobs from ADR-0005 (dead-lettered jobs, idempotency, expired sessions) are not scheduled yet; the queue supports them. | Item that first creates such records |
| MVP-04 | `make cover-check` run alone after partial test runs can merge a stale unit profile with a fresh integration profile and report wrong numbers; `make test` always regenerates both. Make covercheck reject profiles older than the sources. | Tooling |
| MVP-04 | Firefox and WebKit E2E runs (ADR-0002) are not yet part of a gate; the auth journey runs on Chromium only. | MVP-15 |
| MVP-05 | The identity module still writes `workspaces`/`workspace_members` at bootstrap and reads roles at login, while the workspace module owns those tables from MVP-05. Move both behind the workspace application interface. | Cross-cutting refactor item |
| MVP-05 | Denied authorization attempts are not audited (audit has a `denied` outcome). Decide which denials to record without flooding the log. | Audit/observability item |
| MVP-05 | The invitation page asks an existing user to sign in and reopen the link; returning to the link after sign-in automatically would be friendlier. | UX polish |
| Review 2026-10-23 | Security review of MVP-00 through MVP-05 (bootstrap takeover, MFA bypass on promotion, TOTP throttle, audit redaction, contract/UI inconsistencies). Resolved 2026-10-23; see the review's resolution log. ADR-0013 acceptance is still pending. | Resolved |
| Review 2026-10-23 | Password login still uses a non-locking throttle pre-check, so parallel guesses can exceed the account threshold the way TOTP guesses could before REVIEW-003. Apply the same attempt reservation to login and recovery-code redemption. | Before MVP-15 release |
