# ADR-0005: MVP data retention defaults

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

The MVP must define retention for audit events, soft-deleted test assets,
artifacts, and short-lived security records. Retention configuration UI,
permanent purge of test assets, and legal hold are outside the MVP scope lock
(`docs/MVP_PLAN.md` section 1), so the defaults must be safe without them.

## Decision

### Long-lived product data

| Data | MVP default | Notes |
|---|---|---|
| Audit events | Kept indefinitely | Append-only; no purge job in the MVP. Retention reduction is a deferred, sensitive operation. |
| Soft-deleted suites and cases | Kept indefinitely, restorable | Permanent purge is deferred; nothing is hard-deleted automatically. |
| Archived projects | Kept indefinitely, restorable | Archive is reversible; project hard deletion is deferred. |
| Case revisions | Kept indefinitely | Immutable. |
| Runs, run-case snapshots, result attempts | Kept indefinitely | Immutable history; never rewritten by later case edits or deletion. |
| Defects | Kept indefinitely | Soft-deleted defects remain restorable. |
| Attachments and automation artifacts referenced by retained data | Kept with their owner | Encrypted at rest (MVP-08). |
| Webhook and integration delivery history | 30 days | Metadata only; payload bodies are not retained after delivery. |
| Dead-lettered jobs | 30 days | Then deleted; the audit event remains. |

### Short-lived records

| Data | Lifetime |
|---|---|
| Unreferenced uploads (never attached to an entity) | Removed after 24 hours by reference-safe cleanup |
| Idempotency records | 24 hours after creation |
| Login throttling state | 24 hours after last attempt |
| OIDC state/nonce/PKCE records | 10 minutes, single use |
| Revoked or expired session rows | Deleted 30 days after expiry; audit events remain |
| Expired invitation and reset records | Deleted 30 days after expiry; audit events remain |
| Revoked or expired CI and MCP credential verifiers | Verifier material cleared at revocation/expiry; metadata kept for audit |

Credential and token lifetimes are defined in ADR-0006.

### Rules

1. Cleanup runs as PostgreSQL-backed jobs (MVP-03), is idempotent, and records
   counts (never content) in logs and metrics.
2. Cleanup must never delete an object still referenced by any entity in any
   workspace.
3. Backups follow the operator's schedule; restoring a backup can resurrect
   rows deleted by cleanup. This is documented in the MVP-15 runbook.
4. Changing any default above requires an ADR because it affects migrations,
   jobs, and operator expectations.

## Consequences

- Database size grows with history; operators get storage visibility, not
  automatic deletion. Configurable retention and purge arrive post-MVP.

## Alternatives considered

- Automatic purge of soft-deleted assets after 30 days: rejected for the MVP;
  permanent purge requires elevated permission and step-up flows that are
  deferred.
- Fixed audit retention (for example 400 days): rejected until retention
  configuration and export exist.
