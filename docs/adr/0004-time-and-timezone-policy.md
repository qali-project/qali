# ADR-0004: Time and timezone policy

Status: Accepted  
Date: 2026-10-22  
Work item: MVP-00

## Context

AGENTS.md requires UTC in storage and API and rendering in the user's locale.
Time also drives session expiry, TOTP windows, token TTLs, job retries,
durations, and report boundaries, all of which must be deterministic in tests.

## Decision

1. **Storage.** Every instant is a PostgreSQL `timestamptz`. The database
   session time zone is set to `UTC` by the connection configuration.
   `timestamp without time zone` is forbidden for instants. Calendar dates (none
   in the MVP) would use `date`.
2. **Precision.** Instants are stored with PostgreSQL microsecond precision and
   serialized with millisecond precision.
3. **API output.** RFC 3339 in UTC with a `Z` suffix and exactly three
   fractional digits: `2026-10-22T14:03:07.120Z`. Field names end in `At`
   (`createdAt`, `completedAt`).
4. **API input.** Instants must carry an explicit offset (`Z` or `+hh:mm`) and
   are normalized to UTC. Inputs without an offset are rejected with `400`.
5. **Durations.** Integer milliseconds (`durationMs`), non-negative. Durations
   reported by clients (manual timer, automation) are stored as reported and
   bounded to 7 days; server-measured intervals use the monotonic clock where
   available.
6. **Clock injection.** Domain and application code obtain time only through a
   `Clock` interface. Production uses the system clock in UTC; tests use a fixed
   or manually advanced clock. Direct calls to `time.Now()` outside the clock
   adapter fail lint (enforced from MVP-01).
7. **Rendering.** The frontend renders instants with `Intl.DateTimeFormat` in the
   browser's locale and time zone. A per-user time zone/locale preference is
   deferred; when added, it overrides the browser default.
8. **Reports.** MVP reports operate on instants and counts, not calendar days, so
   no server-side time-zone bucketing is required. Any later day/week bucketing
   must take an explicit IANA time zone parameter.
9. **Logs.** Structured logs use RFC 3339 UTC timestamps.

## Consequences

- Tests never depend on the wall clock or the host time zone.
- CSV export writes UTC RFC 3339 instants; spreadsheet users convert locally.

## Alternatives considered

- Storing a user time zone alongside each instant: rejected; unnecessary for
  instants and a source of inconsistency.
- Unix epoch numbers in the API: rejected; less readable and error-prone units.
