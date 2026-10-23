-- PostgreSQL-backed job queue (IMPLEMENTATION_PLAN 4.2): claims use
-- FOR UPDATE SKIP LOCKED with a lease; failures retry with backoff until
-- max_attempts, then the job is dead-lettered.

-- +goose Up
CREATE TABLE qali.jobs (
  id              uuid        PRIMARY KEY,
  queue           text        NOT NULL CHECK (queue ~ '^[a-z][a-z0-9_]*$'),
  kind            text        NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$'),
  payload         jsonb       NOT NULL DEFAULT '{}'::jsonb,
  workspace_id    uuid,
  status          text        NOT NULL CHECK (status IN ('pending', 'running', 'succeeded', 'dead')),
  attempts        integer     NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts    integer     NOT NULL CHECK (max_attempts BETWEEN 1 AND 100),
  run_at          timestamptz NOT NULL,
  locked_until    timestamptz,
  last_error      text        CHECK (last_error IS NULL OR length(last_error) <= 2000),
  idempotency_key text        CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 1 AND 255),
  created_at      timestamptz NOT NULL,
  updated_at      timestamptz NOT NULL,
  finished_at     timestamptz,
  CHECK ((status = 'running') = (locked_until IS NOT NULL)),
  CHECK ((status IN ('succeeded', 'dead')) = (finished_at IS NOT NULL)),
  UNIQUE (kind, idempotency_key)
);

CREATE INDEX jobs_claimable ON qali.jobs (queue, run_at) WHERE status = 'pending';
CREATE INDEX jobs_leased ON qali.jobs (queue, locked_until) WHERE status = 'running';

-- +goose Down
DROP TABLE qali.jobs;
