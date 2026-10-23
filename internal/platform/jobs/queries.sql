-- name: InsertJob :one
INSERT INTO qali.jobs (
  id, queue, kind, payload, workspace_id, status, attempts, max_attempts,
  run_at, idempotency_key, created_at, updated_at
) VALUES (
  sqlc.arg(id), sqlc.arg(queue), sqlc.arg(kind), sqlc.arg(payload), sqlc.narg(workspace_id),
  'pending', 0, sqlc.arg(max_attempts), sqlc.arg(run_at), sqlc.narg(idempotency_key),
  sqlc.arg(now), sqlc.arg(now)
)
ON CONFLICT (kind, idempotency_key) DO NOTHING
RETURNING id;

-- name: JobByIdempotencyKey :one
SELECT id FROM qali.jobs WHERE kind = sqlc.arg(kind) AND idempotency_key = sqlc.arg(idempotency_key);

-- name: ClaimJobs :many
-- Takes up to max_jobs due jobs, or jobs whose lease expired, that still
-- have attempts left. SKIP LOCKED lets concurrent workers claim disjoint sets.
UPDATE qali.jobs
SET status = 'running',
    attempts = attempts + 1,
    locked_until = sqlc.arg(locked_until),
    updated_at = sqlc.arg(now)
WHERE id IN (
  SELECT j.id
  FROM qali.jobs j
  WHERE j.queue = sqlc.arg(queue)
    AND j.attempts < j.max_attempts
    AND ((j.status = 'pending' AND j.run_at <= sqlc.arg(now))
      OR (j.status = 'running' AND j.locked_until < sqlc.arg(now)))
  ORDER BY j.run_at, j.id
  FOR UPDATE SKIP LOCKED
  LIMIT sqlc.arg(max_jobs)
)
RETURNING id, queue, kind, payload, workspace_id, attempts, max_attempts, run_at;

-- name: CompleteJob :execrows
UPDATE qali.jobs
SET status = 'succeeded', locked_until = NULL, finished_at = sqlc.arg(now), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND status = 'running';

-- name: RetryJob :execrows
UPDATE qali.jobs
SET status = 'pending', locked_until = NULL, run_at = sqlc.arg(run_at),
    last_error = sqlc.arg(last_error), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND status = 'running';

-- name: KillJob :execrows
UPDATE qali.jobs
SET status = 'dead', locked_until = NULL, finished_at = sqlc.arg(now),
    last_error = sqlc.arg(last_error), updated_at = sqlc.arg(now)
WHERE id = sqlc.arg(id) AND status = 'running';

-- name: DeadLetterExpired :execrows
-- Running jobs whose lease expired with no attempts left: the worker crashed
-- on the final attempt.
UPDATE qali.jobs
SET status = 'dead', locked_until = NULL, finished_at = sqlc.arg(now),
    last_error = 'lease expired on final attempt', updated_at = sqlc.arg(now)
WHERE status = 'running' AND locked_until < sqlc.arg(now) AND attempts >= max_attempts;
