-- name: LockChain :exec
-- Serializes appends to one chain until the transaction ends.
SELECT pg_advisory_xact_lock(hashtextextended('qali.audit:' || sqlc.arg(chain)::text, 0));

-- name: LastHash :one
SELECT hash
FROM qali.audit_events
WHERE chain = sqlc.arg(chain)
ORDER BY seq DESC
LIMIT 1;

-- name: InsertEvent :exec
INSERT INTO qali.audit_events (
  id, chain, workspace_id, occurred_at, actor_type, actor_id, action,
  target_type, target_id, outcome, request_id, source_ip, metadata, prev_hash, hash
) VALUES (
  sqlc.arg(id), sqlc.arg(chain), sqlc.narg(workspace_id), sqlc.arg(occurred_at),
  sqlc.arg(actor_type), sqlc.narg(actor_id), sqlc.arg(action), sqlc.narg(target_type),
  sqlc.narg(target_id), sqlc.arg(outcome), sqlc.narg(request_id), sqlc.narg(source_ip),
  sqlc.arg(metadata), sqlc.narg(prev_hash), sqlc.arg(hash)
);

-- name: ChainEvents :many
SELECT id, chain, workspace_id, occurred_at, actor_type, actor_id, action,
       target_type, target_id, outcome, request_id, source_ip, metadata, prev_hash, hash
FROM qali.audit_events
WHERE chain = sqlc.arg(chain)
ORDER BY seq;
