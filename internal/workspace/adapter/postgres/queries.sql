-- Workspace queries (ADR-0013). Every statement runs in a scoped
-- transaction; row-level security limits tenant tables to the scope's
-- workspace, so no query trusts a client-supplied workspace ID alone.
--
-- workspace_members also has a member_self policy (a user sees their own
-- memberships in every workspace), and permissive policies are OR'ed.
-- Membership queries therefore filter on qali.current_workspace()
-- explicitly; RLS alone would return the caller's rows from other
-- workspaces.

-- name: UserWorkspaces :many
-- System scope with the user set: the member_self policies expose the
-- user's own memberships and workspaces only.
SELECT w.id, w.name, m.role
FROM qali.workspace_members m
JOIN qali.workspaces w ON w.id = m.workspace_id
WHERE m.user_id = sqlc.arg(user_id) AND m.status = 'active' AND w.id > sqlc.arg(after)
ORDER BY w.id
LIMIT sqlc.arg(row_limit);

-- name: Workspace :one
SELECT id, name FROM qali.workspaces WHERE id = qali.current_workspace();

-- name: Membership :one
SELECT user_id, role, status, version, created_at
FROM qali.workspace_members
WHERE workspace_id = qali.current_workspace() AND user_id = sqlc.arg(user_id);

-- name: MembershipForUpdate :one
SELECT user_id, role, status, version, created_at
FROM qali.workspace_members
WHERE workspace_id = qali.current_workspace() AND user_id = sqlc.arg(user_id)
FOR UPDATE;

-- name: Members :many
SELECT user_id, role, status, version, created_at
FROM qali.workspace_members
WHERE workspace_id = qali.current_workspace() AND user_id > sqlc.arg(after)
ORDER BY user_id
LIMIT sqlc.arg(row_limit);

-- name: LockActiveOwners :many
SELECT user_id FROM qali.workspace_members
WHERE workspace_id = qali.current_workspace() AND role = 'owner' AND status = 'active'
ORDER BY user_id
FOR UPDATE;

-- name: UpdateMembership :one
UPDATE qali.workspace_members
SET role = sqlc.arg(role), status = sqlc.arg(status), updated_at = sqlc.arg(at), version = version + 1
WHERE workspace_id = qali.current_workspace() AND user_id = sqlc.arg(user_id) AND version = sqlc.arg(version)
RETURNING user_id, role, status, version, created_at;

-- name: InsertMembership :exec
INSERT INTO qali.workspace_members (workspace_id, user_id, role, status, created_at, updated_at)
VALUES (qali.current_workspace(), sqlc.arg(user_id), sqlc.arg(role), 'active', sqlc.arg(at), sqlc.arg(at));

-- name: InvitationWorkspace :one
SELECT workspace_id FROM qali.invitation_lookups WHERE lookup_id = sqlc.arg(lookup_id);

-- name: InsertInvitationLookup :exec
INSERT INTO qali.invitation_lookups (lookup_id, workspace_id)
VALUES (sqlc.arg(lookup_id), qali.current_workspace());

-- name: InsertInvitation :exec
INSERT INTO qali.invitations (id, workspace_id, email, role, lookup_id, verifier, key_version, invited_by, created_at, expires_at)
VALUES (sqlc.arg(id), qali.current_workspace(), sqlc.arg(email), sqlc.arg(role), sqlc.arg(lookup_id), sqlc.arg(verifier),
        sqlc.arg(key_version), sqlc.arg(invited_by), sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: RevokePendingInvitations :exec
UPDATE qali.invitations SET revoked_at = sqlc.arg(at)
WHERE email = sqlc.arg(email) AND accepted_at IS NULL AND revoked_at IS NULL;

-- name: PendingInvitations :many
SELECT id, email, role, lookup_id, verifier, key_version, invited_by, created_at, expires_at, accepted_at, revoked_at
FROM qali.invitations
WHERE accepted_at IS NULL AND revoked_at IS NULL AND expires_at > sqlc.arg(now) AND id > sqlc.arg(after)
ORDER BY id
LIMIT sqlc.arg(row_limit);

-- name: RevokeInvitation :execrows
UPDATE qali.invitations SET revoked_at = sqlc.arg(at)
WHERE id = sqlc.arg(id) AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > sqlc.arg(at);

-- name: InvitationByLookup :one
SELECT id, email, role, lookup_id, verifier, key_version, invited_by, created_at, expires_at, accepted_at, revoked_at
FROM qali.invitations WHERE lookup_id = sqlc.arg(lookup_id)
FOR UPDATE;

-- name: PeekInvitation :one
SELECT id, email, role, lookup_id, verifier, key_version, invited_by, created_at, expires_at, accepted_at, revoked_at
FROM qali.invitations WHERE lookup_id = sqlc.arg(lookup_id);

-- name: AcceptInvitation :execrows
UPDATE qali.invitations SET accepted_at = sqlc.arg(at), accepted_by = sqlc.arg(user_id)
WHERE id = sqlc.arg(id) AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > sqlc.arg(at);

-- name: InsertProject :exec
INSERT INTO qali.projects (id, workspace_id, code, name, visibility, created_by, created_at, updated_at)
VALUES (sqlc.arg(id), qali.current_workspace(), sqlc.arg(code), sqlc.arg(name), sqlc.arg(visibility),
        sqlc.arg(created_by), sqlc.arg(at), sqlc.arg(at));

-- name: Project :one
SELECT p.id, p.code, p.name, p.visibility, p.created_by, p.created_at, p.version,
       COALESCE(pm.level, '')::text AS level
FROM qali.projects p
LEFT JOIN qali.project_members pm ON pm.project_id = p.id AND pm.user_id = sqlc.arg(user_id)
WHERE p.id = sqlc.arg(id);

-- name: VisibleProjects :many
SELECT p.id, p.code, p.name, p.visibility, p.created_by, p.created_at, p.version,
       COALESCE(pm.level, '')::text AS level
FROM qali.projects p
LEFT JOIN qali.project_members pm ON pm.project_id = p.id AND pm.user_id = sqlc.arg(user_id)
WHERE p.id > sqlc.arg(after)
  AND (sqlc.arg(see_all)::boolean OR p.visibility = 'public' OR pm.user_id IS NOT NULL)
ORDER BY p.id
LIMIT sqlc.arg(row_limit);

-- name: ProjectMembers :many
SELECT user_id, level, version FROM qali.project_members
WHERE project_id = sqlc.arg(project_id) AND user_id > sqlc.arg(after)
ORDER BY user_id
LIMIT sqlc.arg(row_limit);

-- name: ProjectMemberForUpdate :one
SELECT user_id, level, version FROM qali.project_members
WHERE project_id = sqlc.arg(project_id) AND user_id = sqlc.arg(user_id)
FOR UPDATE;

-- name: InsertProjectMember :exec
INSERT INTO qali.project_members (workspace_id, project_id, user_id, level, created_at, updated_at)
VALUES (qali.current_workspace(), sqlc.arg(project_id), sqlc.arg(user_id), sqlc.arg(level), sqlc.arg(at), sqlc.arg(at));

-- name: UpdateProjectMember :one
UPDATE qali.project_members
SET level = sqlc.arg(level), updated_at = sqlc.arg(at), version = version + 1
WHERE project_id = sqlc.arg(project_id) AND user_id = sqlc.arg(user_id) AND version = sqlc.arg(version)
RETURNING user_id, level, version;

-- name: DeleteProjectMember :execrows
DELETE FROM qali.project_members
WHERE project_id = sqlc.arg(project_id) AND user_id = sqlc.arg(user_id) AND version = sqlc.arg(version);
