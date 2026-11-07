-- name: InstallationExists :one
SELECT EXISTS (SELECT 1 FROM qali.installation);

-- name: InsertInstallation :exec
INSERT INTO qali.installation (owner_user_id, primary_workspace_id, bootstrapped_at)
VALUES (sqlc.arg(owner_user_id), sqlc.arg(primary_workspace_id), sqlc.arg(at));

-- name: InsertUser :exec
INSERT INTO qali.users (id, email, display_name, password_hash, password_changed_at, status, created_at, updated_at)
VALUES (sqlc.arg(id), sqlc.arg(email), sqlc.arg(display_name), sqlc.arg(password_hash), sqlc.arg(at), 'active', sqlc.arg(at), sqlc.arg(at));

-- name: UserByEmail :one
SELECT id, email, display_name, password_hash, status, totp_algorithm, totp_dek_id, totp_nonce, totp_ciphertext,
       totp_confirmed_at, totp_last_step
FROM qali.users WHERE email = sqlc.arg(email);

-- name: UserByID :one
SELECT id, email, display_name, password_hash, status, totp_algorithm, totp_dek_id, totp_nonce, totp_ciphertext,
       totp_confirmed_at, totp_last_step
FROM qali.users WHERE id = sqlc.arg(id);

-- name: UsersByIDs :many
SELECT id, email, display_name FROM qali.users WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: SetPassword :exec
UPDATE qali.users
SET password_hash = sqlc.arg(password_hash), password_changed_at = sqlc.arg(at), updated_at = sqlc.arg(at), version = version + 1
WHERE id = sqlc.arg(id);

-- name: SetTOTPSecret :exec
UPDATE qali.users
SET totp_algorithm = sqlc.arg(algorithm), totp_dek_id = sqlc.arg(dek_id), totp_nonce = sqlc.arg(nonce),
    totp_ciphertext = sqlc.arg(ciphertext), totp_confirmed_at = NULL, totp_last_step = NULL,
    updated_at = sqlc.arg(at), version = version + 1
WHERE id = sqlc.arg(id) AND totp_confirmed_at IS NULL;

-- name: ConfirmTOTP :execrows
UPDATE qali.users
SET totp_confirmed_at = sqlc.arg(at), totp_last_step = sqlc.arg(step), updated_at = sqlc.arg(at), version = version + 1
WHERE id = sqlc.arg(id) AND totp_ciphertext IS NOT NULL AND totp_confirmed_at IS NULL;

-- name: AdvanceTOTPStep :execrows
-- Fails (0 rows) when a concurrent request already used this or a later step.
UPDATE qali.users SET totp_last_step = sqlc.arg(step)
WHERE id = sqlc.arg(id) AND (totp_last_step IS NULL OR totp_last_step < sqlc.arg(step));

-- name: InsertWorkspace :exec
INSERT INTO qali.workspaces (id, name, created_at, updated_at) VALUES (sqlc.arg(id), sqlc.arg(name), sqlc.arg(at), sqlc.arg(at));

-- name: InsertMember :exec
INSERT INTO qali.workspace_members (workspace_id, user_id, role, status, created_at, updated_at)
VALUES (sqlc.arg(workspace_id), sqlc.arg(user_id), sqlc.arg(role), 'active', sqlc.arg(at), sqlc.arg(at));

-- name: ActiveRoles :many
-- Row-level security limits this to the current user's own memberships.
SELECT role FROM qali.workspace_members WHERE user_id = sqlc.arg(user_id) AND status = 'active';

-- name: InsertSession :exec
INSERT INTO qali.sessions (id, user_id, lookup_id, verifier, key_version, csrf_verifier, state, auth_method,
  created_at, last_seen_at, idle_expires_at, expires_at, mfa_verified_at, source_ip)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(lookup_id), sqlc.arg(verifier), sqlc.arg(key_version),
  sqlc.arg(csrf_verifier), sqlc.arg(state), sqlc.arg(auth_method), sqlc.arg(created_at), sqlc.arg(created_at),
  sqlc.arg(idle_expires_at), sqlc.arg(expires_at), sqlc.narg(mfa_verified_at), sqlc.narg(source_ip));

-- name: SessionByLookup :one
SELECT id, user_id, lookup_id, verifier, key_version, csrf_verifier, state, auth_method, created_at, last_seen_at,
       idle_expires_at, expires_at, mfa_verified_at, revoked_at, revoke_reason
FROM qali.sessions WHERE lookup_id = sqlc.arg(lookup_id);

-- name: TouchSession :exec
UPDATE qali.sessions SET last_seen_at = sqlc.arg(last_seen_at), idle_expires_at = sqlc.arg(idle_expires_at)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RevokeSession :exec
UPDATE qali.sessions SET revoked_at = sqlc.arg(at), revoke_reason = sqlc.arg(reason)
WHERE id = sqlc.arg(id) AND revoked_at IS NULL;

-- name: RevokeUserSessions :execrows
UPDATE qali.sessions SET revoked_at = sqlc.arg(at), revoke_reason = sqlc.arg(reason)
WHERE user_id = sqlc.arg(user_id) AND revoked_at IS NULL;

-- name: SupersedeRecoveryCodes :exec
UPDATE qali.recovery_codes SET superseded_at = sqlc.arg(at)
WHERE user_id = sqlc.arg(user_id) AND used_at IS NULL AND superseded_at IS NULL;

-- name: InsertRecoveryCode :exec
INSERT INTO qali.recovery_codes (id, user_id, lookup, code_hash, created_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(lookup), sqlc.arg(code_hash), sqlc.arg(at));

-- name: LiveRecoveryCode :one
SELECT id, code_hash FROM qali.recovery_codes
WHERE user_id = sqlc.arg(user_id) AND lookup = sqlc.arg(lookup) AND used_at IS NULL AND superseded_at IS NULL;

-- name: UseRecoveryCode :execrows
UPDATE qali.recovery_codes SET used_at = sqlc.arg(at)
WHERE id = sqlc.arg(id) AND used_at IS NULL AND superseded_at IS NULL;

-- name: InsertPasswordReset :exec
INSERT INTO qali.password_resets (id, user_id, lookup_id, verifier, key_version, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(user_id), sqlc.arg(lookup_id), sqlc.arg(verifier), sqlc.arg(key_version),
  sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: PasswordResetByLookup :one
SELECT id, user_id, verifier, key_version, expires_at, used_at FROM qali.password_resets WHERE lookup_id = sqlc.arg(lookup_id);

-- name: UsePasswordReset :execrows
UPDATE qali.password_resets SET used_at = sqlc.arg(at) WHERE id = sqlc.arg(id) AND used_at IS NULL;

-- name: InsertSetupToken :exec
INSERT INTO qali.setup_tokens (id, lookup_id, verifier, key_version, issued_by, created_at, expires_at)
VALUES (sqlc.arg(id), sqlc.arg(lookup_id), sqlc.arg(verifier), sqlc.arg(key_version), sqlc.arg(issued_by),
  sqlc.arg(created_at), sqlc.arg(expires_at));

-- name: SetupTokenByLookup :one
SELECT id, verifier, key_version, expires_at, used_at FROM qali.setup_tokens WHERE lookup_id = sqlc.arg(lookup_id);

-- name: UseSetupToken :execrows
UPDATE qali.setup_tokens SET used_at = sqlc.arg(at)
WHERE id = sqlc.arg(id) AND used_at IS NULL AND expires_at > sqlc.arg(at);

-- name: ThrottleState :one
SELECT failures, next_allowed_at FROM qali.login_throttle WHERE key = sqlc.arg(key);

-- name: EnsureThrottle :exec
INSERT INTO qali.login_throttle (key, kind, failures, next_allowed_at, updated_at)
VALUES (sqlc.arg(key), sqlc.arg(kind), 0, sqlc.arg(at), sqlc.arg(at))
ON CONFLICT (key) DO NOTHING;

-- name: LockThrottle :one
SELECT failures, next_allowed_at FROM qali.login_throttle WHERE key = sqlc.arg(key) FOR UPDATE;

-- name: SaveThrottle :exec
UPDATE qali.login_throttle
SET failures = sqlc.arg(failures), next_allowed_at = sqlc.arg(next_allowed_at), updated_at = sqlc.arg(at)
WHERE key = sqlc.arg(key);

-- name: DEKByScope :one
SELECT id, kek_version, nonce, ciphertext FROM qali.encryption_keys WHERE scope = sqlc.arg(scope);

-- name: InsertDEK :exec
INSERT INTO qali.encryption_keys (id, scope, kek_version, nonce, ciphertext, created_at)
VALUES (sqlc.arg(id), sqlc.arg(scope), sqlc.arg(kek_version), sqlc.arg(nonce), sqlc.arg(ciphertext), sqlc.arg(at))
ON CONFLICT (scope) DO NOTHING;
-- name: LoginPolicy :one
SELECT primary_workspace_id, local_login_enabled, login_policy_version FROM qali.installation;

-- name: LockLoginPolicy :one
SELECT primary_workspace_id, local_login_enabled, login_policy_version FROM qali.installation FOR UPDATE;

-- name: SaveLoginPolicy :exec
UPDATE qali.installation SET local_login_enabled = $1, login_policy_version = login_policy_version + 1;

-- name: OIDCProvider :one
SELECT * FROM qali.oidc_provider;

-- name: SaveOIDCProvider :exec
INSERT INTO qali.oidc_provider (id, issuer, client_id, label, secret_dek_id, secret_nonce, secret_ciphertext,
 status, verified_at, verified_by, created_at, updated_at, version)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
ON CONFLICT (singleton) DO UPDATE SET
 id=EXCLUDED.id, issuer=EXCLUDED.issuer, client_id=EXCLUDED.client_id, label=EXCLUDED.label,
 secret_dek_id=EXCLUDED.secret_dek_id, secret_nonce=EXCLUDED.secret_nonce, secret_ciphertext=EXCLUDED.secret_ciphertext,
 status=EXCLUDED.status, verified_at=EXCLUDED.verified_at, verified_by=EXCLUDED.verified_by,
 updated_at=EXCLUDED.updated_at, version=EXCLUDED.version;

-- name: RemoveOIDCProvider :exec
DELETE FROM qali.oidc_provider;

-- name: InsertOIDCFlow :exec
INSERT INTO qali.oidc_flows (id,lookup_id,state_verifier,nonce_verifier,binding_verifier,key_version,
 provider_id,purpose,user_id,sealed_dek_id,sealed_nonce,sealed_payload,created_at,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14);

-- name: ConsumeOIDCFlow :one
UPDATE qali.oidc_flows SET consumed_at = sqlc.arg(at)
WHERE lookup_id = sqlc.arg(lookup_id) AND state_verifier = sqlc.arg(state_verifier)
 AND binding_verifier = sqlc.arg(binding_verifier) AND consumed_at IS NULL AND expires_at > sqlc.arg(at)
RETURNING *;

-- name: OIDCIdentity :one
SELECT * FROM qali.user_identities WHERE issuer=$1 AND subject=$2;

-- name: OwnOIDCIdentity :one
SELECT * FROM qali.user_identities WHERE user_id=$1 AND issuer=$2;

-- name: InsertOIDCIdentity :exec
INSERT INTO qali.user_identities (id,user_id,issuer,subject,link_method,linked_at,last_login_at)
VALUES ($1,$2,$3,$4,$5,$6,$7);

-- name: TouchOIDCIdentity :exec
UPDATE qali.user_identities SET last_login_at=$2 WHERE id=$1;

-- name: RemoveOIDCIdentity :exec
DELETE FROM qali.user_identities WHERE user_id=$1;

-- name: RemoveAllOIDCIdentities :exec
DELETE FROM qali.user_identities;

-- name: CleanupOIDCFlows :execrows
DELETE FROM qali.oidc_flows WHERE expires_at <= $1;

-- name: HasPasswordlessOIDCUsers :one
SELECT EXISTS (SELECT 1 FROM qali.users u JOIN qali.user_identities i ON i.user_id=u.id
 WHERE u.status='active' AND u.password_hash IS NULL);
