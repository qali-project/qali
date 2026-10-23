# Security Architecture

Status: normative design and acceptance baseline  
Primary threat: compromise of the database, an ordinary user account, an
integration credential, or a publicly reachable HTTP handler must not become a
workspace-wide or host-wide compromise.

## 1. Security objectives

1. A database-only breach does not disclose usable passwords, sessions, tokens,
   OAuth credentials, integration secrets, signing keys, or file-encryption keys.
2. The default deployment exposes one TLS port and no database, metrics, debug,
   profiling, worker, object-storage, or administration port.
3. Ordinary testers cannot access administrative configuration or credentials.
4. Tenant and project authorization applies consistently to UI, API, workers,
   search, exports, dashboards, notifications, webhooks, and MCP.
5. External content and destinations cannot turn integrations into SSRF, stored
   XSS, credential exfiltration, or remote-code-execution paths.
6. Security-sensitive actions are attributable, detectable, revocable, and
   recoverable.

## 2. Trust boundaries

```text
Untrusted network
    |
    | TCP 443 only
    v
TLS reverse proxy
    |
    | private container network, HTTP or mTLS
    v
Qali process: web + REST + OAuth callbacks + MCP + health
    |                     |
    |                     +--> restricted outbound integration proxy/client
    |
    +--> PostgreSQL (private, no host port, TLS when remote)
    +--> local encrypted blobs or private S3-compatible endpoint
    +--> optional KMS/Vault (outbound/private only)
```

All public protocols share the same authenticated HTTPS origin and listener.
There is no separate MCP, admin, metrics, gRPC, or debug listener in the default
deployment. `/metrics`, diagnostics, and profiling are disabled publicly; an
operator may access protected diagnostics through the main listener or execute a
local CLI command inside the container.

## 3. Network exposure

- The production Compose file publishes only reverse-proxy `443/tcp`. Port 80 is
  not required; deployments may enable it solely for an HTTP-to-HTTPS redirect or
  ACME challenge when their certificate strategy needs it.
- Compose uses separate networks: an edge network for the reverse proxy, a
  non-published application network for proxy-to-Qali traffic, and an
  `internal: true` data network shared only by Qali and PostgreSQL. Qali may join a
  controlled egress network for configured providers; PostgreSQL never does.
  PostgreSQL has no `ports` mapping and accepts only the application identity.
- Health checks execute inside the network/container. Orchestrators use private
  probes; public health output is boolean and contains no dependency details.
- Admin UI routes share port 443, require admin permissions and recent MFA, and
  reveal no secrets. There is no network-accessible database/admin console.
- Outbound traffic is deny-by-default where the platform supports it. Operators
  allow DNS plus configured SMTP, OIDC/SAML metadata, KMS, storage, webhook, and
  integration destinations.
- Self-hosted integration destinations require an explicit host/CIDR allowlist.
  Redirects, DNS rebinding, private/link-local/metadata IPs, alternate numeric IP
  forms, and changed DNS answers are checked on every connection.

## 4. Password and credential protection

### 4.1 Passwords

- Password authentication is optional and may be disabled after SSO is verified.
- Store only Argon2id hashes with unique cryptographic salts and parameters in
  each record. Calibrate memory/time cost at installation and permit rehash on
  successful login.
- Mix a server-side password pepper into the KDF input. The pepper is supplied by
  a Docker/Kubernetes secret, KMS, or Vault and is never stored in PostgreSQL,
  images, repository files, logs, crash dumps, or environment diagnostics.
- Rate limit by account and network, use generic errors, progressive delay, and
  alerts without enabling attacker-driven permanent lockout.
- Recovery uses one-time, short-lived, hashed tokens; successful recovery revokes
  sessions and refresh grants. Recovery codes are hashed like passwords.

### 4.2 Token classes

- Generate at least 256 bits of randomness. Show bearer secrets exactly once.
- Store a non-secret lookup prefix plus an HMAC-SHA-256 verifier using a server
  pepper outside the database. A raw database dump cannot validate guesses or
  recreate a bearer token.
- Browser session, password reset, invitation, personal API, CI, SCIM, OAuth
  authorization code, access token, refresh token, webhook, and service-account
  credentials use distinct prefixes, tables, audiences, scopes, TTLs, and
  verification keys.
- Refresh tokens rotate; reuse revokes the token family. Session IDs rotate on
  login, privilege change, and step-up authentication.
- Signing keys live outside PostgreSQL. Publish only public verification keys.

### 4.3 Recoverable third-party secrets

Hashing cannot be used for secrets the application must later send to a provider.
Protect them with envelope encryption:

1. Generate a random data-encryption key (DEK) per workspace or installation.
2. Encrypt every secret with an approved AEAD and unique nonce; bind workspace,
   integration, secret type, and schema version as associated data.
3. Store ciphertext, nonce, algorithm/key version, and a KMS-wrapped DEK in the
   database.
4. Keep the key-encryption key (KEK) only in Docker/Kubernetes secrets, an OS
   credential store, Vault, or cloud KMS. Never store it in the database.
5. Decrypt only for the outbound operation, keep plaintext lifetime short, never
   return stored secret values to UI/API, and zero/replace buffers where practical.

The lightweight deployment accepts a mounted root-key file with restrictive
permissions. Environment variables are a compatibility fallback, not the
recommended production path, because they are easy to expose through process and
diagnostic tooling. KMS/Vault is the recommended high-security mode.

Key rotation rewraps DEKs without decrypting every secret. Compromise response
supports revoking provider credentials and migrating ciphertext to a new DEK.

## 5. File and attachment protection

- Local blobs are stored outside the web root under random object keys, encrypted
  with per-object DEKs wrapped by the workspace DEK. S3 deployments enable TLS,
  server-side encryption, private buckets, blocked public access, and short-lived
  signed operations or application-proxied downloads.
- Authorization is checked before upload initiation and again before download.
  Object names never grant access.
- Stream uploads with hard size limits, content sniffing, extension/MIME policy,
  checksum, quota, decompression-bomb limits, and optional malware quarantine.
- Serve active content as download or from an isolated origin; set safe content
  type, disposition, CSP, and `nosniff`. SVG/HTML are sanitized or forced to
  download.
- Orphan cleanup never deletes an object still referenced by another tenant.

## 6. Application security

- Secure, HTTP-only, SameSite cookies; strict origin checks and CSRF tokens on
  browser mutations. Never place bearer tokens in local storage.
- OIDC authorization code with PKCE plus strict state, nonce, issuer, audience,
  redirect URI, and algorithm validation. SAML uses signed assertions/responses,
  audience/destination validation, short validity, replay cache, and encrypted
  metadata secrets where applicable.
- Central input validation, parameterized SQL, output encoding, sanitized rich
  text, restrictive CSP, frame protections, HSTS, permissions policy, and no
  inline script exceptions in production.
- Request/body/upload limits, deadlines, cancellation, concurrency limits, and
  rate limits by IP, principal, credential, workspace, and expensive operation.
- Optimistic concurrency prevents silent overwrites. Idempotency protects retryable
  mutations, CI ingestion, callbacks, and webhook handling.
- Production builds disable debug endpoints, source maps containing source, stack
  traces in responses, and runtime profiling. Errors use stable public codes and
  internal correlation IDs.

## 7. Integration, webhook, and MCP security

- Only administrators install/configure integrations. Each installation declares
  provider scopes and explicit project/external-resource mappings.
- OAuth provider tokens are envelope-encrypted. Prefer short-lived tokens and app
  installations over broad personal tokens.
- Inbound callbacks verify signature, timestamp, nonce/delivery ID, issuer, state,
  and content type before decoding. Replay identifiers are retained through the
  provider retry window.
- Outbound webhooks use HMAC signatures over timestamp plus raw body, rotate
  secrets, include event IDs, and never place the secret itself in a header.
- Egress clients apply the SSRF controls in section 3, safe redirect policy,
  response size/time limits, TLS verification, and proxy policy.
- MCP is a resource server over the main HTTPS listener. Tokens are audience-
  bound, scoped, short-lived, and evaluated against current RBAC. Tool input and
  output are bounded; no generic REST or SQL escape hatch exists.
- External AI endpoints are untrusted egress destinations. Apply allowlists,
  field-level redaction, DLP hooks, size limits, explicit consent, provenance,
  and human confirmation for high-risk write actions.

## 8. Database and tenant isolation

- Every tenant-owned primary/foreign key relationship includes or validates
  `workspace_id`. Repository helpers require workspace scope by construction.
- Use PostgreSQL row-level security as defense in depth after the application
  query model is stable; the application sets a transaction-local workspace and
  actor context. The application remains responsible for authorization.
- Database roles are split for migration and runtime. Runtime cannot create
  extensions, roles, or schemas and does not own tables where avoidable.
- Remote database connections require TLS with certificate verification.
- Backups are encrypted with a backup key separate from database and application
  keys. Restore drills verify tenant boundaries and secret/key prerequisites.
- Logs and analytics never receive secret columns. Database error text is
  sanitized before returning to clients.

## 9. Audit and detection

- Append-only audit events record actor/principal type, workspace/project,
  action, target, timestamp, outcome, source IP/session/client, request ID, and
  safe before/after metadata. Secret values and sensitive content are redacted.
- High-risk events include authentication changes, failed step-up, role/access
  change, credential lifecycle, integration/AI enablement, exports, permanent
  deletion, key rotation, restore, and audit-policy change.
- Use hash chaining or signed export batches to make tampering evident. A database
  attacker may delete records, so high-security deployments stream audit events
  to an external append-only destination.
- Alerts have rate controls and never include reusable credentials or attachment
  contents.

## 10. Supply chain and runtime hardening

- Pinned dependencies and images, reproducible builds, lockfiles, automated
  update review, SBOM, provenance, vulnerability/license scans, and signed release
  artifacts.
- Minimal non-root image, read-only root filesystem, dropped Linux capabilities,
  `no-new-privileges`, seccomp/AppArmor defaults, bounded CPU/memory/PIDs, and a
  dedicated writable data/temp volume.
- No shell or package manager in the final image where operationally practical.
- Secrets enter as mounted files with least privilege. Example `.env` files
  contain placeholders only and are excluded from images and version control.
- Plugins do not execute arbitrary in-process code. Integration adapters are
  compiled, separately deployed, or run through a constrained protocol boundary.

## 11. Secure deployment profiles

### Compact profile

- Reverse proxy, Qali, and PostgreSQL.
- One public port: 443.
- Mounted application root-key file and local encrypted blob volume.
- PostgreSQL and Qali on a private internal network.

### Hardened profile

- External managed PostgreSQL with TLS and least-privilege identity.
- Private S3-compatible storage with encryption and retention policy.
- Vault/KMS for KEK, signing keys, and password/token peppers.
- External append-only audit sink, controlled egress proxy, SSO/MFA enforcement,
  and separate API/worker replicas.

Both profiles use the same application image and configuration schema.

## 12. Mandatory security gates

- Threat model and abuse cases for every new public endpoint or integration.
- Unit and integration tests for authentication, authorization, tenancy, secret
  handling, CSRF, SSRF, replay, rate limits, uploads, and redaction.
- Static analysis, dependency/container/IaC scanning, secret scanning, fuzzing of
  parsers and public protocols, and dynamic API security tests in CI.
- Independent penetration test before 1.0 and after material auth/tenant changes.
- Documented vulnerability disclosure, supported-version policy, patch SLA,
  incident response, key rotation, backup/restore, and security advisory process.
- Release is blocked by unresolved critical/high findings unless maintainers
  record scope, compensating controls, owner, and expiry for an exception.

