# Qali

Qali is an open-source, self-hosted test management platform for teams that
want to keep manual and automated testing in one place without depending on a
proprietary cloud service.

> [!IMPORTANT]
> Qali is under active development and does not have a stable release yet. It
> is not ready for production use. Installation packages and supported upgrade
> instructions will be published with the first release.

## What Qali is for

Qali is designed to help a team:

- organize projects, test suites, and versioned test cases;
- plan and perform manual test runs;
- collect automated test results from CI pipelines;
- attach evidence and connect failed results to defects;
- understand test progress and release readiness;
- control access with workspace and project roles;
- keep its testing data on infrastructure it operates.

## Deployment model

Qali is built for straightforward self-hosting. The default deployment uses
Docker Compose and consists of:

- Qali, serving the web interface and API;
- PostgreSQL;
- a reverse proxy providing HTTPS.

Only the HTTPS endpoint is exposed by default. The application and database
remain on private container networks.

### Optional OpenID Connect sign-in

Qali supports one discovery-based OpenID Connect provider per installation.
Owners configure it under **Security** in the primary workspace, copy the
displayed redirect URI to the provider, and complete **Verify provider**.
Accounts can link a provider from **Account**, or use a verified email matching
an existing account. New accounts require an invitation.

Outbound provider access is opt-in. Add the override to every Compose command:

```sh
docker compose -f deploy/compose/compose.yaml -f deploy/compose/compose.oidc.yaml up -d
```

The override gives outbound access only to Qali. PostgreSQL stays isolated;
only HTTPS port 443 is published. Issuer and provider endpoints require HTTPS
and public addresses by default. For a private, self-hosted issuer, explicitly
set `QALI_OIDC_ALLOW_PRIVATE_ISSUER=true` before starting Compose. This permits
private addresses only for the configured issuer hostname. The container must
trust the issuer's TLS certificate.

After verification, an Owner or Workspace Administrator can disable ordinary
password sign-in. Owners retain emergency password **and Qali TOTP** access;
keep an Owner password and authenticator available during provider outages.
Provider sign-in also preserves Qali's MFA requirements. Changing provider
credentials resets verification and re-enables password sign-in. Removing or
changing the issuer is refused while active linked accounts have no password.

## Security

Qali is designed around workspace isolation, least-privilege access, protected
credentials, auditable administrative actions, and encrypted sensitive data.

Please report suspected vulnerabilities privately through GitHub's private
vulnerability reporting feature. Do not open a public issue or pull request for
a suspected security problem. See the [security policy](SECURITY.md) for
details.

## Releases

There are no supported Qali releases yet. When the first release is available,
this repository will provide versioned container images, installation
instructions, checksums, and upgrade guidance.

Watch the repository or follow its
[Releases](https://github.com/qali-project/qali/releases) page to receive release
updates.

## License

Qali is licensed under the [Apache License 2.0](LICENSE).

