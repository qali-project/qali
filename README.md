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

