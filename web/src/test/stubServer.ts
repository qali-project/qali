import { createApiClient, type Session } from "../api/client";

export type StubHandler = (request: Request) => { status: number; body?: unknown };

/**
 * The network is the boundary: the generated client runs for real against a
 * stub transport keyed by "METHOD /path". Unknown routes answer 404.
 */
export function stubServer(handlers: Record<string, StubHandler>) {
  const requests: Request[] = [];
  const client = createApiClient({
    baseUrl: "http://qali.test",
    fetch: (request: Request) => {
      requests.push(request.clone());
      const key = `${request.method} ${new URL(request.url).pathname}`;
      const handler = handlers[key];
      const { status, body } = handler
        ? handler(request)
        : { status: 404, body: { code: "not_found" } };
      return Promise.resolve(
        new Response(body === undefined ? null : JSON.stringify(body), {
          status,
          headers: { "Content-Type": "application/json" },
        }),
      );
    },
  });
  return { client, requests };
}

export const stubSession = (
  state: Session["state"],
  csrfToken = "csrf-1",
  email = "owner@example.org",
): Session => ({
  state,
  csrfToken,
  expiresAt: "2026-10-22T12:00:00.000Z",
  user: {
    id: "0199f0c2-1111-7000-8000-000000000001",
    email,
    displayName: "Owner",
    mfaEnrolled: state !== "mfa_enrollment",
  },
});
