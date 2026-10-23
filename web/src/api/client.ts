import createClient, { type ClientOptions } from "openapi-fetch";

import type { components, paths } from "../generated/api";

export type Session = components["schemas"]["Session"];
export type Problem = components["schemas"]["Problem"];

export type ApiClient = ReturnType<typeof createClient<paths>> & {
  /** Remember the session's CSRF token for unsafe requests (ADR-0012). */
  setCsrfToken(token: string | undefined): void;
};

const unsafe = new Set(["POST", "PUT", "PATCH", "DELETE"]);

// The only way the frontend talks to the backend: a client typed from
// api/openapi.yaml. Regenerate types with `make generate`.
export function createApiClient(options: ClientOptions = {}): ApiClient {
  const client = createClient<paths>({ baseUrl: "", credentials: "same-origin", ...options });
  let csrfToken: string | undefined;
  client.use({
    onRequest({ request }) {
      if (csrfToken && unsafe.has(request.method)) {
        request.headers.set("X-CSRF-Token", csrfToken);
      }
      return request;
    },
  });
  return Object.assign(client, {
    setCsrfToken(token: string | undefined) {
      csrfToken = token;
    },
  });
}

/** Returns the stable problem code of an error response, if any. */
export function problemCode(error: unknown): string | undefined {
  if (error && typeof error === "object" && "code" in error && typeof error.code === "string") {
    return error.code;
  }
  return undefined;
}
