import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { createApiClient, type Session } from "./api/client";
import { App } from "./App";
import { PRODUCT_NAME } from "./app/product";

type Handler = (request: Request) => { status: number; body?: unknown };

// The network is the boundary: the generated client runs for real against a
// stub transport keyed by "METHOD /path".
function server(handlers: Record<string, Handler>) {
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

const session = (state: Session["state"], csrfToken = "csrf-1"): Session => ({
  state,
  csrfToken,
  expiresAt: "2026-10-22T12:00:00.000Z",
  user: {
    id: "0199f0c2-1111-7000-8000-000000000001",
    email: "owner@example.org",
    displayName: "Owner",
    mfaEnrolled: state !== "mfa_enrollment",
  },
});

const ready = {
  "GET /api/v1/setup": () => ({ status: 200, body: { bootstrapRequired: false } }),
  // Home opens a workspace (REVIEW-006); these tests need none.
  "GET /api/v1/workspaces": () => ({ status: 200, body: { items: [], nextCursor: null } }),
};
const signedOut = {
  ...ready,
  "GET /api/v1/auth/session": () => ({ status: 401, body: { code: "unauthenticated" } }),
};

describe("App", () => {
  it("sends a fresh installation to owner setup", async () => {
    const { client } = server({
      "GET /api/v1/setup": () => ({ status: 200, body: { bootstrapRequired: true } }),
    });
    render(<App client={client} initialPath="/" />);
    expect(screen.getByRole("heading", { level: 1, name: PRODUCT_NAME })).toBeInTheDocument();
    expect(
      await screen.findByRole("heading", { name: "Create the owner account" }),
    ).toBeInTheDocument();
  });

  it("asks anonymous visitors to sign in and explains failures", async () => {
    const { client } = server({
      ...signedOut,
      "POST /api/v1/auth/login": () => ({ status: 401, body: { code: "invalid_credentials" } }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/" />);
    await screen.findByRole("heading", { name: "Sign in" });

    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(screen.getByLabelText("Email")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByText("Enter your email.")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Email"), "owner@example.org");
    await user.type(screen.getByLabelText("Password"), "wrong password");
    await user.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The email or password is incorrect.",
    );
  });

  it("lets visitors reach recovery without a session", async () => {
    const { client } = server(signedOut);
    render(<App client={client} initialPath="/recover" />);
    expect(
      await screen.findByRole("heading", { name: "Recover your account" }),
    ).toBeInTheDocument();
  });

  it("shows the signed-in home and signs out with the CSRF token", async () => {
    const { client, requests } = server({
      ...ready,
      "GET /api/v1/auth/session": () => ({ status: 200, body: session("active", "csrf-home") }),
      "GET /health/live": () => ({ status: 200, body: { status: "ok" } }),
      "POST /api/v1/auth/logout": () => ({ status: 204 }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/" />);
    expect(await screen.findByText(/Signed in as/)).toHaveTextContent(
      "Signed in as Owner (owner@example.org)",
    );
    expect(await screen.findByText("Service status: ok")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Sign out" }));
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    const logout = requests.find(
      (r) => r.method === "POST" && r.url.endsWith("/api/v1/auth/logout"),
    );
    expect(logout?.headers.get("X-CSRF-Token")).toBe("csrf-home");
  });

  it("guides an owner through TOTP enrollment and shows recovery codes once", async () => {
    const codes = Array.from(
      { length: 10 },
      (_, i) => `AAAA-BBBB-CCCC-DD${String(i).padStart(2, "A")}`,
    );
    const { client } = server({
      ...ready,
      "GET /api/v1/auth/session": () => ({ status: 200, body: session("mfa_enrollment") }),
      "POST /api/v1/auth/mfa/totp/enrollment": () => ({
        status: 200,
        body: {
          secret: "JBSWY3DPEHPK3PXP",
          otpauthUri: "otpauth://totp/Qali:owner@example.org?secret=JBSWY3DPEHPK3PXP",
        },
      }),
      "POST /api/v1/auth/mfa/totp/enrollment/confirm": () => ({
        status: 200,
        body: { session: session("active", "csrf-2"), recoveryCodes: codes },
      }),
      "GET /health/live": () => ({ status: 200, body: { status: "ok" } }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/" />);
    await user.click(await screen.findByRole("button", { name: "Set up authenticator app" }));
    expect(await screen.findByTestId("totp-secret")).toHaveTextContent("JBSWY3DPEHPK3PXP");

    await user.type(screen.getByLabelText("Authentication code"), "12345");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(screen.getByText("Enter the 6-digit code.")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Authentication code"));
    await user.type(screen.getByLabelText("Authentication code"), "123456");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    const list = await screen.findByRole("list", { name: "Recovery codes" });
    expect(list.querySelectorAll("li")).toHaveLength(10);

    await user.click(screen.getByRole("button", { name: "I saved my recovery codes" }));
    expect(await screen.findByText(/Signed in as/)).toBeInTheDocument();
  });

  it("announces when the service cannot be reached", async () => {
    const { client } = server({
      "GET /api/v1/setup": () => ({ status: 503, body: { code: "unavailable" } }),
    });
    render(<App client={client} initialPath="/" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("The service is unavailable");
  });
});
