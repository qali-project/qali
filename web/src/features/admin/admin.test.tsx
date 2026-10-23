import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { App } from "../../App";
import { stubServer, stubSession, type StubHandler } from "../../test/stubServer";

const WS = "0199f0c2-2222-7000-8000-000000000001";
const TESTER = "0199f0c2-1111-7000-8000-000000000002";
const PROJECT = "0199f0c2-3333-7000-8000-000000000001";
const base = `/api/v1/workspaces/${WS}`;

const ownerPermissions = [
  "workspace.read",
  "members.read",
  "members.invite",
  "members.update_role",
  "members.deactivate",
  "projects.create",
];

function workspace(role: string, permissions: string[]) {
  return { id: WS, name: "Acme QA", role, permissions };
}

function signedIn(role: string, permissions: string[]): Record<string, StubHandler> {
  return {
    "GET /api/v1/setup": () => ({ status: 200, body: { bootstrapRequired: false } }),
    "GET /api/v1/auth/session": () => ({ status: 200, body: stubSession("active") }),
    "GET /api/v1/workspaces": () => ({
      status: 200,
      body: { items: [workspace(role, permissions)], nextCursor: null },
    }),
  };
}

const testerMember = {
  userId: TESTER,
  email: "tester@example.org",
  displayName: "Tess Tester",
  role: "tester",
  status: "active",
  version: 1,
  createdAt: "2026-10-22T12:00:00Z",
};

const members = () => ({ status: 200, body: { items: [testerMember], nextCursor: null } });
const noInvitations = () => ({ status: 200, body: { items: [], nextCursor: null } });

describe("administration visibility (MVP-05.AC-10)", () => {
  it("hides administration from testers and refuses direct navigation", async () => {
    const { client, requests } = stubServer(signedIn("tester", ["workspace.read"]));
    render(<App client={client} initialPath="/admin/members" />);
    expect(
      await screen.findByRole("heading", { name: "You do not have access to this page" }),
    ).toBeInTheDocument();
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Projects" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Members" })).not.toBeInTheDocument();
    expect(requests.some((r) => r.url.includes("/members"))).toBe(false);
  });

  it("hides project access management without projects.manage_access", async () => {
    const { client } = stubServer({
      ...signedIn("tester", ["workspace.read"]),
      [`GET ${base}/projects/${PROJECT}`]: () => ({
        status: 200,
        body: {
          id: PROJECT,
          code: "WEB",
          name: "Web",
          visibility: "public",
          version: 1,
          createdAt: "2026-10-22T12:00:00Z",
          permissions: ["projects.read", "repository.read"],
        },
      }),
      [`GET ${base}/projects`]: () => ({
        status: 200,
        body: {
          items: [
            {
              id: PROJECT,
              code: "WEB",
              name: "Web",
              visibility: "public",
              version: 1,
              createdAt: "2026-10-22T12:00:00Z",
              permissions: ["projects.read"],
            },
          ],
          nextCursor: null,
        },
      }),
    });
    const { unmount } = render(<App client={client} initialPath="/projects" />);
    expect(await screen.findByText("WEB")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: /Manage access/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Create a project" })).not.toBeInTheDocument();
    unmount();

    render(<App client={client} initialPath={`/w/${WS}/projects/${PROJECT}/access`} />);
    expect(
      await screen.findByRole("heading", { name: "You do not have access to this page" }),
    ).toBeInTheDocument();
  });

  it("shows administration to owners", async () => {
    const { client } = stubServer({
      ...signedIn("owner", ownerPermissions),
      [`GET ${base}/members`]: members,
      [`GET ${base}/invitations`]: noInvitations,
    });
    render(<App client={client} initialPath="/admin/members" />);
    expect(await screen.findByRole("heading", { name: "Members" })).toBeInTheDocument();
    expect(await screen.findByRole("rowheader", { name: "Tess Tester" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Members" })).toBeInTheDocument();
    expect(screen.getByText("No pending invitations.")).toBeInTheDocument();
  });
});

describe("member administration", () => {
  it("changes a role with If-Match and steps up when recent MFA is required", async () => {
    let patches = 0;
    const { client, requests } = stubServer({
      ...signedIn("owner", ownerPermissions),
      [`GET ${base}/members`]: members,
      [`GET ${base}/invitations`]: noInvitations,
      [`PATCH ${base}/members/${TESTER}`]: () => {
        patches++;
        return patches === 1
          ? { status: 403, body: { code: "recent_mfa_required" } }
          : { status: 200, body: { ...testerMember, role: "qa_lead", version: 2 } };
      },
      "POST /api/v1/auth/mfa/step-up": () => ({
        status: 200,
        body: stubSession("active", "csrf-rotated"),
      }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/admin/members" />);
    await user.selectOptions(await screen.findByLabelText("Role for Tess Tester"), "qa_lead");

    expect(await screen.findByRole("heading", { name: "Confirm it is you" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    expect(screen.getByText("Enter the 6-digit code.")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Authenticator code"), "123456");
    await user.click(screen.getByRole("button", { name: "Confirm" }));
    await screen.findByRole("rowheader", { name: "Tess Tester" });
    expect(screen.queryByRole("heading", { name: "Confirm it is you" })).not.toBeInTheDocument();

    const sent = requests.filter((r) => r.method === "PATCH");
    expect(sent).toHaveLength(2);
    expect(sent[0]!.headers.get("If-Match")).toBe('"1"');
    expect(await sent[0]!.json()).toEqual({ role: "qa_lead" });
    // The retried request uses the rotated session's CSRF token.
    expect(sent[1]!.headers.get("X-CSRF-Token")).toBe("csrf-rotated");
  });

  it("explains the last-owner rule", async () => {
    const { client } = stubServer({
      ...signedIn("owner", ownerPermissions),
      [`GET ${base}/members`]: members,
      [`GET ${base}/invitations`]: noInvitations,
      [`PATCH ${base}/members/${TESTER}`]: () => ({ status: 409, body: { code: "last_owner" } }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/admin/members" />);
    await user.click(await screen.findByRole("button", { name: "Deactivate Tess Tester" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "The workspace needs at least one active owner.",
    );
  });

  it("shows a new invitation link once, with the token in the fragment", async () => {
    const { client, requests } = stubServer({
      ...signedIn("owner", ownerPermissions),
      [`GET ${base}/members`]: members,
      [`GET ${base}/invitations`]: noInvitations,
      [`POST ${base}/invitations`]: () => ({
        status: 201,
        body: {
          token: "qali_inv_secret",
          invitation: {
            id: "0199f0c2-4444-7000-8000-000000000001",
            email: "new@example.org",
            role: "viewer",
            invitedBy: "0199f0c2-1111-7000-8000-000000000001",
            createdAt: "2026-10-22T12:00:00Z",
            expiresAt: "2026-10-29T12:00:00Z",
          },
        },
      }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/admin/members" />);
    await user.click(await screen.findByRole("button", { name: "Create invitation" }));
    expect(screen.getByText("Enter a valid email address.")).toBeInTheDocument();
    await user.type(screen.getByLabelText("Email"), "new@example.org");
    await user.selectOptions(screen.getByLabelText("Role"), "viewer");
    await user.click(screen.getByRole("button", { name: "Create invitation" }));
    const link = await screen.findByLabelText("Invitation link");
    expect(link).toHaveValue(`${window.location.origin}/invite#qali_inv_secret`);
    const post = requests.find((r) => r.method === "POST" && r.url.endsWith("/invitations"));
    expect(await post!.json()).toEqual({ email: "new@example.org", role: "viewer" });
    expect(
      within(screen.getByLabelText("Role")).queryByRole("option", { name: "Owner" }),
    ).not.toBeInTheDocument();
  });
});

describe("invitation acceptance", () => {
  const signedOut: Record<string, StubHandler> = {
    "GET /api/v1/setup": () => ({ status: 200, body: { bootstrapRequired: false } }),
    "GET /api/v1/auth/session": () => ({ status: 401, body: { code: "unauthenticated" } }),
  };
  const preview = () => ({
    status: 200,
    body: {
      workspaceName: "Acme QA",
      email: "new@example.org",
      role: "tester",
      expiresAt: "2026-10-29T12:00:00Z",
    },
  });

  it("creates an account from a link and signs in", async () => {
    let accepted = false;
    const { client, requests } = stubServer({
      ...signedOut,
      "POST /api/v1/invitations/preview": preview,
      "POST /api/v1/invitations/accept": () => {
        accepted = true;
        return { status: 201, body: stubSession("active", "csrf-new", "new@example.org") };
      },
      "GET /api/v1/workspaces": () => ({
        status: 200,
        body: { items: [workspace("tester", ["workspace.read"])], nextCursor: null },
      }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/invite#qali_inv_abc" />);
    expect(await screen.findByRole("heading", { name: "Join Acme QA" })).toBeInTheDocument();
    expect(screen.getByLabelText("Email")).toHaveValue("new@example.org");
    await user.type(screen.getByLabelText("Your name"), "New Member");
    await user.type(screen.getByLabelText("Password"), "a long enough password");
    await user.click(screen.getByRole("button", { name: "Create account and join" }));
    expect(await screen.findByText(/Signed in as/)).toBeInTheDocument();
    expect(accepted).toBe(true);
    const body = (await requests
      .find((r) => r.url.endsWith("/invitations/accept"))!
      .json()) as Record<string, string>;
    expect(body.token).toBe("qali_inv_abc");
    // The token never appears in a URL the client requests.
    expect(requests.every((r) => !r.url.includes("qali_inv_abc"))).toBe(true);
  });

  it("rejects invalid links without details", async () => {
    const { client } = stubServer({
      ...signedOut,
      "POST /api/v1/invitations/preview": () => ({
        status: 410,
        body: { code: "invitation_invalid" },
      }),
    });
    render(<App client={client} initialPath="/invite#qali_inv_used" />);
    expect(
      await screen.findByRole("heading", { name: "Invitation not valid" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/invalid, expired, or already used/);
  });

  it("joins with the signed-in account", async () => {
    const { client } = stubServer({
      ...signedIn("tester", ["workspace.read"]),
      "POST /api/v1/invitations/preview": preview,
      "POST /api/v1/invitations/accept-existing": () => ({
        status: 410,
        body: { code: "invitation_invalid" },
      }),
    });
    const user = userEvent.setup();
    render(<App client={client} initialPath="/invite#qali_inv_abc" />);
    await user.click(await screen.findByRole("button", { name: "Join workspace" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/invalid, expired, or already used/);
  });
});
