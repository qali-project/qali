import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { App } from "../../App";
import { stubServer, stubSession } from "../../test/stubServer";

const A = "0199f0c2-2222-7000-8000-00000000000a";
const B = "0199f0c2-2222-7000-8000-00000000000b";

const handlers = {
  "GET /api/v1/setup": () => ({ status: 200, body: { bootstrapRequired: false } }),
  "GET /api/v1/auth/session": () => ({ status: 200, body: stubSession("active") }),
  "GET /api/v1/workspaces": () => ({
    status: 200,
    body: {
      items: [
        { id: A, name: "Acme QA", role: "owner", permissions: ["workspace.read", "members.read"] },
        { id: B, name: "Beta Labs", role: "tester", permissions: ["workspace.read"] },
      ],
      nextCursor: null,
    },
  }),
  [`GET /api/v1/workspaces/${A}/projects`]: () => ({
    status: 200,
    body: { items: [], nextCursor: null },
  }),
  [`GET /api/v1/workspaces/${B}/projects`]: () => ({
    status: 200,
    body: { items: [], nextCursor: null },
  }),
};

afterEach(() => {
  localStorage.clear();
});

// REVIEW-006: a member of several workspaces chooses one explicitly, and
// every page and request is bound to the workspace in the URL.
describe("workspace selection", () => {
  it("binds pages and requests to the chosen workspace", async () => {
    const { client, requests } = stubServer(handlers);
    const user = userEvent.setup();
    render(<App client={client} initialPath="/" />);
    const picker = await screen.findByLabelText("Workspace");
    expect(
      within(picker)
        .getAllByRole("option")
        .map((o) => o.textContent),
    ).toEqual(["Acme QA", "Beta Labs"]);
    const nav = screen.getByRole("navigation", { name: "Main" });
    expect(within(nav).getByRole("link", { name: "Members" })).toBeInTheDocument();

    await user.selectOptions(picker, B);
    expect(await screen.findByRole("heading", { name: "Beta Labs" })).toBeInTheDocument();
    expect(within(nav).queryByRole("link", { name: "Members" })).not.toBeInTheDocument();
    await user.click(within(nav).getByRole("link", { name: "Projects" }));
    await screen.findByText("No projects yet.");
    const listed = requests.filter((r) => r.url.includes("/projects"));
    expect(listed.every((r) => r.url.includes(`/workspaces/${B}/`))).toBe(true);
  });

  it("remembers the last workspace for links without one", async () => {
    localStorage.setItem("qali.workspace", B);
    const { client, requests } = stubServer(handlers);
    render(<App client={client} initialPath="/projects" />);
    await screen.findByText("No projects yet.");
    expect(requests.some((r) => r.url.includes(`/workspaces/${B}/projects`))).toBe(true);
    expect(requests.some((r) => r.url.includes(`/workspaces/${A}/projects`))).toBe(false);
  });

  it("reports a workspace the caller does not belong to", async () => {
    const { client } = stubServer(handlers);
    render(<App client={client} initialPath="/w/0199f0c2-2222-7000-8000-0000000000ff/projects" />);
    expect(await screen.findByRole("heading", { name: "Workspace not found" })).toBeInTheDocument();
  });
});
