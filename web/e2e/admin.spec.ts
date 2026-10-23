import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type TestInfo } from "@playwright/test";

import { setupToken } from "./setup";
import { Authenticator } from "./totp";

// MVP-05.AC-10 and AC-11 over a fresh installation (the "admin" suite has its
// own server and database): the owner invites a tester, the tester accepts
// and cannot reach administration, and a role change applies at once.
test.describe.configure({ mode: "serial" });

const password = "correct horse battery staple";

async function expectNoAxeViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag22aa"])
    .analyze();
  expect(results.violations).toEqual([]);
}

async function setUpOwner(page: Page, info: TestInfo): Promise<Authenticator> {
  await page.goto("/");
  await page.getByLabel("Setup token").fill(setupToken(info));
  await page.getByLabel("Email").fill("owner@example.org");
  await page.getByLabel("Your name").fill("Olga Owner");
  await page.getByLabel("Workspace name").fill("Acme QA");
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create owner account" }).click();
  await page.getByRole("button", { name: "Set up authenticator app" }).click();
  const secret = (await page.getByTestId("totp-secret").textContent())?.trim() ?? "";
  const auth = new Authenticator(secret);
  await page.getByLabel("Authentication code", { exact: true }).fill(await auth.next());
  await page.getByRole("button", { name: "Confirm" }).click();
  await page.getByRole("button", { name: "I saved my recovery codes" }).click();
  await expect(page.getByText(/Signed in as Olga Owner/)).toBeVisible();
  return auth;
}

test("owner invites a tester; the tester cannot administer; a role change applies at once", async ({
  page,
  browser,
}, info) => {
  test.setTimeout(180_000);
  const auth = await setUpOwner(page, info);

  // The owner sees administration and invites a tester.
  const nav = page.getByRole("navigation", { name: "Main" });
  await nav.getByRole("link", { name: "Members" }).click();
  await expect(page.getByRole("heading", { name: "Members", exact: true })).toBeVisible();
  await expect(page.getByRole("rowheader", { name: "Olga Owner" })).toBeVisible();
  await page.getByLabel("Email").fill("tina@example.org");
  await expect(page.getByLabel("Role", { exact: true })).toHaveValue("tester");
  await page.getByRole("button", { name: "Create invitation" }).click();
  const link = await page.getByLabel("Invitation link").inputValue();
  expect(link).toMatch(/\/invite#qali_inv_[a-z2-7]{16}_/);
  await expect(page.getByText("tina@example.org · Tester")).toBeVisible();
  await expectNoAxeViolations(page);

  // The tester accepts in a separate browser and lands signed in.
  const testerContext = await browser.newContext();
  const tester = await testerContext.newPage();
  await tester.goto(link);
  await expect(tester.getByRole("heading", { name: "Join Acme QA" })).toBeVisible();
  await expectNoAxeViolations(tester);
  await tester.getByLabel("Your name").fill("Tina Tester");
  await tester.getByLabel("Password").fill("tester passphrase 2026");
  await tester.getByLabel("Password").press("Enter"); // keyboard submission
  await expect(tester.getByText(/Signed in as Tina Tester/)).toBeVisible();

  // Administration is hidden and refused on direct navigation.
  const testerNav = tester.getByRole("navigation", { name: "Main" });
  await expect(testerNav.getByRole("link", { name: "Projects" })).toBeVisible();
  await expect(testerNav.getByRole("link", { name: "Members" })).toHaveCount(0);
  await tester.goto("/admin/members");
  await expect(
    tester.getByRole("heading", { name: "You do not have access to this page" }),
  ).toBeVisible();
  await expectNoAxeViolations(tester);
  const api = await tester.request.get(`/api/v1/workspaces/${await workspaceId(tester)}/members`);
  expect(api.status()).toBe(403);

  // The used link cannot be replayed.
  const replay = await browser.newContext();
  const replayPage = await replay.newPage();
  await replayPage.goto(link);
  await expect(replayPage.getByRole("heading", { name: "Invitation not valid" })).toBeVisible();
  await replay.close();

  // The owner promotes the tester; recent MFA may be requested first.
  await page.reload();
  const role = page.getByLabel("Role for Tina Tester");
  const patched = page.waitForResponse((r) => r.request().method() === "PATCH");
  await role.selectOption("workspace_admin");
  if ((await patched).status() === 403) {
    await page.getByLabel("Authenticator code").fill(await auth.next());
    await page.getByRole("button", { name: "Confirm" }).click();
  }
  await expect(role).toHaveValue("workspace_admin");

  // The tester's very next request sees the new role, and with it the
  // administrator MFA requirement (REVIEW-002): enroll first, then administer.
  await tester.goto("/admin/members");
  await expect(
    tester.getByRole("heading", { name: "Set up two-factor authentication" }),
  ).toBeVisible();
  await tester.getByRole("button", { name: "Set up authenticator app" }).click();
  const testerSecret = (await tester.getByTestId("totp-secret").textContent())?.trim() ?? "";
  const testerAuth = new Authenticator(testerSecret);
  await tester.getByLabel("Authentication code", { exact: true }).fill(await testerAuth.next());
  await tester.getByRole("button", { name: "Confirm" }).click();
  await tester.getByRole("button", { name: "I saved my recovery codes" }).click();
  await tester.goto("/admin/members");
  await expect(tester.getByRole("heading", { name: "Members", exact: true })).toBeVisible();
  await expect(
    tester.getByRole("navigation", { name: "Main" }).getByRole("link", { name: "Members" }),
  ).toBeVisible();
  await testerContext.close();
});

async function workspaceId(page: Page): Promise<string> {
  const res = await page.request.get("/api/v1/workspaces");
  const body = (await res.json()) as { items: { id: string }[] };
  return body.items[0]!.id;
}
