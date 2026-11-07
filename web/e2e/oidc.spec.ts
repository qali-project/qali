import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type TestInfo } from "@playwright/test";

import { setupToken } from "./setup";
import { Authenticator } from "./totp";

const password = "correct horse battery staple";

async function ownerSetup(page: Page, info: TestInfo) {
  await page.goto("/");
  await page.getByLabel("Setup token").fill(setupToken(info));
  await page.getByLabel("Email").fill("owner@example.org");
  await page.getByLabel("Your name").fill("Olga Owner");
  await page.getByLabel("Workspace name").fill("Acme QA");
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Create owner account" }).click();
  await page.getByRole("button", { name: "Set up authenticator app" }).click();
  const auth = new Authenticator(
    (await page.getByTestId("totp-secret").textContent())?.trim() ?? "",
  );
  await page.getByLabel("Authentication code", { exact: true }).fill(await auth.next());
  await page.getByRole("button", { name: "Confirm", exact: true }).click();
  await page.getByRole("button", { name: "I saved my recovery codes" }).click();
  await expect(page.getByText(/Signed in as Olga Owner/)).toBeVisible();
  return auth;
}

async function idpLogin(page: Page, email: string) {
  await expect(page.getByRole("heading", { name: "Test identity provider" })).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Continue", exact: true }).click();
}

async function signOut(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sign in", exact: true })).toBeVisible();
}

test("configure and verify provider, link and sign in, enforce policy and recover during outage", async ({
  page,
  browser,
}, info) => {
  test.setTimeout(240_000);
  const issuer = process.env.QALI_E2E_OIDC_ISSUER;
  if (!issuer) throw new Error("Run with make test-e2e");
  const auth = await ownerSetup(page, info);
  await page
    .getByRole("navigation", { name: "Main" })
    .getByRole("link", { name: "Security" })
    .click();
  await page.getByLabel("Issuer URL").fill(issuer);
  await page.getByLabel("Client ID", { exact: true }).fill("test-client");
  await page.getByLabel("Provider label").fill("Company sign-in");
  await page.getByLabel("Client secret", { exact: true }).fill("fixture-only");
  await page.getByRole("button", { name: "Save provider" }).click();
  await expect(page.getByText("draft", { exact: true })).toBeVisible();
  await expect(page.getByLabel("Client secret", { exact: true })).toHaveValue("");
  await page.getByRole("button", { name: "Verify provider" }).click();
  await idpLogin(page, "owner@example.org");
  await expect(page.getByText("verified", { exact: true })).toBeVisible();
  expect(
    (await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag22aa"]).analyze())
      .violations,
  ).toEqual([]);

  await page
    .getByRole("navigation", { name: "Main" })
    .getByRole("link", { name: "Members" })
    .click();
  await page.getByLabel("Email").fill("member@example.org");
  await page.getByRole("button", { name: "Create invitation" }).click();
  const link = await page.getByLabel("Invitation link").inputValue();
  const memberContext = await browser.newContext();
  const member = await memberContext.newPage();
  await member.goto(link);
  await member.getByLabel("Your name").fill("Tina Tester");
  await member.getByLabel("Password", { exact: true }).fill(password);
  await member.getByRole("button", { name: "Create account and join" }).click();
  await expect(member.getByText(/Signed in as Tina Tester/)).toBeVisible();
  await member.getByRole("link", { name: "Account", exact: true }).click();
  await member.getByLabel("Current password").fill(password);
  await member.getByRole("button", { name: "Link Company sign-in" }).click();
  await idpLogin(member, "member@example.org");
  await expect(member.getByRole("button", { name: "Unlink provider" })).toBeVisible();
  await signOut(member);
  await member.getByRole("button", { name: "Continue with Company sign-in" }).click();
  await idpLogin(member, "member@example.org");
  await expect(member.getByText(/Signed in as Tina Tester/)).toBeVisible();

  await page
    .getByRole("navigation", { name: "Main" })
    .getByRole("link", { name: "Security" })
    .click();
  await page.getByRole("button", { name: "Disable password sign-in" }).click();
  await expect(
    page.getByText("Disabled except for emergency Owner access with password and TOTP."),
  ).toBeVisible();
  await signOut(member);
  await member.getByLabel("Email").fill("member@example.org");
  await member.getByLabel("Password", { exact: true }).fill(password);
  await member.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(member.getByText("The email or password is incorrect.")).toBeVisible();
  await memberContext.close();

  expect((await page.request.post(issuer + "/outage")).status()).toBe(204);
  await signOut(page);
  await page.getByLabel("Email").fill("owner@example.org");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Enter your authentication code" })).toBeVisible();
  await page.getByLabel("Authentication code", { exact: true }).fill(await auth.next());
  await page.getByLabel("Authentication code", { exact: true }).press("Enter");
  await expect(page.getByText(/Signed in as Olga Owner/)).toBeVisible();
});
