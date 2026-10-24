import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { setupToken } from "./setup";
import { Authenticator } from "./totp";

// One journey over one fresh database (MVP-04.AC-14): bootstrap, MFA
// enrollment, sign-out, sign-in with TOTP, recovery, and recovery replay.
test.describe.configure({ mode: "serial" });

const email = "owner@example.org";
const firstPassword = "correct horse battery staple";
const recoveredPassword = "recovered passphrase for the owner";

async function expectNoAxeViolations(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag22aa"])
    .analyze();
  expect(results.violations).toEqual([]);
}

async function sessionState(page: Page): Promise<string | undefined> {
  const res = await page.request.get("/api/v1/auth/session");
  if (res.status() !== 200) return undefined;
  return ((await res.json()) as { state: string }).state;
}

async function signIn(page: Page, password: string, auth: Authenticator) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByLabel("Password").press("Enter"); // keyboard submission
  await expect(page.getByRole("heading", { name: "Enter your authentication code" })).toBeVisible();
  expect(await sessionState(page)).toBe("mfa_challenge");
  await page.getByLabel("Authentication code", { exact: true }).fill(await auth.next());
  await page.getByLabel("Authentication code", { exact: true }).press("Enter");
  await expect(page.getByText(/Signed in as/)).toBeVisible();
  expect(await sessionState(page)).toBe("active");
}

async function signOut(page: Page) {
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  expect(await sessionState(page)).toBeUndefined();
}

test("owner journey: setup, MFA, sign-out, sign-in, recovery", async ({ page }, info) => {
  test.setTimeout(180_000); // may wait for fresh TOTP windows

  // Bootstrap.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Create the owner account" })).toBeVisible();
  await expectNoAxeViolations(page);
  // Without the operator's setup token nobody can claim the installation.
  await page.getByLabel("Setup token").fill("qali_setup_guessed");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Your name").fill("Olga Owner");
  await page.getByLabel("Workspace name").fill("Acme QA");
  await page.getByLabel("Password").fill(firstPassword);
  await page.getByRole("button", { name: "Create owner account" }).click();
  await expect(page.getByRole("alert")).toHaveText(/setup token is invalid/);
  await page.getByLabel("Setup token").fill(setupToken(info));
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Your name").fill("Olga Owner");
  await page.getByLabel("Workspace name").fill("Acme QA");
  await page.getByLabel("Password").fill(firstPassword);
  await page.getByRole("button", { name: "Create owner account" }).click();

  // MFA enrollment is mandatory for the owner.
  await expect(
    page.getByRole("heading", { name: "Set up two-factor authentication" }),
  ).toBeVisible();
  expect(await sessionState(page)).toBe("mfa_enrollment");
  await page.getByRole("button", { name: "Set up authenticator app" }).click();
  const secret = (await page.getByTestId("totp-secret").textContent())?.trim() ?? "";
  expect(secret).toMatch(/^[A-Z2-7]{32}$/);
  const auth = new Authenticator(secret);
  await page.getByLabel("Authentication code", { exact: true }).fill(await auth.next());
  await page.getByRole("button", { name: "Confirm" }).click();
  const codeList = page.getByRole("list", { name: "Recovery codes" }).locator("code");
  await expect(codeList).toHaveCount(10); // waits for the confirmation response
  const codes = await codeList.allTextContents();
  await expectNoAxeViolations(page);
  await page.getByRole("button", { name: "I saved my recovery codes" }).click();
  await expect(page.getByText("Signed in as Olga Owner (owner@example.org)")).toBeVisible();
  expect(await sessionState(page)).toBe("active");

  // Sign out and back in with password and TOTP.
  await signOut(page);
  await expectNoAxeViolations(page);
  await signIn(page, firstPassword, auth);

  // Recover with a single-use code; all sessions end.
  await signOut(page);
  await page.getByRole("link", { name: "Use a recovery code" }).click();
  await expect(page.getByRole("heading", { name: "Recover your account" })).toBeVisible();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Recovery code").fill(codes[0]!);
  await page.getByLabel("New password").fill(recoveredPassword);
  await page.getByRole("button", { name: "Reset password" }).click();
  await expect(page.getByRole("status")).toHaveText(/Your password was reset/);

  // The old password no longer works; the new one does.
  await page.getByRole("link", { name: "Sign in" }).click();
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(firstPassword);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("The email or password is incorrect.");
  await signIn(page, recoveredPassword, auth);

  // The used recovery code cannot be replayed.
  await signOut(page);
  await page.goto("/recover");
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Recovery code").fill(codes[0]!);
  await page.getByLabel("New password").fill("another long passphrase");
  await page.getByRole("button", { name: "Reset password" }).click();
  await expect(page.getByRole("alert")).toHaveText("The email or password is incorrect.");
});
