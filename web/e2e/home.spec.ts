import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// The home page requires a session since MVP-04; these checks cover the
// public shell and API.
test("the liveness API answers from the real server", async ({ request }) => {
  const live = await request.get("/health/live");
  expect(live.status()).toBe(200);
  expect(await live.json()).toEqual({ status: "ok" });
});

test("the server is ready against a migrated database", async ({ request }) => {
  const ready = await request.get("/health/ready");
  expect(ready.status()).toBe(200);
  expect(await ready.json()).toEqual({ status: "ready" });
});

test("the content security policy does not block the application", async ({ page }) => {
  const errors: string[] = [];
  // Anonymous visitors legitimately get 401 from the session endpoint; only
  // policy violations and script errors count.
  page.on("console", (msg) => {
    if (msg.type() === "error" && msg.text().includes("Content Security Policy"))
      errors.push(msg.text());
  });
  page.on("pageerror", (err) => errors.push(err.message));
  const response = await page.goto("/");
  expect(response?.headers()["content-security-policy"]).toContain("default-src 'self'");
  await expect(page.getByRole("heading", { level: 2 })).toBeVisible();
  expect(errors).toEqual([]);
});

test("client-side routes load the application shell", async ({ page }) => {
  await page.goto("/projects/does-not-matter");
  await expect(page.getByRole("heading", { level: 1, name: "Qali" })).toBeVisible();
});

test("the entry page has no detectable accessibility violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 2 })).toBeVisible();
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag22aa"])
    .analyze();
  expect(results.violations).toEqual([]);
});
