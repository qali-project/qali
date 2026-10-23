import { defineConfig, devices } from "@playwright/test";

// E2E runs against the production binary with the embedded bundle.
// `make test-e2e` builds it and sets QALI_E2E_BINARY.
const binary = process.env.QALI_E2E_BINARY;
const secrets = process.env.QALI_E2E_SECRETS_DIR;
if (!binary || !secrets) {
  throw new Error("QALI_E2E_BINARY and QALI_E2E_SECRETS_DIR are not set; run `make test-e2e`.");
}
// Avoid 4000-4700: Windows/Hyper-V often reserves ports in that range.
const basePort = Number(process.env.QALI_E2E_PORT ?? "18473");
const allBrowsers = process.env.QALI_E2E_ALL_BROWSERS === "1";

// Each suite is a journey over its own fresh installation: its own server
// and database (tools/e2eenv creates one database per suite). The first
// suite runs every spec that no other suite claims, so a new spec file can
// never be skipped silently.
const isolated = [{ name: "admin", testMatch: /admin\.spec\.ts/ }];
const suites = [
  { name: "auth", testMatch: /.*\.spec\.ts/, testIgnore: isolated.map((s) => s.testMatch) },
  ...isolated.map((s) => ({ ...s, testIgnore: [] as RegExp[] })),
].map((suite, i) => ({
  ...suite,
  port: basePort + i,
  baseURL: `http://127.0.0.1:${basePort + i}`,
}));

const browsers = [
  { name: "chromium", use: devices["Desktop Chrome"] },
  ...(allBrowsers
    ? [
        { name: "firefox", use: devices["Desktop Firefox"] },
        { name: "webkit", use: devices["Desktop Safari"] },
      ]
    : []),
];

export default defineConfig({
  testDir: "./e2e",
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: { trace: "retain-on-failure" },
  projects: suites.flatMap((suite) =>
    browsers.map((browser) => ({
      name: `${suite.name}-${browser.name}`,
      testMatch: suite.testMatch,
      testIgnore: suite.testIgnore,
      use: { ...browser.use, baseURL: suite.baseURL },
    })),
  ),
  webServer: suites.map((suite) => ({
    command: `"${binary}"`,
    env: {
      ...process.env,
      QALI_ENV: "development",
      QALI_HTTP_ADDR: `127.0.0.1:${suite.port}`,
      QALI_PUBLIC_URL: suite.baseURL,
      QALI_DATABASE_URL_FILE: `${secrets}/${suite.name}/database_url`,
      QALI_KEK_FILE: `${secrets}/${suite.name}/kek`,
      QALI_TOKEN_PEPPER_FILE: `${secrets}/${suite.name}/token_pepper`,
      QALI_PASSWORD_PEPPER_FILE: `${secrets}/${suite.name}/password_pepper`,
    },
    url: `${suite.baseURL}/health/live`,
    reuseExistingServer: false,
    timeout: 30_000,
  })),
});
