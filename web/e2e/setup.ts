import { execFileSync } from "node:child_process";

import type { TestInfo } from "@playwright/test";

/**
 * Issues a first-owner setup token with the operator CLI against the
 * suite's own database, as an operator would on the server (REVIEW-001).
 */
export function setupToken(info: TestInfo): string {
  const binary = process.env.QALI_E2E_BINARY;
  const secrets = process.env.QALI_E2E_SECRETS_DIR;
  if (!binary || !secrets) throw new Error("run `make test-e2e`");
  const suite = info.project.name.split("-")[0]!;
  const out = execFileSync(binary, ["setup-token"], {
    env: {
      ...process.env,
      QALI_ENV: "development",
      QALI_PUBLIC_URL: "http://127.0.0.1",
      QALI_DATABASE_URL_FILE: `${secrets}/${suite}/database_url`,
      QALI_KEK_FILE: `${secrets}/${suite}/kek`,
      QALI_TOKEN_PEPPER_FILE: `${secrets}/${suite}/token_pepper`,
      QALI_PASSWORD_PEPPER_FILE: `${secrets}/${suite}/password_pepper`,
    },
    encoding: "utf8",
  });
  const token = /qali_setup_\S+/.exec(out)?.[0];
  if (!token) throw new Error(`no setup token in CLI output: ${out}`);
  return token;
}
