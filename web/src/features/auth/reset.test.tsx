import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { App } from "../../App";
import { stubServer } from "../../test/stubServer";

describe("password reset page (REVIEW-005)", () => {
  it("never takes the bearer token from the URL", async () => {
    const { client } = stubServer({
      "GET /api/v1/setup": () => ({ status: 200, body: { bootstrapRequired: false } }),
      "GET /api/v1/auth/session": () => ({ status: 401, body: { code: "unauthenticated" } }),
    });
    render(<App client={client} initialPath="/reset-password?token=qali_reset_fromquery" />);
    const field = await screen.findByLabelText("Reset token");
    expect(field).toHaveValue("");
    expect(document.body.innerHTML).not.toContain("qali_reset_fromquery");
  });
});
