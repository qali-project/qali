import { describe, expect, it } from "vitest";

import type { Session } from "../../api/client";
import { allowedPath, destination, messageFor } from "./destination";

const session = (state: Session["state"]): Session => ({
  state,
  csrfToken: "t",
  expiresAt: "2026-10-22T12:00:00.000Z",
  user: {
    id: "0199f0c2-1111-7000-8000-000000000001",
    email: "o@example.org",
    displayName: "O",
    mfaEnrolled: false,
  },
});

describe("destination", () => {
  it("sends everyone to setup until an owner exists", () => {
    expect(destination(true, null)).toBe("/setup");
    expect(destination(true, session("active"))).toBe("/setup");
  });

  it("routes by session state", () => {
    expect(destination(false, null)).toBe("/login");
    expect(destination(false, session("mfa_enrollment"))).toBe("/mfa/enroll");
    expect(destination(false, session("mfa_challenge"))).toBe("/mfa/challenge");
    expect(destination(false, session("active"))).toBe("/");
  });
});

describe("messageFor", () => {
  it("maps known problem codes and falls back for unknown ones", () => {
    expect(messageFor("invalid_credentials")).toMatch(/incorrect/);
    expect(messageFor("too_many_attempts")).toMatch(/Too many attempts/);
    expect(messageFor("internal_error")).toMatch(/Something went wrong/);
    expect(messageFor(undefined)).toMatch(/Something went wrong/);
  });
});

describe("allowedPath", () => {
  it("keeps pages behind setup and sign-in", () => {
    expect(allowedPath("/admin/members", true, null)).toBe(false);
    expect(allowedPath("/admin/members", false, null)).toBe(false);
    expect(allowedPath("/recover", false, null)).toBe(true);
    expect(allowedPath("/admin/members", false, session("mfa_challenge"))).toBe(false);
  });

  it("lets active sessions use application pages but not sign-in pages", () => {
    expect(allowedPath("/admin/members", false, session("active"))).toBe(true);
    expect(allowedPath("/projects", false, session("active"))).toBe(true);
    expect(allowedPath("/login", false, session("active"))).toBe(false);
    expect(allowedPath("/mfa/enroll", false, session("active"))).toBe(false);
  });

  it("opens invitation links signed out or active, not mid-MFA", () => {
    expect(allowedPath("/invite", false, null)).toBe(true);
    expect(allowedPath("/invite", false, session("active"))).toBe(true);
    expect(allowedPath("/invite", false, session("mfa_enrollment"))).toBe(false);
    expect(allowedPath("/invite", true, null)).toBe(false);
  });
});
