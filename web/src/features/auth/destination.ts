import type { Session } from "../../api/client";

export type AuthRoute = "/setup" | "/login" | "/mfa/enroll" | "/mfa/challenge" | "/";

/** Where a visitor must go, given setup status and the current session. */
export function destination(setupRequired: boolean, session: Session | null): AuthRoute {
  if (setupRequired) return "/setup";
  if (!session) return "/login";
  switch (session.state) {
    case "mfa_enrollment":
      return "/mfa/enroll";
    case "mfa_challenge":
      return "/mfa/challenge";
    default:
      return "/";
  }
}

/** Pages reachable without the session that destination() requires. */
export const publicRoutes = ["/login", "/recover", "/reset-password"] as const;

/** Sign-in pages; an active session is sent home from them. */
export const authRoutes = ["/setup", "/mfa/enroll", "/mfa/challenge", ...publicRoutes] as const;

/** Whether pathname may render, given setup status and session. */
export function allowedPath(pathname: string, setupRequired: boolean, session: Session | null) {
  const target = destination(setupRequired, session);
  if (pathname === target) return true;
  if (setupRequired) return false;
  // Invitation links work signed out and with an active session.
  if (pathname === "/invite") return !session || session.state === "active";
  if (!session) return (publicRoutes as readonly string[]).includes(pathname);
  return target === "/" && !(authRoutes as readonly string[]).includes(pathname);
}

const messages: Record<string, string> = {
  invalid_credentials: "The email or password is incorrect.",
  invalid_code: "That code is not valid. Enter the current code from your authenticator app.",
  invalid_token: "This reset link is invalid or has expired. Ask your administrator for a new one.",
  too_many_attempts: "Too many attempts. Wait a moment and try again.",
  weak_password: "Use at least 12 characters, different from your email address.",
  invalid_email: "Enter a valid email address.",
  already_bootstrapped: "Setup is already complete. Sign in instead.",
  setup_token_invalid:
    "The setup token is invalid, expired, or already used. Run “qali setup-token” on the server for a new one.",
  already_enrolled: "Two-factor authentication is already enabled.",
  enrollment_not_started: "Start the setup of your authenticator app first.",
};

/** A human message for a problem code. */
export function messageFor(code: string | undefined): string {
  return (code && messages[code]) ?? "Something went wrong. Try again.";
}
