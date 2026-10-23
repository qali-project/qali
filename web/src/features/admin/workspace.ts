import { useQuery } from "@tanstack/react-query";
import { matchPath, useLocation } from "react-router";

import type { components } from "../../generated/api";
import { useAuth } from "../auth/AuthContext";

export type Workspace = components["schemas"]["Workspace"];
export type Member = components["schemas"]["Member"];
export type MemberList = components["schemas"]["MemberList"];
export type ProjectList = components["schemas"]["ProjectList"];
export type Invitation = components["schemas"]["Invitation"];
export type Project = components["schemas"]["Project"];
export type ProjectMember = components["schemas"]["ProjectMember"];
export type WorkspaceRole = components["schemas"]["WorkspaceRole"];
export type AccessLevel = components["schemas"]["ProjectAccessLevel"];

const storageKey = "qali.workspace";

/** Every workspace where the caller is an active member. */
export function useWorkspaces() {
  const { client, session } = useAuth();
  return useQuery({
    queryKey: ["workspaces", session?.user.id],
    enabled: session?.state === "active",
    queryFn: async (): Promise<Workspace[]> => {
      const { data, error } = await client.GET("/api/v1/workspaces", {
        params: { query: { limit: 200 } },
      });
      if (error !== undefined || data === undefined) throw new Error("workspaces unavailable");
      return data.items;
    },
  });
}

/** The workspace ID in the current URL (/w/:workspaceId/...), if any. */
export function useWorkspaceId(): string | undefined {
  const { pathname } = useLocation();
  return matchPath({ path: "/w/:workspaceId", end: false }, pathname)?.params.workspaceId;
}

/** The workspace to open for links without one: the last chosen, else the first. */
export function preferredWorkspace(list: Workspace[]): Workspace | undefined {
  let remembered: string | null = null;
  try {
    remembered = localStorage.getItem(storageKey);
  } catch {
    // Storage may be unavailable (private mode); fall back to the first.
  }
  return list.find((w) => w.id === remembered) ?? list[0];
}

export function rememberWorkspace(id: string) {
  try {
    localStorage.setItem(storageKey, id);
  } catch {
    // Remembering is a convenience only.
  }
}

export type WorkspaceResult = {
  isPending: boolean;
  isError: boolean;
  /** The workspace named in the URL; null when the caller is not a member. */
  data: Workspace | null | undefined;
};

/**
 * The workspace named in the URL with the permissions the server reports
 * (REVIEW-006: pages never pick a workspace implicitly). Permissions only
 * hide controls; the server authorizes every request.
 */
export function useWorkspace(): WorkspaceResult {
  const id = useWorkspaceId();
  const list = useWorkspaces();
  return {
    isPending: list.isPending,
    isError: list.isError,
    data: list.data ? (list.data.find((w) => w.id === id) ?? null) : undefined,
  };
}

/** Path of a page inside a workspace. */
export const inWorkspace = (ws: { id: string }, path = "") => `/w/${ws.id}${path}`;

export function can(subject: { permissions: string[] } | null | undefined, permission: string) {
  return subject?.permissions.includes(permission) ?? false;
}

/** Administration is shown only to roles that hold an administrative grant. */
export function canAdminister(ws: Workspace | null | undefined): boolean {
  return can(ws, "members.read");
}

export const roleLabels: Record<WorkspaceRole, string> = {
  owner: "Owner",
  workspace_admin: "Workspace administrator",
  qa_lead: "QA lead",
  tester: "Tester",
  viewer: "Viewer",
};

export const levelLabels: Record<AccessLevel, string> = {
  contributor: "Contributor",
  viewer: "Viewer",
};

/** ETag value for optimistic concurrency (ADR-0003). */
export const ifMatch = (version: number) => `"${version}"`;

const messages: Record<string, string> = {
  forbidden: "You do not have permission to do this.",
  not_found: "This item no longer exists or you cannot access it.",
  last_owner: "The workspace needs at least one active owner.",
  version_mismatch: "Someone else changed this first. The list was refreshed; try again.",
  if_match_required: "The change could not be applied. Reload and try again.",
  already_member: "This person is already a member.",
  account_exists: "An account with this email already exists. Sign in to accept the invitation.",
  invitation_invalid:
    "This invitation link is invalid, expired, or already used. Ask for a new invitation.",
  project_code_taken: "Another project already uses this code.",
  invalid_email: "Enter a valid email address.",
  weak_password: "Use at least 12 characters, different from your email address.",
  invalid_code: "That code is not valid. Enter the current code from your authenticator app.",
  too_many_attempts: "Too many attempts. Wait a moment and try again.",
  invalid_input: "Check the values and try again.",
};

export function adminMessage(code: string | undefined): string {
  return (code && messages[code]) ?? "Something went wrong. Try again.";
}
