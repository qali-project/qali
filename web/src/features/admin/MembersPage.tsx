import { zodResolver } from "@hookform/resolvers/zod";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { problemCode } from "../../api/client";
import { usePageTitle } from "../../app/title";
import { FormError, TextField } from "../../components/TextField";
import { useAuth } from "../auth/AuthContext";
import { NotPermitted, WorkspaceState } from "./NotPermitted";
import { useSensitive } from "./StepUp";
import {
  adminMessage,
  can,
  canAdminister,
  ifMatch,
  roleLabels,
  useWorkspace,
  type Member,
  type MemberList,
  type Workspace,
  type WorkspaceRole,
} from "./workspace";

const roles = Object.keys(roleLabels) as WorkspaceRole[];
const invitableRoles = roles.filter((r) => r !== "owner");

export function MembersPage() {
  usePageTitle("Members");
  const ws = useWorkspace();
  if (ws.isPending || ws.isError || !ws.data) return <WorkspaceState query={ws} />;
  if (!canAdminister(ws.data)) return <NotPermitted />;
  return (
    <section aria-labelledby="members-title">
      <h2 id="members-title">Members</h2>
      <MemberTable ws={ws.data} />
      {can(ws.data, "members.invite") && (
        <>
          <InviteForm ws={ws.data} />
          <PendingInvitations ws={ws.data} />
        </>
      )}
    </section>
  );
}

function useMembers(ws: Workspace) {
  const { client } = useAuth();
  return useInfiniteQuery({
    queryKey: ["members", ws.id],
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: MemberList) => last.nextCursor ?? undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/api/v1/workspaces/{workspaceId}/members", {
        params: { path: { workspaceId: ws.id }, query: { cursor: pageParam } },
      });
      if (error !== undefined || data === undefined) throw new Error("members unavailable");
      return data;
    },
  });
}

/** All loaded members, for pickers on other pages. */
export function useMemberList(ws: Workspace | null | undefined) {
  const { client } = useAuth();
  return useQuery({
    queryKey: ["member-picker", ws?.id],
    enabled: can(ws, "members.read"),
    queryFn: async () => {
      const { data, error } = await client.GET("/api/v1/workspaces/{workspaceId}/members", {
        params: { path: { workspaceId: ws!.id }, query: { limit: 200 } },
      });
      if (error !== undefined || data === undefined) throw new Error("members unavailable");
      return data.items.filter((m) => m.status === "active");
    },
  });
}

function MemberTable({ ws }: { ws: Workspace }) {
  const { client } = useAuth();
  const queries = useQueryClient();
  const members = useMembers(ws);
  const [error, setError] = useState<string>();
  const sensitive = useSensitive(setError);

  const update = (m: Member, body: { role?: WorkspaceRole; status?: Member["status"] }) =>
    sensitive.run(async () => {
      const { error: problem } = await client.PATCH(
        "/api/v1/workspaces/{workspaceId}/members/{userId}",
        {
          params: {
            path: { workspaceId: ws.id, userId: m.userId },
            header: { "If-Match": ifMatch(m.version) },
          },
          body,
        },
      );
      const code = problem === undefined ? undefined : (problemCode(problem) ?? "unknown");
      if (code !== "recent_mfa_required") {
        await queries.invalidateQueries({ queryKey: ["members", ws.id] });
        await queries.invalidateQueries({ queryKey: ["workspaces"] });
      }
      return code;
    });

  if (members.isPending) return <p role="status">Loading members…</p>;
  if (members.isError) return <p role="alert">Members could not be loaded. Try again later.</p>;
  const rows = members.data.pages.flatMap((p) => p.items);
  const canRole = can(ws, "members.update_role");
  const canStatus = can(ws, "members.deactivate");
  return (
    <>
      {sensitive.prompt}
      <FormError message={error} />
      <div className="table-wrap">
        <table>
          <caption className="visually-hidden">Workspace members</caption>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Email</th>
              <th scope="col">Role</th>
              <th scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((m) => (
              <tr key={m.userId}>
                <th scope="row">{m.displayName}</th>
                <td>{m.email}</td>
                <td>
                  {canRole ? (
                    <select
                      aria-label={`Role for ${m.displayName}`}
                      value={m.role}
                      onChange={(e) => void update(m, { role: e.target.value as WorkspaceRole })}
                    >
                      {roles.map((r) => (
                        <option key={r} value={r}>
                          {roleLabels[r]}
                        </option>
                      ))}
                    </select>
                  ) : (
                    roleLabels[m.role]
                  )}
                </td>
                <td>
                  <span>{m.status === "active" ? "Active" : "Deactivated"}</span>{" "}
                  {canStatus && (
                    <button
                      type="button"
                      className="secondary"
                      aria-label={`${m.status === "active" ? "Deactivate" : "Reactivate"} ${m.displayName}`}
                      onClick={() =>
                        void update(m, {
                          status: m.status === "active" ? "deactivated" : "active",
                        })
                      }
                    >
                      {m.status === "active" ? "Deactivate" : "Reactivate"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {members.hasNextPage && (
        <button
          type="button"
          className="secondary"
          disabled={members.isFetchingNextPage}
          onClick={() => void members.fetchNextPage()}
        >
          Show more members
        </button>
      )}
    </>
  );
}

const inviteSchema = z.object({
  email: z.string().trim().email("Enter a valid email address.").max(254),
  role: z.enum(["workspace_admin", "qa_lead", "tester", "viewer"]),
});

function InviteForm({ ws }: { ws: Workspace }) {
  const { client } = useAuth();
  const queries = useQueryClient();
  const roleId = useId();
  const [error, setError] = useState<string>();
  const [link, setLink] = useState<{ email: string; url: string }>();
  const sensitive = useSensitive(setError);
  const form = useForm<z.infer<typeof inviteSchema>>({
    resolver: zodResolver(inviteSchema),
    defaultValues: { role: "tester" },
  });
  const onSubmit = form.handleSubmit((values) =>
    sensitive.run(async () => {
      setLink(undefined);
      const { data, error: problem } = await client.POST(
        "/api/v1/workspaces/{workspaceId}/invitations",
        { params: { path: { workspaceId: ws.id } }, body: values },
      );
      if (!data) return problemCode(problem) ?? "unknown";
      // The token travels in the fragment, which browsers never send to
      // servers or put in Referer headers.
      setLink({
        email: data.invitation.email,
        url: `${window.location.origin}/invite#${data.token}`,
      });
      form.reset({ email: "", role: "tester" });
      await queries.invalidateQueries({ queryKey: ["invitations", ws.id] });
      return undefined;
    }),
  );
  return (
    <section aria-labelledby="invite-title">
      <h3 id="invite-title">Invite a member</h3>
      {sensitive.prompt}
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Email"
          type="email"
          autoComplete="off"
          error={form.formState.errors.email?.message}
          {...form.register("email")}
        />
        <div className="field">
          <label htmlFor={roleId}>Role</label>
          <select id={roleId} {...form.register("role")}>
            {invitableRoles.map((r) => (
              <option key={r} value={r}>
                {roleLabels[r]}
              </option>
            ))}
          </select>
        </div>
        <FormError message={error} />
        <button type="submit" disabled={form.formState.isSubmitting}>
          Create invitation
        </button>
      </form>
      {link && (
        <div role="status" className="panel">
          <p>
            Send this link to <strong>{link.email}</strong>. It works once, expires in 7 days, and
            is not shown again.
          </p>
          <TextField label="Invitation link" readOnly value={link.url} />
        </div>
      )}
    </section>
  );
}

function PendingInvitations({ ws }: { ws: Workspace }) {
  const { client } = useAuth();
  const queries = useQueryClient();
  const [error, setError] = useState<string>();
  const invitations = useQuery({
    queryKey: ["invitations", ws.id],
    queryFn: async () => {
      const { data, error } = await client.GET("/api/v1/workspaces/{workspaceId}/invitations", {
        params: { path: { workspaceId: ws.id }, query: { limit: 200 } },
      });
      if (error !== undefined || data === undefined) throw new Error("invitations unavailable");
      return data.items;
    },
  });
  const revoke = async (id: string) => {
    setError(undefined);
    const { response, error: problem } = await client.POST(
      "/api/v1/workspaces/{workspaceId}/invitations/{invitationId}/revoke",
      { params: { path: { workspaceId: ws.id, invitationId: id } } },
    );
    if (response.status !== 204) setError(adminMessage(problemCode(problem)));
    await queries.invalidateQueries({ queryKey: ["invitations", ws.id] });
  };
  return (
    <section aria-labelledby="pending-title">
      <h3 id="pending-title">Pending invitations</h3>
      <FormError message={error} />
      {invitations.isPending && <p role="status">Loading invitations…</p>}
      {invitations.isError && <p role="alert">Invitations could not be loaded.</p>}
      {invitations.data?.length === 0 && <p>No pending invitations.</p>}
      {invitations.data && invitations.data.length > 0 && (
        <ul className="plain">
          {invitations.data.map((inv) => (
            <li key={inv.id}>
              {inv.email} · {roleLabels[inv.role]} · expires{" "}
              <time dateTime={inv.expiresAt}>{new Date(inv.expiresAt).toLocaleString()}</time>{" "}
              <button
                type="button"
                className="secondary"
                aria-label={`Revoke invitation for ${inv.email}`}
                onClick={() => void revoke(inv.id)}
              >
                Revoke
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
