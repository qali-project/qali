import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";

import { problemCode } from "../../api/client";
import { usePageTitle } from "../../app/title";
import { FormError, TextField } from "../../components/TextField";
import { useAuth } from "../auth/AuthContext";
import { useSensitive } from "./StepUp";
import { useWorkspace } from "./workspace";
import { WorkspaceState } from "./NotPermitted";

export function SecurityPage() {
  usePageTitle("Sign-in security");
  const ws = useWorkspace();
  if (ws.isPending || ws.isError || !ws.data) return <WorkspaceState query={ws} />;
  if (!ws.data.permissions.includes("security.read"))
    return <p role="alert">You cannot manage sign-in security.</p>;
  return <SecuritySettings workspaceId={ws.data.id} />;
}

function SecuritySettings({ workspaceId }: { workspaceId: string }) {
  const { client } = useAuth();
  const queries = useQueryClient();
  const [error, setError] = useState<string>();
  const sensitive = useSensitive(setError);
  const [busy, setBusy] = useState(false);
  const [issuer, setIssuer] = useState("");
  const [clientId, setClientId] = useState("");
  const [label, setLabel] = useState("");
  const [secret, setSecret] = useState("");
  const provider = useQuery({
    queryKey: ["oidc-provider", workspaceId],
    queryFn: async () => {
      const { data, response } = await client.GET(
        "/api/v1/workspaces/{workspaceId}/security/oidc-provider",
        { params: { path: { workspaceId } } },
      );
      if (response.status === 404) return { data: null, etag: undefined };
      if (!data) throw new Error("Provider unavailable");
      return { data, etag: response.headers.get("ETag") ?? undefined };
    },
  });
  const policy = useQuery({
    queryKey: ["login-policy", workspaceId],
    queryFn: async () => {
      const { data, response } = await client.GET(
        "/api/v1/workspaces/{workspaceId}/security/login-policy",
        { params: { path: { workspaceId } } },
      );
      if (!data) throw new Error("Policy unavailable");
      return { data, etag: response.headers.get("ETag") ?? undefined };
    },
  });
  const refresh = async () => {
    await queries.invalidateQueries({ queryKey: ["oidc-provider", workspaceId] });
    await queries.invalidateQueries({ queryKey: ["login-policy", workspaceId] });
    await queries.invalidateQueries({ queryKey: ["auth-methods"] });
  };
  const run = async (action: () => Promise<string | undefined>) => {
    setBusy(true);
    try {
      await sensitive.run(action);
    } catch {
      setError("The service is unavailable. Try again.");
    } finally {
      setBusy(false);
    }
  };
  const save = (ev: FormEvent) => {
    ev.preventDefault();
    const saved = provider.data?.data;
    void run(async () => {
      const { data, error } = await client.PUT(
        "/api/v1/workspaces/{workspaceId}/security/oidc-provider",
        {
          params: { path: { workspaceId }, header: { "If-Match": provider.data?.etag } },
          body: {
            issuer: issuer || saved?.issuer || "",
            clientId: clientId || saved?.clientId || "",
            label: label || saved?.label || "",
            ...(secret ? { clientSecret: secret } : {}),
          },
        },
      );
      if (!data) return problemCode(error);
      setSecret("");
      await refresh();
      return undefined;
    });
  };
  const verify = () =>
    run(async () => {
      const { data, error } = await client.POST(
        "/api/v1/workspaces/{workspaceId}/security/oidc-provider/verify",
        { params: { path: { workspaceId } } },
      );
      if (!data) return problemCode(error);
      window.location.assign(data.authorizationUrl);
      return undefined;
    });
  const remove = () =>
    run(async () => {
      const { error, response } = await client.DELETE(
        "/api/v1/workspaces/{workspaceId}/security/oidc-provider",
        { params: { path: { workspaceId }, header: { "If-Match": provider.data?.etag } } },
      );
      if (response.status !== 204) return problemCode(error);
      await refresh();
      return undefined;
    });
  const toggle = () =>
    run(async () => {
      const { data, error } = await client.PUT(
        "/api/v1/workspaces/{workspaceId}/security/login-policy",
        {
          params: { path: { workspaceId }, header: { "If-Match": policy.data?.etag } },
          body: { localLogin: !policy.data?.data.localLogin },
        },
      );
      if (!data) return problemCode(error);
      await refresh();
      return undefined;
    });
  if (provider.isPending || policy.isPending) return <p role="status">Loading sign-in security…</p>;
  if (provider.isError || policy.isError)
    return <p role="alert">Sign-in security is unavailable in this workspace.</p>;
  const saved = provider.data.data;
  return (
    <section aria-labelledby="security-title">
      <h2 id="security-title">Sign-in security</h2>
      <p>
        One identity provider serves this installation. Configure it here, then verify it before
        offering provider sign-in.
      </p>
      <p>
        Provider status: <strong>{saved?.status ?? "Not configured"}</strong>
      </p>
      {saved && (
        <p>
          Register this redirect URI with your provider: <code>{saved.redirectUri}</code>
        </p>
      )}
      <form onSubmit={save}>
        <TextField
          label="Issuer URL"
          type="url"
          required
          value={issuer || saved?.issuer || ""}
          onChange={(e) => setIssuer(e.target.value)}
        />
        <TextField
          label="Client ID"
          required
          value={clientId || saved?.clientId || ""}
          onChange={(e) => setClientId(e.target.value)}
        />
        <TextField
          label="Provider label"
          required
          maxLength={80}
          value={label || saved?.label || ""}
          onChange={(e) => setLabel(e.target.value)}
        />
        <TextField
          label="Client secret"
          type="password"
          autoComplete="new-password"
          required={!saved}
          value={secret}
          onChange={(e) => setSecret(e.target.value)}
          hint={
            saved
              ? "Leave empty to keep the stored secret."
              : "The secret is stored encrypted and cannot be displayed."
          }
        />
        <button disabled={busy} type="submit">
          Save provider
        </button>
      </form>
      {saved && (
        <div className="actions">
          <button disabled={busy} onClick={() => void verify()}>
            Verify provider
          </button>
          <button disabled={busy} onClick={() => void remove()}>
            Remove provider
          </button>
        </div>
      )}
      <h3>Password sign-in</h3>
      <p>
        {policy.data.data.localLogin
          ? "Enabled for all accounts."
          : "Disabled except for emergency Owner access with password and TOTP."}
      </p>
      <p>
        Removing or changing the provider re-enables password sign-in. Accounts without passwords
        must retain a usable provider.
      </p>
      <button
        disabled={busy || ((!saved || saved.status !== "verified") && policy.data.data.localLogin)}
        onClick={() => void toggle()}
      >
        {policy.data.data.localLogin ? "Disable password sign-in" : "Enable password sign-in"}
      </button>
      <FormError message={error} />
      {sensitive.prompt}
    </section>
  );
}
