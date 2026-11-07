import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { Link } from "react-router";

import { problemCode } from "../../api/client";
import { usePageTitle } from "../../app/title";
import { FormError, TextField } from "../../components/TextField";
import { useSensitive } from "../admin/StepUp";
import { useAuth } from "./AuthContext";
import { useAuthMethods } from "./OIDCSignIn";

export function AccountPage() {
  usePageTitle("Your account");
  const { client, session } = useAuth();
  const methods = useAuthMethods();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const sensitive = useSensitive(setError);
  const identity = useQuery({
    queryKey: ["own-oidc-identity"],
    queryFn: async () => {
      const { data, response } = await client.GET("/api/v1/auth/oidc/identity");
      if (response.status === 404) return null;
      if (!data) throw new Error("Identity unavailable");
      return data;
    },
  });
  const link = async () => {
    setBusy(true);
    try {
      await sensitive.run(async () => {
        const { data, error } = await client.POST("/api/v1/auth/oidc/link", { body: { password } });
        if (!data) return problemCode(error);
        setPassword("");
        window.location.assign(data.authorizationUrl);
        return undefined;
      });
    } catch {
      setError("Provider sign-in is unavailable.");
    } finally {
      setBusy(false);
    }
  };
  const unlink = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const { response } = await client.DELETE("/api/v1/auth/oidc/identity");
      if (response.status !== 204)
        setError("Could not unlink. You must have another usable sign-in method.");
      else await identity.refetch();
    } catch {
      setError("The service is unavailable.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <section aria-labelledby="account-title">
      <h2 id="account-title">Your account</h2>
      <Link to="/">Back to workspace</Link>
      <p>{session?.user.email}</p>
      {identity.isPending && <p role="status">Loading linked identity…</p>}
      {identity.isError && <p role="alert">Your linked identity could not be loaded.</p>}
      {identity.data ? (
        <>
          <p>Linked provider: {identity.data.issuer}</p>
          <button disabled={busy} onClick={() => void unlink()}>
            Unlink provider
          </button>
        </>
      ) : (
        methods.data?.oidc && (
          <>
            {!session?.user.mfaEnrolled && (
              <TextField
                label="Current password"
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            )}
            <button disabled={busy} onClick={() => void link()}>
              Link {methods.data.oidc.label}
            </button>
          </>
        )
      )}
      <FormError message={error} />
      {sensitive.prompt}
    </section>
  );
}
