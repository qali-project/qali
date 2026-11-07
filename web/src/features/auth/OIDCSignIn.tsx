import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { FormError } from "../../components/TextField";
import { useAuth } from "./AuthContext";

export function useAuthMethods() {
  const { client } = useAuth();
  return useQuery({
    queryKey: ["auth-methods"],
    queryFn: async () => {
      const { data } = await client.GET("/api/v1/auth/methods");
      if (!data) throw new Error("Sign-in methods unavailable");
      return data;
    },
  });
}

export function OIDCSignIn({ invitationToken }: { invitationToken?: string }) {
  const { client } = useAuth();
  const methods = useAuthMethods();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const start = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const { data } = await client.POST("/api/v1/auth/oidc/start", {
        body: invitationToken ? { purpose: "invitation", invitationToken } : { purpose: "login" },
      });
      if (data) window.location.assign(data.authorizationUrl);
      else setError("Provider sign-in is unavailable. Try again later.");
    } catch {
      setError("Provider sign-in is unavailable. Try again later.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      {methods.isPending && <p role="status">Loading sign-in methods…</p>}
      {methods.isError && <p role="alert">Sign-in methods could not be loaded.</p>}
      {methods.data?.oidc && (
        <button type="button" disabled={busy} onClick={() => void start()}>
          Continue with {methods.data.oidc.label}
        </button>
      )}
      {methods.data?.localLogin === false && (
        <p>
          {invitationToken
            ? "Accept this invitation with your identity provider."
            : "Password sign-in is available only to Owners for emergency access, with an authenticator code."}
        </p>
      )}
      <FormError message={error} />
    </>
  );
}
