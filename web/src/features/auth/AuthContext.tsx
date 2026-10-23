import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useMemo, type ReactNode } from "react";

import type { ApiClient, Session } from "../../api/client";

type Auth = {
  client: ApiClient;
  loading: boolean;
  failed: boolean;
  setupRequired: boolean;
  session: Session | null;
  /** Store a session returned by the server (login, MFA, setup). */
  signedIn: (session: Session) => void;
  signedOut: () => void;
};

const AuthContext = createContext<Auth | null>(null);

export function AuthProvider({ client, children }: { client: ApiClient; children: ReactNode }) {
  const queries = useQueryClient();
  const setup = useQuery({
    queryKey: ["setup"],
    queryFn: async () => {
      const { data, error } = await client.GET("/api/v1/setup");
      if (error !== undefined || data === undefined) throw new Error("setup status unavailable");
      return data.bootstrapRequired;
    },
  });
  const session = useQuery({
    queryKey: ["session"],
    enabled: setup.data === false,
    queryFn: async () => {
      const { data, response } = await client.GET("/api/v1/auth/session");
      if (response.status === 401) {
        client.setCsrfToken(undefined);
        return null;
      }
      if (data === undefined) throw new Error("session unavailable");
      client.setCsrfToken(data.csrfToken);
      return data;
    },
  });

  const signedIn = useCallback(
    (s: Session) => {
      client.setCsrfToken(s.csrfToken);
      queries.setQueryData(["setup"], false);
      queries.setQueryData(["session"], s);
    },
    [client, queries],
  );
  const signedOut = useCallback(() => {
    client.setCsrfToken(undefined);
    queries.setQueryData(["session"], null);
  }, [client, queries]);

  const value = useMemo<Auth>(
    () => ({
      client,
      loading: setup.isPending || (setup.data === false && session.isPending),
      failed: setup.isError || session.isError,
      setupRequired: setup.data === true,
      session: session.data ?? null,
      signedIn,
      signedOut,
    }),
    [
      client,
      setup.isPending,
      setup.isError,
      setup.data,
      session.isPending,
      session.isError,
      session.data,
      signedIn,
      signedOut,
    ],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): Auth {
  const auth = useContext(AuthContext);
  if (!auth) throw new Error("useAuth outside AuthProvider");
  return auth;
}
