import { zodResolver } from "@hookform/resolvers/zod";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useLocation, useNavigate } from "react-router";
import { z } from "zod";

import { problemCode } from "../../api/client";
import { usePageTitle } from "../../app/title";
import { FormError, TextField } from "../../components/TextField";
import { useAuth } from "../auth/AuthContext";
import { destination } from "../auth/destination";
import { adminMessage, rememberWorkspace, roleLabels } from "./workspace";

const accountSchema = z.object({
  displayName: z.string().trim().min(1, "Enter your name.").max(200),
  password: z
    .string()
    .min(12, "Use at least 12 characters.")
    .max(256, "Use at most 256 characters."),
});

/**
 * Accepts an invitation link. The one-time token is in the URL fragment
 * (/invite#qali_inv_...), which is never sent to the server in requests or
 * Referer headers; it is posted explicitly instead.
 */
export function InvitePage() {
  usePageTitle("Accept invitation");
  const { client, session } = useAuth();
  const token = useLocation().hash.replace(/^#/, "");
  const preview = useQuery({
    queryKey: ["invitation", token],
    enabled: token !== "",
    queryFn: async () => {
      const { data, error } = await client.POST("/api/v1/invitations/preview", { body: { token } });
      if (data) return { ok: true as const, invitation: data };
      return { ok: false as const, message: adminMessage(problemCode(error)) };
    },
  });

  if (token === "") return <InvalidInvitation message={adminMessage("invitation_invalid")} />;
  if (preview.isPending) return <p role="status">Checking invitation…</p>;
  if (preview.isError)
    return <p role="alert">The invitation could not be checked. Try again later.</p>;
  if (!preview.data.ok) return <InvalidInvitation message={preview.data.message} />;
  const inv = preview.data.invitation;
  return (
    <section aria-labelledby="invite-title">
      <h2 id="invite-title">Join {inv.workspaceName}</h2>
      <p>
        You were invited as <strong>{roleLabels[inv.role]}</strong> with the email{" "}
        <strong>{inv.email}</strong>.
      </p>
      {session?.state === "active" ? (
        <AcceptWithAccount token={token} />
      ) : (
        <CreateAccount token={token} email={inv.email} />
      )}
    </section>
  );
}

function InvalidInvitation({ message }: { message: string }) {
  return (
    <section aria-labelledby="invalid-invite-title">
      <h2 id="invalid-invite-title">Invitation not valid</h2>
      <p role="alert">{message}</p>
      <Link to="/">Go to the home page</Link>
    </section>
  );
}

function CreateAccount({ token, email }: { token: string; email: string }) {
  const { client, signedIn } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string>();
  const form = useForm<z.infer<typeof accountSchema>>({ resolver: zodResolver(accountSchema) });
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { data, error: problem } = await client.POST("/api/v1/invitations/accept", {
      body: { token, ...values },
    });
    if (!data) return setError(adminMessage(problemCode(problem)));
    signedIn(data);
    void navigate(destination(false, data), { replace: true });
  });
  const e = form.formState.errors;
  return (
    <>
      <h3>Create your account</h3>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField label="Email" type="email" autoComplete="username" readOnly value={email} />
        <TextField
          label="Your name"
          autoComplete="name"
          error={e.displayName?.message}
          {...form.register("displayName")}
        />
        <TextField
          label="Password"
          type="password"
          autoComplete="new-password"
          hint="At least 12 characters."
          error={e.password?.message}
          {...form.register("password")}
        />
        <FormError message={error} />
        <button type="submit" disabled={form.formState.isSubmitting}>
          Create account and join
        </button>
      </form>
      <p>
        Already have an account? <Link to="/login">Sign in</Link>, then open the invitation link
        again.
      </p>
    </>
  );
}

function AcceptWithAccount({ token }: { token: string }) {
  const { client } = useAuth();
  const queries = useQueryClient();
  const navigate = useNavigate();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const accept = async () => {
    setError(undefined);
    setBusy(true);
    const { data, error: problem } = await client.POST("/api/v1/invitations/accept-existing", {
      body: { token },
    });
    setBusy(false);
    if (!data) return setError(adminMessage(problemCode(problem)));
    await queries.invalidateQueries({ queryKey: ["workspaces"] });
    rememberWorkspace(data.id);
    void navigate(`/w/${data.id}`, { replace: true });
  };
  return (
    <>
      <FormError message={error} />
      <button type="button" disabled={busy} onClick={() => void accept()}>
        Join workspace
      </button>
    </>
  );
}
