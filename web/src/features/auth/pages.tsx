import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useNavigate } from "react-router";
import { z } from "zod";

import { problemCode, type Session } from "../../api/client";
import { usePageTitle } from "../../app/title";
import { FormError, TextField } from "../../components/TextField";
import { useAuth } from "./AuthContext";
import { destination, messageFor } from "./destination";

const email = z.string().trim().email("Enter a valid email address.").max(254);
const newPassword = z
  .string()
  .min(12, "Use at least 12 characters.")
  .max(256, "Use at most 256 characters.");
const code = z.string().regex(/^[0-9]{6}$/, "Enter the 6-digit code.");

const setupSchema = z.object({
  setupToken: z.string().trim().min(1, "Enter the setup token from the server."),
  email,
  displayName: z.string().trim().min(1, "Enter your name.").max(200),
  workspaceName: z.string().trim().min(1, "Enter a workspace name.").max(120),
  password: newPassword,
});

export function SetupPage() {
  usePageTitle("Set up Qali");
  const { client, signedIn } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string>();
  const form = useForm<z.infer<typeof setupSchema>>({ resolver: zodResolver(setupSchema) });
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { data, error: problem } = await client.POST("/api/v1/setup/owner", { body: values });
    if (!data) return setError(messageFor(problemCode(problem)));
    signedIn(data);
    void navigate(destination(false, data));
  });
  const e = form.formState.errors;
  return (
    <section aria-labelledby="setup-title">
      <h2 id="setup-title">Create the owner account</h2>
      <p>This account owns the installation. You will set up two-factor authentication next.</p>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Setup token"
          autoComplete="off"
          hint="Run “qali setup-token” on the server (for example with docker compose exec) and paste the token it prints. It works once, for one hour."
          error={e.setupToken?.message}
          {...form.register("setupToken")}
        />
        <TextField
          label="Email"
          type="email"
          autoComplete="username"
          error={e.email?.message}
          {...form.register("email")}
        />
        <TextField
          label="Your name"
          autoComplete="name"
          error={e.displayName?.message}
          {...form.register("displayName")}
        />
        <TextField
          label="Workspace name"
          error={e.workspaceName?.message}
          {...form.register("workspaceName")}
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
          Create owner account
        </button>
      </form>
    </section>
  );
}

const loginSchema = z.object({
  email: z.string().trim().min(1, "Enter your email."),
  password: z.string().min(1, "Enter your password."),
});

export function LoginPage() {
  usePageTitle("Sign in");
  const { client, signedIn } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string>();
  const form = useForm<z.infer<typeof loginSchema>>({ resolver: zodResolver(loginSchema) });
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { data, error: problem } = await client.POST("/api/v1/auth/login", { body: values });
    if (!data) return setError(messageFor(problemCode(problem)));
    signedIn(data);
    void navigate(destination(false, data));
  });
  const e = form.formState.errors;
  return (
    <section aria-labelledby="login-title">
      <h2 id="login-title">Sign in</h2>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Email"
          type="email"
          autoComplete="username"
          error={e.email?.message}
          {...form.register("email")}
        />
        <TextField
          label="Password"
          type="password"
          autoComplete="current-password"
          error={e.password?.message}
          {...form.register("password")}
        />
        <FormError message={error} />
        <button type="submit" disabled={form.formState.isSubmitting}>
          Sign in
        </button>
      </form>
      <p>
        <Link to="/recover">Use a recovery code</Link>
      </p>
    </section>
  );
}

const codeSchema = z.object({ code });

export function ChallengePage() {
  usePageTitle("Two-factor authentication");
  const { client, signedIn } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string>();
  const form = useForm<z.infer<typeof codeSchema>>({ resolver: zodResolver(codeSchema) });
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { data, error: problem } = await client.POST("/api/v1/auth/mfa/challenge", {
      body: values,
    });
    if (!data) return setError(messageFor(problemCode(problem)));
    signedIn(data);
    void navigate("/");
  });
  return (
    <section aria-labelledby="challenge-title">
      <h2 id="challenge-title">Enter your authentication code</h2>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Authentication code"
          inputMode="numeric"
          autoComplete="one-time-code"
          error={form.formState.errors.code?.message}
          {...form.register("code")}
        />
        <FormError message={error} />
        <button type="submit" disabled={form.formState.isSubmitting}>
          Verify
        </button>
      </form>
      <SignOutButton />
    </section>
  );
}

export function EnrollPage() {
  usePageTitle("Set up two-factor authentication");
  const { client, signedIn } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string>();
  const [enrollment, setEnrollment] = useState<{ secret: string; otpauthUri: string }>();
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>();
  const [activated, setActivated] = useState<Session>();
  const form = useForm<z.infer<typeof codeSchema>>({ resolver: zodResolver(codeSchema) });

  const begin = async () => {
    setError(undefined);
    const { data, error: problem } = await client.POST("/api/v1/auth/mfa/totp/enrollment");
    if (!data) return setError(messageFor(problemCode(problem)));
    setEnrollment(data);
  };
  const confirm = form.handleSubmit(async (values) => {
    setError(undefined);
    const { data, error: problem } = await client.POST("/api/v1/auth/mfa/totp/enrollment/confirm", {
      body: values,
    });
    if (!data) return setError(messageFor(problemCode(problem)));
    // The rotated session is already active server-side; the app switches to
    // it after the user confirms the codes are saved.
    client.setCsrfToken(data.session.csrfToken);
    setActivated(data.session);
    setRecoveryCodes(data.recoveryCodes);
  });

  if (recoveryCodes) {
    return (
      <section aria-labelledby="codes-title">
        <h2 id="codes-title">Save your recovery codes</h2>
        <p>
          Each code works once if you lose your authenticator. Store them somewhere safe; they will
          not be shown again.
        </p>
        <ol className="codes" aria-label="Recovery codes">
          {recoveryCodes.map((c) => (
            <li key={c}>
              <code>{c}</code>
            </li>
          ))}
        </ol>
        <button
          type="button"
          onClick={() => {
            if (activated) signedIn(activated);
            void navigate("/");
          }}
        >
          I saved my recovery codes
        </button>
      </section>
    );
  }

  return (
    <section aria-labelledby="enroll-title">
      <h2 id="enroll-title">Set up two-factor authentication</h2>
      <p>Owners and administrators must use an authenticator app.</p>
      {!enrollment ? (
        <button type="button" onClick={() => void begin()}>
          Set up authenticator app
        </button>
      ) : (
        <>
          <p>Add this key to your authenticator app, then enter the code it shows.</p>
          <p>
            Setup key: <code data-testid="totp-secret">{enrollment.secret}</code>
          </p>
          <p>
            <a href={enrollment.otpauthUri}>Open in authenticator app</a>
          </p>
          <form onSubmit={(ev) => void confirm(ev)} noValidate>
            <TextField
              label="Authentication code"
              inputMode="numeric"
              autoComplete="one-time-code"
              error={form.formState.errors.code?.message}
              {...form.register("code")}
            />
            <button type="submit" disabled={form.formState.isSubmitting}>
              Confirm
            </button>
          </form>
        </>
      )}
      <FormError message={error} />
      <SignOutButton />
    </section>
  );
}

const recoverSchema = z.object({
  email,
  recoveryCode: z
    .string()
    .trim()
    .min(16, "Enter a recovery code such as ABCD-EFGH-IJKL-MNOP.")
    .max(32),
  newPassword,
});

export function RecoverPage() {
  usePageTitle("Recover your account");
  const { client } = useAuth();
  const [error, setError] = useState<string>();
  const [done, setDone] = useState(false);
  const form = useForm<z.infer<typeof recoverSchema>>({ resolver: zodResolver(recoverSchema) });
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { response, error: problem } = await client.POST("/api/v1/auth/recovery", {
      body: values,
    });
    if (response.status !== 204) return setError(messageFor(problemCode(problem)));
    setDone(true);
  });
  const e = form.formState.errors;
  if (done) {
    return (
      <section aria-labelledby="recovered-title">
        <h2 id="recovered-title">Password changed</h2>
        <p role="status">Your password was reset and all sessions were signed out.</p>
        <Link to="/login">Sign in</Link>
      </section>
    );
  }
  return (
    <section aria-labelledby="recover-title">
      <h2 id="recover-title">Recover your account</h2>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Email"
          type="email"
          autoComplete="username"
          error={e.email?.message}
          {...form.register("email")}
        />
        <TextField
          label="Recovery code"
          autoComplete="off"
          error={e.recoveryCode?.message}
          {...form.register("recoveryCode")}
        />
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          hint="At least 12 characters."
          error={e.newPassword?.message}
          {...form.register("newPassword")}
        />
        <FormError message={error} />
        <button type="submit" disabled={form.formState.isSubmitting}>
          Reset password
        </button>
      </form>
      <Link to="/login">Back to sign in</Link>
    </section>
  );
}

const resetSchema = z.object({
  token: z.string().trim().min(1, "Enter the reset token."),
  newPassword,
});

export function ResetPasswordPage() {
  usePageTitle("Reset password");
  const { client } = useAuth();
  const [error, setError] = useState<string>();
  const [done, setDone] = useState(false);
  // The token is typed or pasted, never read from the URL: a query string
  // would keep a bearer credential in history and proxy logs (REVIEW-005).
  const form = useForm<z.infer<typeof resetSchema>>({ resolver: zodResolver(resetSchema) });
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { response, error: problem } = await client.POST("/api/v1/auth/password-reset", {
      body: values,
    });
    if (response.status !== 204) return setError(messageFor(problemCode(problem)));
    setDone(true);
  });
  const e = form.formState.errors;
  if (done) {
    return (
      <section aria-labelledby="reset-done-title">
        <h2 id="reset-done-title">Password changed</h2>
        <p role="status">Your password was reset and all sessions were signed out.</p>
        <Link to="/login">Sign in</Link>
      </section>
    );
  }
  return (
    <section aria-labelledby="reset-title">
      <h2 id="reset-title">Reset your password</h2>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Reset token"
          autoComplete="off"
          error={e.token?.message}
          {...form.register("token")}
        />
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          error={e.newPassword?.message}
          {...form.register("newPassword")}
        />
        <FormError message={error} />
        <button type="submit" disabled={form.formState.isSubmitting}>
          Set new password
        </button>
      </form>
    </section>
  );
}

export function SignOutButton({ everywhere = false }: { everywhere?: boolean }) {
  const { client, signedOut } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState<string>();
  const signOut = async () => {
    const { response, error: problem } = everywhere
      ? await client.POST("/api/v1/auth/logout-all")
      : await client.POST("/api/v1/auth/logout");
    if (response.status !== 204) return setError(messageFor(problemCode(problem)));
    signedOut();
    void navigate("/login");
  };
  return (
    <>
      <button type="button" className="secondary" onClick={() => void signOut()}>
        {everywhere ? "Sign out of all devices" : "Sign out"}
      </button>
      <FormError message={error} />
    </>
  );
}
