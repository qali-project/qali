import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { problemCode } from "../../api/client";
import { FormError, TextField } from "../../components/TextField";
import { useAuth } from "../auth/AuthContext";
import { adminMessage } from "./workspace";

const schema = z.object({ code: z.string().regex(/^[0-9]{6}$/, "Enter the 6-digit code.") });

type Props = {
  /** Called after the server recorded recent MFA; retries the action. */
  onVerified: () => void;
  onCancel: () => void;
};

/**
 * Asks for a fresh authenticator code before a sensitive action
 * (ADR-0013). The server rotates the session, so the new CSRF token is
 * stored before the action is retried.
 */
export function StepUp({ onVerified, onCancel }: Props) {
  const { client, signedIn } = useAuth();
  const [error, setError] = useState<string>();
  const form = useForm<z.infer<typeof schema>>({ resolver: zodResolver(schema) });
  useEffect(() => {
    form.setFocus("code");
  }, [form]);
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { data, error: problem } = await client.POST("/api/v1/auth/mfa/step-up", {
      body: values,
    });
    if (!data) return setError(adminMessage(problemCode(problem)));
    signedIn(data);
    onVerified();
  });
  return (
    <section aria-labelledby="step-up-title" className="panel">
      <h3 id="step-up-title">Confirm it is you</h3>
      <p>This change needs a current code from your authenticator app.</p>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Authenticator code"
          inputMode="numeric"
          autoComplete="one-time-code"
          error={form.formState.errors.code?.message}
          {...form.register("code")}
        />
        <FormError message={error} />
        <div className="actions">
          <button type="submit" disabled={form.formState.isSubmitting}>
            Confirm
          </button>
          <button type="button" className="secondary" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </section>
  );
}

/**
 * Runs actions that may need step-up. An action returns its problem code,
 * or undefined on success; recent_mfa_required opens the step-up prompt and
 * retries the action once verified.
 */
export function useSensitive(onError: (message: string | undefined) => void) {
  const [retry, setRetry] = useState<(() => Promise<string | undefined>) | null>(null);
  const run = async (action: () => Promise<string | undefined>) => {
    onError(undefined);
    const code = await action();
    if (code === "recent_mfa_required") {
      setRetry(() => action);
      return;
    }
    if (code) onError(adminMessage(code));
  };
  const prompt = retry ? (
    <StepUp
      onCancel={() => setRetry(null)}
      onVerified={() => {
        const action = retry;
        setRetry(null);
        void run(action);
      }}
    />
  ) : null;
  return { run, prompt };
}
