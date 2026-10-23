import { Link } from "react-router";

import { usePageTitle } from "../../app/title";
import type { WorkspaceResult } from "./workspace";

/** Shown on direct navigation to a page the caller's role cannot use. */
export function NotPermitted() {
  usePageTitle("Not permitted");
  return (
    <section aria-labelledby="not-permitted-title">
      <h2 id="not-permitted-title">You do not have access to this page</h2>
      <p>
        Your role in this workspace does not include this area. Ask a workspace owner if you need
        it.
      </p>
      <Link to="/">Go to the home page</Link>
    </section>
  );
}

/** Loading, error, and no-workspace states of the workspace query. */
export function WorkspaceState({ query }: { query: WorkspaceResult }) {
  if (query.isPending) return <p role="status">Loading…</p>;
  if (query.isError)
    return <p role="alert">Your workspace could not be loaded. Try again later.</p>;
  return (
    <section aria-labelledby="no-workspace-title">
      <h2 id="no-workspace-title">Workspace not found</h2>
      <p>It does not exist or you are not an active member of it.</p>
      <Link to="/">Go to the home page</Link>
    </section>
  );
}

export function NotFound() {
  usePageTitle("Page not found");
  return (
    <section aria-labelledby="not-found-title">
      <h2 id="not-found-title">Page not found</h2>
      <Link to="/">Go to the home page</Link>
    </section>
  );
}
