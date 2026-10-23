import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { useEffect, useId, useState, type ReactNode } from "react";
import {
  BrowserRouter,
  MemoryRouter,
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router";

import type { ApiClient } from "./api/client";
import { PRODUCT_NAME } from "./app/product";
import { usePageTitle } from "./app/title";
import { AuthProvider, useAuth } from "./features/auth/AuthContext";
import { allowedPath, destination } from "./features/auth/destination";
import {
  ChallengePage,
  EnrollPage,
  LoginPage,
  RecoverPage,
  ResetPasswordPage,
  SetupPage,
  SignOutButton,
} from "./features/auth/pages";
import { InvitePage } from "./features/admin/InvitePage";
import { MembersPage } from "./features/admin/MembersPage";
import { ProjectAccessPage, ProjectsPage } from "./features/admin/ProjectsPage";
import { NotFound, WorkspaceState } from "./features/admin/NotPermitted";
import {
  canAdminister,
  inWorkspace,
  preferredWorkspace,
  rememberWorkspace,
  useWorkspace,
  useWorkspaces,
  type Workspace,
} from "./features/admin/workspace";

type AppProps = {
  client: ApiClient;
  /** Tests render with an in-memory history starting here. */
  initialPath?: string;
};

export function App({ client, initialPath }: AppProps) {
  const [queryClient] = useState(
    () => new QueryClient({ defaultOptions: { queries: { retry: false } } }),
  );
  const routes = (
    <AuthProvider client={client}>
      <Layout>
        <Gate />
      </Layout>
    </AuthProvider>
  );
  return (
    <QueryClientProvider client={queryClient}>
      {initialPath ? (
        <MemoryRouter initialEntries={[initialPath]}>{routes}</MemoryRouter>
      ) : (
        <BrowserRouter>{routes}</BrowserRouter>
      )}
    </QueryClientProvider>
  );
}

function Layout({ children }: { children: ReactNode }) {
  return (
    <>
      <header>
        <h1>{PRODUCT_NAME}</h1>
        <MainNav />
      </header>
      <main>{children}</main>
    </>
  );
}

/**
 * Navigation for active sessions, bound to the workspace in the URL;
 * administration only for roles that hold it.
 */
function MainNav() {
  const { session } = useAuth();
  const ws = useWorkspace();
  if (session?.state !== "active" || !ws.data) return null;
  return (
    <nav aria-label="Main">
      <WorkspacePicker current={ws.data} />
      <NavLink to={inWorkspace(ws.data)} end>
        Home
      </NavLink>
      <NavLink to={inWorkspace(ws.data, "/projects")}>Projects</NavLink>
      {canAdminister(ws.data) && (
        <NavLink to={inWorkspace(ws.data, "/admin/members")}>Members</NavLink>
      )}
    </nav>
  );
}

/** Switches the workspace explicitly (REVIEW-006). */
function WorkspacePicker({ current }: { current: Workspace }) {
  const list = useWorkspaces();
  const navigate = useNavigate();
  const id = useId();
  return (
    <span className="field-inline">
      <label htmlFor={id}>Workspace</label>
      <select
        id={id}
        value={current.id}
        onChange={(e) => {
          rememberWorkspace(e.target.value);
          void navigate(`/w/${e.target.value}`);
        }}
      >
        {(list.data ?? [current]).map((w) => (
          <option key={w.id} value={w.id}>
            {w.name}
          </option>
        ))}
      </select>
    </span>
  );
}

/**
 * Opens a workspace-less path (/, /projects, ...) in the remembered or first
 * workspace, so links and bookmarks keep working.
 */
function InPreferredWorkspace({ path = "" }: { path?: string }) {
  const list = useWorkspaces();
  if (list.isPending) return <p role="status">Loading…</p>;
  if (list.isError)
    return <p role="alert">Your workspaces could not be loaded. Try again later.</p>;
  const ws = preferredWorkspace(list.data);
  if (!ws) return <HomePage />;
  return <Navigate to={inWorkspace(ws, path)} replace />;
}

/** Sends visitors to the page their setup and session state require. */
function Gate() {
  const { loading, failed, setupRequired, session } = useAuth();
  const { pathname } = useLocation();
  if (loading) {
    return <p role="status">Loading…</p>;
  }
  if (failed) {
    return <p role="alert">The service is unavailable. Try again later.</p>;
  }
  if (!allowedPath(pathname, setupRequired, session)) {
    return <Navigate to={destination(setupRequired, session)} replace />;
  }
  return (
    <Routes>
      <Route path="/setup" element={<SetupPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/recover" element={<RecoverPage />} />
      <Route path="/reset-password" element={<ResetPasswordPage />} />
      <Route path="/mfa/enroll" element={<EnrollPage />} />
      <Route path="/mfa/challenge" element={<ChallengePage />} />
      <Route path="/invite" element={<InvitePage />} />
      <Route path="/w/:workspaceId" element={<WorkspaceHome />} />
      <Route path="/w/:workspaceId/projects" element={<ProjectsPage />} />
      <Route path="/w/:workspaceId/projects/:projectId/access" element={<ProjectAccessPage />} />
      <Route path="/w/:workspaceId/admin/members" element={<MembersPage />} />
      <Route path="/projects" element={<InPreferredWorkspace path="/projects" />} />
      <Route path="/admin/members" element={<InPreferredWorkspace path="/admin/members" />} />
      <Route path="/" element={<InPreferredWorkspace />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

/** Home of one workspace; remembers it for workspace-less links. */
function WorkspaceHome() {
  const ws = useWorkspace();
  useEffect(() => {
    if (ws.data) rememberWorkspace(ws.data.id);
  }, [ws.data]);
  if (ws.isPending || ws.isError || !ws.data) return <WorkspaceState query={ws} />;
  return <HomePage workspace={ws.data} />;
}

function HomePage({ workspace }: { workspace?: Workspace }) {
  const { session } = useAuth();
  usePageTitle("Home");
  return (
    <section aria-labelledby="home-title">
      <h2 id="home-title">{workspace ? workspace.name : "Welcome"}</h2>
      {!workspace && (
        <p>You are not an active member of any workspace. Ask an owner for an invitation.</p>
      )}
      {session && (
        <p>
          Signed in as <strong>{session.user.displayName}</strong> ({session.user.email})
        </p>
      )}
      <ServiceStatus />
      <div className="actions">
        <SignOutButton />
        <SignOutButton everywhere />
      </div>
    </section>
  );
}

function ServiceStatus() {
  const { client } = useAuth();
  const liveness = useQuery({
    queryKey: ["health", "live"],
    queryFn: async () => {
      const { data, error, response } = await client.GET("/health/live");
      if (error !== undefined || data === undefined) {
        throw new Error(`liveness request failed with HTTP ${response.status}`);
      }
      return data;
    },
  });
  if (liveness.isError) {
    return <p role="alert">Service status is unavailable.</p>;
  }
  return (
    <p role="status">
      {liveness.isPending ? "Checking service status…" : `Service status: ${liveness.data.status}`}
    </p>
  );
}
