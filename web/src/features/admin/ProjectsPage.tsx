import { zodResolver } from "@hookform/resolvers/zod";
import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { useForm } from "react-hook-form";
import { Link, useParams } from "react-router";
import { z } from "zod";

import { problemCode } from "../../api/client";
import { usePageTitle } from "../../app/title";
import { FormError, TextField } from "../../components/TextField";
import { useAuth } from "../auth/AuthContext";
import { useMemberList } from "./MembersPage";
import { NotPermitted, WorkspaceState } from "./NotPermitted";
import {
  adminMessage,
  can,
  ifMatch,
  inWorkspace,
  levelLabels,
  useWorkspace,
  type AccessLevel,
  type Project,
  type ProjectList,
  type ProjectMember,
  type Workspace,
} from "./workspace";

const levels = Object.keys(levelLabels) as AccessLevel[];

/** Projects visible to the caller; administrators can create projects. */
export function ProjectsPage() {
  usePageTitle("Projects");
  const ws = useWorkspace();
  if (ws.isPending || ws.isError || !ws.data) return <WorkspaceState query={ws} />;
  return (
    <section aria-labelledby="projects-title">
      <h2 id="projects-title">Projects</h2>
      <ProjectList ws={ws.data} />
      {can(ws.data, "projects.create") && <CreateProject ws={ws.data} />}
    </section>
  );
}

function ProjectList({ ws }: { ws: Workspace }) {
  const { client } = useAuth();
  const projects = useInfiniteQuery({
    queryKey: ["projects", ws.id],
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last: ProjectList) => last.nextCursor ?? undefined,
    queryFn: async ({ pageParam }) => {
      const { data, error } = await client.GET("/api/v1/workspaces/{workspaceId}/projects", {
        params: { path: { workspaceId: ws.id }, query: { cursor: pageParam } },
      });
      if (error !== undefined || data === undefined) throw new Error("projects unavailable");
      return data;
    },
  });
  if (projects.isPending) return <p role="status">Loading projects…</p>;
  if (projects.isError) return <p role="alert">Projects could not be loaded. Try again later.</p>;
  const rows = projects.data.pages.flatMap((p) => p.items);
  if (rows.length === 0) return <p>No projects yet.</p>;
  return (
    <>
      <ul className="plain">
        {rows.map((p) => (
          <li key={p.id}>
            <strong>{p.code}</strong> {p.name} ·{" "}
            {p.visibility === "public" ? "Public" : "Restricted"}
            {can(p, "projects.manage_access") && (
              <>
                {" "}
                ·{" "}
                <Link to={inWorkspace(ws, `/projects/${p.id}/access`)}>
                  Manage access to {p.code}
                </Link>
              </>
            )}
          </li>
        ))}
      </ul>
      {projects.hasNextPage && (
        <button
          type="button"
          className="secondary"
          disabled={projects.isFetchingNextPage}
          onClick={() => void projects.fetchNextPage()}
        >
          Show more projects
        </button>
      )}
    </>
  );
}

const projectSchema = z.object({
  code: z
    .string()
    .trim()
    .regex(/^[A-Z][A-Z0-9]{1,9}$/, "Use 2-10 uppercase letters or digits, starting with a letter."),
  name: z.string().trim().min(1, "Enter a project name.").max(120),
  visibility: z.enum(["public", "restricted"]),
});

function CreateProject({ ws }: { ws: Workspace }) {
  const { client } = useAuth();
  const queries = useQueryClient();
  const visibilityId = useId();
  const [error, setError] = useState<string>();
  const form = useForm<z.infer<typeof projectSchema>>({
    resolver: zodResolver(projectSchema),
    defaultValues: { visibility: "restricted" },
  });
  const onSubmit = form.handleSubmit(async (values) => {
    setError(undefined);
    const { data, error: problem } = await client.POST(
      "/api/v1/workspaces/{workspaceId}/projects",
      { params: { path: { workspaceId: ws.id } }, body: values },
    );
    if (!data) return setError(adminMessage(problemCode(problem)));
    form.reset({ code: "", name: "", visibility: "restricted" });
    await queries.invalidateQueries({ queryKey: ["projects", ws.id] });
  });
  const e = form.formState.errors;
  return (
    <section aria-labelledby="create-project-title">
      <h3 id="create-project-title">Create a project</h3>
      <form onSubmit={(ev) => void onSubmit(ev)} noValidate>
        <TextField
          label="Code"
          hint="2-10 uppercase letters or digits, for example WEB."
          autoComplete="off"
          error={e.code?.message}
          {...form.register("code")}
        />
        <TextField
          label="Name"
          autoComplete="off"
          error={e.name?.message}
          {...form.register("name")}
        />
        <div className="field">
          <label htmlFor={visibilityId}>Visibility</label>
          <select id={visibilityId} {...form.register("visibility")}>
            <option value="restricted">Restricted: direct members only</option>
            <option value="public">Public: every workspace member</option>
          </select>
        </div>
        <FormError message={error} />
        <button type="submit" disabled={form.formState.isSubmitting}>
          Create project
        </button>
      </form>
    </section>
  );
}

/** Direct project members and their access levels (projects.manage_access). */
export function ProjectAccessPage() {
  usePageTitle("Project access");
  const { projectId = "" } = useParams();
  const { client } = useAuth();
  const ws = useWorkspace();
  const project = useQuery({
    queryKey: ["project", ws.data?.id, projectId],
    enabled: !!ws.data,
    queryFn: async (): Promise<Project | null> => {
      const { data, response } = await client.GET(
        "/api/v1/workspaces/{workspaceId}/projects/{projectId}",
        { params: { path: { workspaceId: ws.data!.id, projectId } } },
      );
      if (response.status === 404 || response.status === 400) return null;
      if (data === undefined) throw new Error("project unavailable");
      return data;
    },
  });
  if (ws.isPending || ws.isError || !ws.data) return <WorkspaceState query={ws} />;
  if (project.isPending) return <p role="status">Loading project…</p>;
  if (project.isError) return <p role="alert">The project could not be loaded. Try again later.</p>;
  if (!project.data) {
    return (
      <section aria-labelledby="no-project-title">
        <h2 id="no-project-title">Project not found</h2>
        <p>It does not exist or you cannot access it.</p>
        <Link to={inWorkspace(ws.data, "/projects")}>Back to projects</Link>
      </section>
    );
  }
  if (!can(project.data, "projects.manage_access")) return <NotPermitted />;
  return (
    <section aria-labelledby="access-title">
      <h2 id="access-title">
        Access to {project.data.code} {project.data.name}
      </h2>
      <p>
        {project.data.visibility === "public"
          ? "Every workspace member can see this public project. Direct members get the level set here."
          : "Only Owners and the direct members below can see this restricted project."}{" "}
        A level never grants more than the member's workspace role.
      </p>
      <ProjectMembers ws={ws.data} project={project.data} />
      <Link to={inWorkspace(ws.data, "/projects")}>Back to projects</Link>
    </section>
  );
}

function ProjectMembers({ ws, project }: { ws: Workspace; project: Project }) {
  const { client } = useAuth();
  const queries = useQueryClient();
  const userId = useId();
  const levelId = useId();
  const [error, setError] = useState<string>();
  const key = ["project-members", ws.id, project.id];
  const path = { workspaceId: ws.id, projectId: project.id };
  const members = useQuery({
    queryKey: key,
    queryFn: async () => {
      const { data, error } = await client.GET(
        "/api/v1/workspaces/{workspaceId}/projects/{projectId}/members",
        { params: { path, query: { limit: 200 } } },
      );
      if (error !== undefined || data === undefined) throw new Error("project members unavailable");
      return data.items;
    },
  });
  const candidates = useMemberList(ws);
  const [pick, setPick] = useState<{ userId: string; level: AccessLevel }>({
    userId: "",
    level: "contributor",
  });
  const done = async (problem: unknown, ok: boolean) => {
    if (!ok) setError(adminMessage(problemCode(problem)));
    await queries.invalidateQueries({ queryKey: key });
  };
  const add = async () => {
    setError(undefined);
    if (!pick.userId) return setError("Choose a member to add.");
    const { data, error: problem } = await client.POST(
      "/api/v1/workspaces/{workspaceId}/projects/{projectId}/members",
      { params: { path }, body: pick },
    );
    await done(problem, data !== undefined);
  };
  const change = async (m: ProjectMember, level: AccessLevel) => {
    setError(undefined);
    const { data, error: problem } = await client.PATCH(
      "/api/v1/workspaces/{workspaceId}/projects/{projectId}/members/{userId}",
      {
        params: { path: { ...path, userId: m.userId }, header: { "If-Match": ifMatch(m.version) } },
        body: { level },
      },
    );
    await done(problem, data !== undefined);
  };
  const remove = async (m: ProjectMember) => {
    setError(undefined);
    const { response, error: problem } = await client.DELETE(
      "/api/v1/workspaces/{workspaceId}/projects/{projectId}/members/{userId}",
      {
        params: { path: { ...path, userId: m.userId }, header: { "If-Match": ifMatch(m.version) } },
      },
    );
    await done(problem, response.status === 204);
  };

  const direct = new Set(members.data?.map((m) => m.userId));
  const addable = candidates.data?.filter((m) => !direct.has(m.userId)) ?? [];
  return (
    <>
      <FormError message={error} />
      {members.isPending && <p role="status">Loading members…</p>}
      {members.isError && <p role="alert">Project members could not be loaded.</p>}
      {members.data?.length === 0 && <p>No direct members.</p>}
      {members.data && members.data.length > 0 && (
        <ul className="plain">
          {members.data.map((m) => (
            <li key={m.userId}>
              {m.displayName} ({m.email}){" "}
              <select
                aria-label={`Access level for ${m.displayName}`}
                value={m.level}
                onChange={(e) => void change(m, e.target.value as AccessLevel)}
              >
                {levels.map((l) => (
                  <option key={l} value={l}>
                    {levelLabels[l]}
                  </option>
                ))}
              </select>{" "}
              <button
                type="button"
                className="secondary"
                aria-label={`Remove ${m.displayName}`}
                onClick={() => void remove(m)}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      )}
      <h3>Add a member</h3>
      <div className="field">
        <label htmlFor={userId}>Member</label>
        <select
          id={userId}
          value={pick.userId}
          onChange={(e) => setPick({ ...pick, userId: e.target.value })}
        >
          <option value="">Choose a member</option>
          {addable.map((m) => (
            <option key={m.userId} value={m.userId}>
              {m.displayName} ({m.email})
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor={levelId}>Access level</label>
        <select
          id={levelId}
          value={pick.level}
          onChange={(e) => setPick({ ...pick, level: e.target.value as AccessLevel })}
        >
          {levels.map((l) => (
            <option key={l} value={l}>
              {levelLabels[l]}
            </option>
          ))}
        </select>
      </div>
      <button type="button" onClick={() => void add()}>
        Add to project
      </button>
    </>
  );
}
