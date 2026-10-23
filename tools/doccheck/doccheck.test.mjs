// Behavioral tests for the documentation and decision-record checker.
// Every test builds a small repository fixture and asserts the reported errors.

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { checkRepository, renderPermissionMatrix } from "./doccheck.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const baseCatalog = () => ({
  version: 1,
  conditions: {
    all: "Any resource the principal can access.",
    own: "Resources created by the principal.",
    assigned: "Resources assigned to the principal.",
  },
  permissions: [
    { id: "projects.read", kind: "read", scope: "project", administrative: false, sensitive: false, ownerOnly: false, description: "Read projects." },
    { id: "projects.update", kind: "write", scope: "project", administrative: true, sensitive: false, ownerOnly: false, description: "Update project settings." },
    { id: "workspace.transfer_ownership", kind: "write", scope: "workspace", administrative: true, sensitive: true, ownerOnly: true, description: "Transfer ownership." },
  ],
  roles: [
    { id: "owner", name: "Owner", grants: { "projects.read": "all", "projects.update": "all", "workspace.transfer_ownership": "all" } },
    { id: "workspace_admin", name: "Workspace Administrator", grants: { "projects.read": "all", "projects.update": "all" } },
    { id: "qa_lead", name: "QA Lead", grants: { "projects.read": "all" } },
    { id: "tester", name: "Tester", grants: { "projects.read": "all" } },
    { id: "viewer", name: "Viewer", grants: { "projects.read": "all" } },
  ],
  projectAccessLevels: [
    { id: "contributor", maxKind: "write", description: "Role grants apply." },
    { id: "viewer", maxKind: "read", description: "Read-only." },
  ],
  credentialTypes: [
    { id: "session", tokenPrefix: "qali_sess_", scopes: [] },
    { id: "ci", tokenPrefix: "qali_ci_", scopes: ["runs:create", "results:submit"] },
    { id: "mcp", tokenPrefix: "qali_mcp_", scopes: ["mcp:read"] },
  ],
});

const mvpPlan = (rows, sections) => `# MVP Execution Plan

## 4. Ordered MVP work items

| Order | ID | Status | Outcome |
|---:|---|---|---|
${rows.map(([o, id, s]) => `| ${o} | ${id} | ${s} | Outcome ${id} |`).join("\n")}

${sections.map(([id, deps]) => `### ${id} — Title of ${id}\n\nDependencies: ${deps}\n`).join("\n")}
`;

const baseFiles = () => {
  const catalog = baseCatalog();
  return {
    "README.md": "# Repo\n\nSee [plan](docs/MVP_PLAN.md#4-ordered-mvp-work-items) and `docs/MVP_PLAN.md`.\n",
    "docs/MVP_PLAN.md": mvpPlan(
      [[0, "MVP-00", "IN_PROGRESS"], [1, "MVP-01", "NOT_STARTED"]],
      [["MVP-00", "none"], ["MVP-01", "MVP-00"]],
    ),
    "docs/adr/README.md": "# ADR index\n\n- [ADR-0001](0001-first.md)\n",
    "docs/adr/0001-first.md": "# ADR-0001: First decision\n\nStatus: Accepted\n\n## Decision\n\nText.\n",
    "docs/rbac/permission-catalog.json": JSON.stringify(catalog, null, 2) + "\n",
    "docs/rbac/permission-matrix.md": renderPermissionMatrix(catalog),
    "docs/acceptance/TEMPLATE.md": "# Acceptance map template\n",
    "docs/acceptance/MVP-00.md": `# MVP-00 acceptance map

## Threats

| Threat ID | Threat |
|---|---|
| MVP-00.T-01 | Something bad |

## Criteria

| AC ID | Criterion | Threat IDs | Tests | Result |
|---|---|---|---|---|
| MVP-00.AC-01 | Criterion one | MVP-00.T-01 | \`test a\` | PASS |
| MVP-00.AC-02 | Criterion two | - | \`test b\` | PENDING |
`,
  };
};

function makeRepo(mutate = () => {}) {
  const files = baseFiles();
  mutate(files);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "doccheck-"));
  for (const [rel, content] of Object.entries(files)) {
    if (content === undefined) continue;
    const full = path.join(root, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return root;
}

function errorsFor(mutate) {
  return checkRepository(makeRepo(mutate));
}

function assertHasError(errors, pattern) {
  assert.ok(
    errors.some((e) => pattern.test(e)),
    `expected an error matching ${pattern}, got:\n${errors.join("\n") || "(none)"}`,
  );
}

function withCatalog(files, edit) {
  const catalog = JSON.parse(files["docs/rbac/permission-catalog.json"]);
  edit(catalog);
  files["docs/rbac/permission-catalog.json"] = JSON.stringify(catalog, null, 2) + "\n";
  files["docs/rbac/permission-matrix.md"] = renderPermissionMatrix(catalog);
}

test("valid fixture repository has no errors", () => {
  assert.deepEqual(errorsFor(), []);
});

test("the real repository documentation passes every check", () => {
  assert.deepEqual(checkRepository(repoRoot), []);
});

// Links

test("broken relative link is reported with its source file", () => {
  assertHasError(
    errorsFor((f) => { f["README.md"] += "\n[missing](docs/NOPE.md)\n"; }),
    /README\.md.*docs\/NOPE\.md/,
  );
});

test("broken heading anchor is reported", () => {
  assertHasError(
    errorsFor((f) => { f["README.md"] += "\n[bad](docs/MVP_PLAN.md#no-such-heading)\n"; }),
    /anchor.*no-such-heading/,
  );
});

test("same-file anchor resolves against headings with punctuation", () => {
  assert.deepEqual(
    errorsFor((f) => { f["docs/MVP_PLAN.md"] += "\nSee [item](#mvp-00--title-of-mvp-00).\n"; }),
    [],
  );
});

test("backticked docs path that does not exist is reported", () => {
  assertHasError(
    errorsFor((f) => { f["README.md"] += "\nRead `docs/GONE.md` first.\n"; }),
    /docs\/GONE\.md/,
  );
});

test("backticked placeholder paths with NN segments are patterns, not references", () => {
  assert.deepEqual(
    errorsFor((f) => { f["README.md"] += "\nCopy to `docs/acceptance/MVP-NN.md` or `docs/adr/NNNN-slug.md`.\n"; }),
    [],
  );
  assertHasError(
    errorsFor((f) => { f["README.md"] += "\nSee `docs/acceptance/MVP-07.md`.\n"; }),
    /MVP-07\.md/,
  );
});

test("links inside fenced code blocks are ignored", () => {
  assert.deepEqual(
    errorsFor((f) => { f["README.md"] += "\n```text\n[x](missing.md) `docs/GONE.md`\n```\n"; }),
    [],
  );
});

test("external links are not fetched and not reported", () => {
  assert.deepEqual(
    errorsFor((f) => { f["README.md"] += "\n[ext](https://example.invalid/x)\n"; }),
    [],
  );
});

// MVP registry

test("duplicate MVP ID in the registry is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "IN_PROGRESS"], [1, "MVP-00", "NOT_STARTED"]],
        [["MVP-00", "none"]],
      );
    }),
    /duplicate.*MVP-00/i,
  );
});

test("registry item without a section heading is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "IN_PROGRESS"], [1, "MVP-01", "NOT_STARTED"]],
        [["MVP-00", "none"]],
      );
    }),
    /MVP-01.*section/i,
  );
});

test("duplicate section heading for one MVP ID is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "IN_PROGRESS"], [1, "MVP-01", "NOT_STARTED"]],
        [["MVP-00", "none"], ["MVP-01", "MVP-00"], ["MVP-01", "MVP-00"]],
      );
    }),
    /duplicate.*MVP-01/i,
  );
});

test("more than one IN_PROGRESS item is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "IN_PROGRESS"], [1, "MVP-01", "IN_PROGRESS"]],
        [["MVP-00", "none"], ["MVP-01", "MVP-00"]],
      );
    }),
    /IN_PROGRESS/,
  );
});

test("an item advanced past an incomplete earlier item is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "NOT_STARTED"], [1, "MVP-01", "COMPLETE"]],
        [["MVP-00", "none"], ["MVP-01", "MVP-00"]],
      );
    }),
    /order/i,
  );
});

test("unknown status value is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "DONE"], [1, "MVP-01", "NOT_STARTED"]],
        [["MVP-00", "none"], ["MVP-01", "MVP-00"]],
      );
    }),
    /status.*DONE/i,
  );
});

test("dependency on a later or unknown item is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "IN_PROGRESS"], [1, "MVP-01", "NOT_STARTED"]],
        [["MVP-00", "MVP-01"], ["MVP-01", "MVP-00"]],
      );
    }),
    /MVP-00.*depend.*MVP-01/i,
  );
});

// ADRs

test("duplicate ADR number is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/adr/0001-other.md"] = "# ADR-0001: Other\n\nStatus: Accepted\n";
      f["docs/adr/README.md"] += "- [ADR-0001 other](0001-other.md)\n";
    }),
    /duplicate.*ADR-0001/i,
  );
});

test("ADR title number that differs from the file number is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/adr/0001-first.md"] = "# ADR-0002: First\n\nStatus: Accepted\n"; }),
    /0001-first\.md.*ADR-0001/,
  );
});

test("ADR without a valid status is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/adr/0001-first.md"] = "# ADR-0001: First\n\nStatus: Maybe\n"; }),
    /status/i,
  );
});

test("ADR missing from the index is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/adr/0002-second.md"] = "# ADR-0002: Second\n\nStatus: Proposed\n"; }),
    /0002-second\.md.*index/i,
  );
});

// Permission catalog

test("duplicate permission ID is reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.permissions.push({ ...c.permissions[0] }); })),
    /duplicate permission.*projects\.read/i,
  );
});

test("permission ID must be family.action in snake case", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => {
      c.permissions.push({ ...c.permissions[0], id: "Projects-Read" });
      c.roles[0].grants["Projects-Read"] = "all";
    })),
    /Projects-Read/,
  );
});

test("grant of an unknown permission is reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.roles[3].grants["runs.fly"] = "all"; })),
    /tester.*unknown permission.*runs\.fly/i,
  );
});

test("grant with an unknown condition is reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.roles[3].grants["projects.read"] = "sometimes"; })),
    /condition.*sometimes/i,
  );
});

for (const role of ["qa_lead", "tester", "viewer"]) {
  test(`${role} granted an administrative permission is reported`, () => {
    assertHasError(
      errorsFor((f) => withCatalog(f, (c) => {
        c.roles.find((r) => r.id === role).grants["projects.update"] = "all";
      })),
      new RegExp(`${role}.*administrative.*projects\\.update`),
    );
  });
}

test("owner-only permission granted to a workspace administrator is reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.roles[1].grants["workspace.transfer_ownership"] = "all"; })),
    /workspace_admin.*owner-only/i,
  );
});

test("owner lacking any catalog permission is reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { delete c.roles[0].grants["projects.update"]; })),
    /owner.*projects\.update/,
  );
});

test("missing or extra MVP role is reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.roles = c.roles.filter((r) => r.id !== "viewer"); })),
    /role.*viewer/i,
  );
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.roles.push({ id: "developer", name: "Developer", grants: {} }); })),
    /role.*developer/i,
  );
});

test("project viewer access level that allows writes is reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.projectAccessLevels[1].maxKind = "write"; })),
    /access level.*viewer.*read/i,
  );
});

test("duplicate or overlapping credential token prefixes are reported", () => {
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.credentialTypes[2].tokenPrefix = "qali_ci_"; })),
    /prefix.*qali_ci_/i,
  );
  assertHasError(
    errorsFor((f) => withCatalog(f, (c) => { c.credentialTypes[2].tokenPrefix = "qali_ci_mcp_"; })),
    /prefix/i,
  );
});

test("stale generated permission matrix is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/rbac/permission-matrix.md"] += "\nhand edit\n"; }),
    /permission-matrix\.md.*stale/i,
  );
});

test("generated matrix shows conditions and denials per role", () => {
  const catalog = baseCatalog();
  catalog.roles[3].grants["projects.read"] = "assigned";
  const matrix = renderPermissionMatrix(catalog);
  const row = matrix.split("\n").find((l) => l.startsWith("| `projects.update`"));
  assert.equal(row, "| `projects.update` | write | yes | all | all | - | - | - |");
  const readRow = matrix.split("\n").find((l) => l.startsWith("| `projects.read`"));
  assert.match(readRow, /\| all \| all \| all \| assigned \| all \|$/);
});

// Acceptance maps

test("duplicate acceptance criterion ID is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/acceptance/MVP-00.md"] += "| MVP-00.AC-01 | Again | - | `t` | PASS |\n"; }),
    /duplicate.*MVP-00\.AC-01/i,
  );
});

test("criterion ID for another item is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/acceptance/MVP-00.md"] += "| MVP-01.AC-01 | Wrong | - | `t` | PASS |\n"; }),
    /MVP-01\.AC-01/,
  );
});

test("reference to an undefined threat is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/acceptance/MVP-00.md"] += "| MVP-00.AC-03 | X | MVP-00.T-09 | `t` | PASS |\n"; }),
    /MVP-00\.T-09/,
  );
});

test("unknown result value is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/acceptance/MVP-00.md"] += "| MVP-00.AC-03 | X | - | `t` | OK |\n"; }),
    /result.*OK/i,
  );
});

test("criterion without a named test is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/acceptance/MVP-00.md"] += "| MVP-00.AC-03 | X | - |  | PENDING |\n"; }),
    /MVP-00\.AC-03.*test/i,
  );
});

test("acceptance map for an unknown item is reported", () => {
  assertHasError(
    errorsFor((f) => { f["docs/acceptance/MVP-99.md"] = "# MVP-99 acceptance map\n"; }),
    /MVP-99/,
  );
});

test("COMPLETE item whose acceptance map is not all PASS is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "COMPLETE"], [1, "MVP-01", "NOT_STARTED"]],
        [["MVP-00", "none"], ["MVP-01", "MVP-00"]],
      );
    }),
    /MVP-00.*COMPLETE.*MVP-00\.AC-02/,
  );
});

test("COMPLETE item without an acceptance map is reported", () => {
  assertHasError(
    errorsFor((f) => {
      f["docs/MVP_PLAN.md"] = mvpPlan(
        [[0, "MVP-00", "COMPLETE"], [1, "MVP-01", "IN_PROGRESS"]],
        [["MVP-00", "none"], ["MVP-01", "MVP-00"]],
      );
      f["docs/acceptance/MVP-00.md"] = undefined;
    }),
    /MVP-00.*acceptance map/i,
  );
});

test("required decision files are reported when missing", () => {
  assertHasError(
    errorsFor((f) => { f["docs/rbac/permission-catalog.json"] = undefined; }),
    /permission-catalog\.json/,
  );
});
