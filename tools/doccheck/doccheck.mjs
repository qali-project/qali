// Documentation and decision-record checker.
//
// Verifies relative links and anchors, the MVP work-item registry, ADR
// numbering, the machine-readable permission catalog and its generated matrix,
// and acceptance maps. Dependency-free so it runs before the application
// toolchain exists.
//
// Usage:
//   node tools/doccheck/doccheck.mjs check [root]
//   node tools/doccheck/doccheck.mjs generate [root]

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PLAN = "docs/MVP_PLAN.md";
const ADR_DIR = "docs/adr";
const ADR_INDEX = "docs/adr/README.md";
const CATALOG = "docs/rbac/permission-catalog.json";
const MATRIX = "docs/rbac/permission-matrix.md";
const ACCEPTANCE_DIR = "docs/acceptance";
const ACCEPTANCE_TEMPLATE = "docs/acceptance/TEMPLATE.md";

const REQUIRED_FILES = [PLAN, ADR_INDEX, CATALOG, MATRIX, ACCEPTANCE_TEMPLATE];
const SKIPPED_DIRS = new Set([".git", "node_modules", "dist", "build", "coverage"]);

const MVP_STATUSES = ["COMPLETE", "IN_PROGRESS", "NOT_STARTED"];
const ADR_STATUS = /^(Proposed|Accepted|Deprecated|Superseded by ADR-(\d{4}))$/;
const MVP_ROLES = ["owner", "workspace_admin", "qa_lead", "tester", "viewer"];
const NON_ADMIN_ROLES = ["qa_lead", "tester", "viewer"];
const RESULTS = ["PASS", "FAIL", "PENDING", "N/A"];

export function checkRepository(root) {
  const errors = [];
  const report = (file, message) => errors.push(`${file}: ${message}`);

  for (const rel of REQUIRED_FILES) {
    if (!exists(root, rel)) report(rel, "required file is missing");
  }

  const docs = listMarkdown(root).map((rel) => ({ rel, ...parseMarkdown(read(root, rel)) }));
  const headingCache = new Map(docs.map((d) => [d.rel, d.anchors]));
  checkLinks(root, docs, headingCache, report);

  const registry = exists(root, PLAN) ? checkPlan(read(root, PLAN), report) : new Map();
  if (exists(root, ADR_INDEX)) checkAdrs(root, report);
  if (exists(root, CATALOG)) checkCatalogFiles(root, report);
  checkAcceptanceMaps(root, registry, report);

  return errors;
}

// ---------------------------------------------------------------------------
// Markdown parsing

function listMarkdown(root, dir = "") {
  const out = [];
  for (const entry of fs.readdirSync(path.join(root, dir), { withFileTypes: true })) {
    const rel = dir ? `${dir}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      if (!SKIPPED_DIRS.has(entry.name)) out.push(...listMarkdown(root, rel));
    } else if (entry.name.endsWith(".md")) {
      out.push(rel);
    }
  }
  return out.sort();
}

// Returns prose lines (fenced code removed) and GitHub-style heading anchors.
function parseMarkdown(text) {
  const lines = [];
  const anchors = new Set();
  const seen = new Map();
  let fence = null;
  for (const raw of text.replace(/\r\n/g, "\n").split("\n")) {
    const marker = raw.match(/^\s*(`{3,}|~{3,})/);
    if (marker) {
      if (fence === null) fence = marker[1][0];
      else if (marker[1][0] === fence) fence = null;
      continue;
    }
    if (fence !== null) continue;
    lines.push(raw);
    const heading = raw.match(/^#{1,6}\s+(.*?)\s*#*\s*$/);
    if (heading) {
      const base = slugify(heading[1]);
      const count = seen.get(base) ?? 0;
      seen.set(base, count + 1);
      anchors.add(count === 0 ? base : `${base}-${count}`);
    }
  }
  return { lines, anchors };
}

function slugify(heading) {
  return heading
    .replace(/\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/[`*]/g, "")
    .toLowerCase()
    .replace(/[^\p{L}\p{N} _-]/gu, "")
    .replace(/ /g, "-");
}

// ---------------------------------------------------------------------------
// Links

function checkLinks(root, docs, headingCache, report) {
  for (const doc of docs) {
    for (const line of doc.lines) {
      const codeSpans = [...line.matchAll(/`([^`]+)`/g)].map((m) => m[1]);
      for (const span of codeSpans) {
        const isPlaceholder = /\bN{2,}\b/.test(span); // e.g. MVP-NN, NNNN-slug
        if (/^docs\/[\w./-]+\.(md|json)$/.test(span) && !isPlaceholder && !exists(root, span)) {
          report(doc.rel, `references missing file \`${span}\``);
        }
      }
      const prose = line.replace(/`[^`]*`/g, "");
      for (const m of prose.matchAll(/\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)/g)) {
        checkLink(root, doc.rel, m[1], headingCache, report);
      }
    }
  }
}

function checkLink(root, from, target, headingCache, report) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return; // external: not fetched, see ADR-0010
  const [filePart, anchor] = target.split("#", 2);
  const rel = filePart
    ? path.posix.normalize(path.posix.join(path.posix.dirname(from), decodeURI(filePart)))
    : from;
  if (rel.startsWith("..") || !exists(root, rel)) {
    report(from, `broken link to ${target}`);
    return;
  }
  if (anchor === undefined || anchor === "") return;
  if (!rel.endsWith(".md")) return;
  let anchors = headingCache.get(rel);
  if (!anchors) {
    anchors = parseMarkdown(read(root, rel)).anchors;
    headingCache.set(rel, anchors);
  }
  if (!anchors.has(anchor.toLowerCase())) {
    report(from, `broken anchor #${anchor} in link to ${target}`);
  }
}

// ---------------------------------------------------------------------------
// MVP registry

function checkPlan(text, report) {
  const { lines } = parseMarkdown(text);
  const rows = [];
  for (const line of lines) {
    const m = line.match(/^\|\s*(\d+)\s*\|\s*(MVP-\d{2})\s*\|\s*([A-Za-z_]+)\s*\|/);
    if (m) rows.push({ order: Number(m[1]), id: m[2], status: m[3] });
  }
  if (rows.length === 0) report(PLAN, "work-item registry table not found");

  const registry = new Map();
  rows.forEach((row, index) => {
    if (registry.has(row.id)) report(PLAN, `duplicate registry ID ${row.id}`);
    else registry.set(row.id, { ...row, index });
    if (row.order !== index) report(PLAN, `${row.id} has order ${row.order}, expected ${index}`);
    if (!MVP_STATUSES.includes(row.status)) report(PLAN, `${row.id} has unknown status ${row.status}`);
  });

  if (rows.filter((r) => r.status === "IN_PROGRESS").length > 1) {
    report(PLAN, "more than one item is IN_PROGRESS");
  }
  let rank = 0;
  for (const row of rows) {
    const r = MVP_STATUSES.indexOf(row.status);
    if (r < 0) continue;
    if (r < rank || (r === 1 && rank === 1)) {
      report(PLAN, `${row.id} is ${row.status} out of order; items advance strictly top to bottom`);
    }
    rank = Math.max(rank, r === 1 ? 2 : r);
  }

  // Sections: exactly one "### MVP-xx — Title" per registry ID, with dependencies.
  const sections = new Map();
  let current = null;
  for (const line of lines) {
    const heading = line.match(/^###\s+(MVP-\d{2})\b/);
    if (heading) {
      current = heading[1];
      if (sections.has(current)) report(PLAN, `duplicate section heading for ${current}`);
      sections.set(current, []);
      continue;
    }
    if (/^#{1,3}\s/.test(line)) current = null;
    const deps = current && line.match(/^Dependencies:\s*(.*)$/);
    if (deps) sections.set(current, [...deps[1].matchAll(/MVP-\d{2}/g)].map((m) => m[0]));
  }
  for (const id of registry.keys()) {
    if (!sections.has(id)) report(PLAN, `${id} has no section heading`);
  }
  for (const [id, deps] of sections) {
    const item = registry.get(id);
    if (!item) {
      report(PLAN, `section ${id} is not in the registry`);
      continue;
    }
    for (const dep of deps) {
      const target = registry.get(dep);
      if (!target || target.index >= item.index) {
        report(PLAN, `${id} depends on ${dep}, which is not an earlier registry item`);
      }
    }
  }
  return registry;
}

// ---------------------------------------------------------------------------
// ADRs

function checkAdrs(root, report) {
  const index = read(root, ADR_INDEX);
  const files = fs.readdirSync(path.join(root, ADR_DIR)).filter((f) => /^\d{4}-.*\.md$/.test(f)).sort();
  const numbers = new Map();
  for (const file of files) {
    const rel = `${ADR_DIR}/${file}`;
    const number = file.slice(0, 4);
    if (!/^\d{4}-[a-z0-9-]+\.md$/.test(file)) report(rel, "ADR file name must be NNNN-lowercase-slug.md");
    if (numbers.has(number)) report(rel, `duplicate ADR number ADR-${number} (also ${numbers.get(number)})`);
    else numbers.set(number, file);

    const text = read(root, rel);
    const title = text.match(/^# ADR-(\d{4}): \S.*$/m);
    if (!title || title[1] !== number) report(rel, `title must be "# ADR-${number}: <title>"`);
    const status = text.match(/^Status:\s*(.*?)\s*$/m);
    const valid = status && status[1].match(ADR_STATUS);
    if (!valid) report(rel, `missing or invalid Status line (${status ? status[1] : "none"})`);
    else if (valid[2] && !files.some((f) => f.startsWith(`${valid[2]}-`))) {
      report(rel, `superseded by unknown ADR-${valid[2]}`);
    }
    if (!index.includes(`](${file})`)) report(rel, `is not listed in the ADR index ${ADR_INDEX}`);
  }
}

// ---------------------------------------------------------------------------
// Permission catalog

function checkCatalogFiles(root, report) {
  let catalog;
  try {
    catalog = JSON.parse(read(root, CATALOG));
  } catch (err) {
    report(CATALOG, `invalid JSON: ${err.message}`);
    return;
  }
  for (const message of validateCatalog(catalog)) report(CATALOG, message);
  const expected = renderPermissionMatrix(catalog);
  if (!exists(root, MATRIX) || read(root, MATRIX).replace(/\r\n/g, "\n") !== expected) {
    report(MATRIX, "is stale; run `make docs-generate`");
  }
}

export function validateCatalog(catalog) {
  const errors = [];
  const conditions = Object.keys(catalog.conditions ?? {});
  const permissions = new Map();

  for (const p of catalog.permissions ?? []) {
    if (permissions.has(p.id)) errors.push(`duplicate permission ${p.id}`);
    permissions.set(p.id, p);
    if (!/^[a-z][a-z_]*\.[a-z][a-z_]*$/.test(p.id)) errors.push(`permission ${p.id} must be family.action in snake_case`);
    if (!["read", "write"].includes(p.kind)) errors.push(`permission ${p.id} has invalid kind ${p.kind}`);
    if (!["workspace", "project"].includes(p.scope)) errors.push(`permission ${p.id} has invalid scope ${p.scope}`);
    for (const flag of ["administrative", "sensitive", "ownerOnly"]) {
      if (typeof p[flag] !== "boolean") errors.push(`permission ${p.id} must set boolean ${flag}`);
    }
    if (!p.description) errors.push(`permission ${p.id} needs a description`);
  }

  const roleIds = (catalog.roles ?? []).map((r) => r.id);
  for (const id of MVP_ROLES) if (!roleIds.includes(id)) errors.push(`missing MVP role ${id}`);
  for (const id of roleIds) if (!MVP_ROLES.includes(id)) errors.push(`role ${id} is not an MVP role`);
  if (new Set(roleIds).size !== roleIds.length) errors.push("duplicate role ID");

  for (const role of catalog.roles ?? []) {
    for (const [pid, condition] of Object.entries(role.grants ?? {})) {
      const p = permissions.get(pid);
      if (!p) {
        errors.push(`role ${role.id} grants unknown permission ${pid}`);
        continue;
      }
      if (!conditions.includes(condition)) errors.push(`role ${role.id} grants ${pid} with unknown condition ${condition}`);
      if (p.ownerOnly && role.id !== "owner") errors.push(`role ${role.id} must not hold owner-only permission ${pid}`);
      if (p.administrative && NON_ADMIN_ROLES.includes(role.id)) {
        errors.push(`role ${role.id} must not hold administrative permission ${pid}`);
      }
      if (role.id === "viewer" && p.kind !== "read") errors.push(`role viewer must not hold write permission ${pid}`);
    }
  }
  const owner = (catalog.roles ?? []).find((r) => r.id === "owner");
  if (owner) {
    for (const pid of permissions.keys()) {
      if (owner.grants?.[pid] !== "all") errors.push(`role owner must hold ${pid} with condition all`);
    }
  }

  const levels = catalog.projectAccessLevels ?? [];
  if (new Set(levels.map((l) => l.id)).size !== levels.length) errors.push("duplicate project access level");
  for (const level of levels) {
    if (!["read", "write"].includes(level.maxKind)) errors.push(`access level ${level.id} has invalid maxKind`);
  }
  const viewerLevel = levels.find((l) => l.id === "viewer");
  if (!viewerLevel || viewerLevel.maxKind !== "read") errors.push("project access level viewer must exist with maxKind read");

  const creds = catalog.credentialTypes ?? [];
  if (new Set(creds.map((c) => c.id)).size !== creds.length) errors.push("duplicate credential type");
  for (const c of creds) {
    if (!/^qali_[a-z]+_$/.test(c.tokenPrefix)) errors.push(`credential ${c.id} has malformed prefix ${c.tokenPrefix}`);
    for (const other of creds) {
      if (other !== c && other.tokenPrefix.startsWith(c.tokenPrefix)) {
        errors.push(`credential prefix ${c.tokenPrefix} (${c.id}) is ambiguous with ${other.tokenPrefix} (${other.id})`);
      }
    }
    const scopes = c.scopes ?? [];
    if (new Set(scopes).size !== scopes.length) errors.push(`credential ${c.id} has duplicate scopes`);
    for (const s of scopes) if (!/^[a-z_]+:[a-z_]+$/.test(s)) errors.push(`credential ${c.id} has malformed scope ${s}`);
  }
  return errors;
}

export function renderPermissionMatrix(catalog) {
  const roles = catalog.roles;
  const out = [
    "# Permission matrix",
    "",
    "<!-- Generated from permission-catalog.json by `make docs-generate`. Do not edit. -->",
    "",
    `Generated from [the permission catalog](permission-catalog.json), version ${catalog.version}.`,
    "Cells show the grant condition; `-` means denied. Project-scoped permissions",
    "also require project access, capped by the project access level.",
    "",
    "Conditions:",
    "",
    ...Object.entries(catalog.conditions).map(([id, text]) => `- \`${id}\`: ${text}`),
    "",
    "## Role grants",
    "",
    `| Permission | Kind | Admin | ${roles.map((r) => r.name).join(" | ")} |`,
    `|---|---|---|${roles.map(() => "---").join("|")}|`,
    ...catalog.permissions.map((p) =>
      `| \`${p.id}\` | ${p.kind} | ${p.administrative ? "yes" : "no"} | ${roles.map((r) => r.grants[p.id] ?? "-").join(" | ")} |`,
    ),
    "",
    "## Sensitive and owner-only permissions",
    "",
    ...catalog.permissions
      .filter((p) => p.sensitive || p.ownerOnly)
      .map((p) => `- \`${p.id}\`${p.ownerOnly ? " (owner-only)" : ""}${p.sensitive ? " (recent MFA, high-severity audit)" : ""}`),
    "",
    "## Project access levels",
    "",
    "| Level | Maximum kind | Description |",
    "|---|---|---|",
    ...catalog.projectAccessLevels.map((l) => `| \`${l.id}\` | ${l.maxKind} | ${l.description} |`),
    "",
    "## Credential types",
    "",
    "| Type | Token prefix | Scopes |",
    "|---|---|---|",
    ...catalog.credentialTypes.map((c) =>
      `| \`${c.id}\` | \`${c.tokenPrefix}\` | ${c.scopes.length ? c.scopes.map((s) => `\`${s}\``).join(", ") : "-"} |`,
    ),
    "",
  ];
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// Acceptance maps

function checkAcceptanceMaps(root, registry, report) {
  const maps = new Map();
  if (exists(root, ACCEPTANCE_DIR)) {
    for (const file of fs.readdirSync(path.join(root, ACCEPTANCE_DIR)).sort()) {
      const m = file.match(/^(MVP-\d{2})\.md$/);
      if (!m) continue;
      const rel = `${ACCEPTANCE_DIR}/${file}`;
      if (!registry.has(m[1])) report(rel, `acceptance map for unknown item ${m[1]}`);
      maps.set(m[1], checkAcceptanceMap(m[1], rel, read(root, rel), report));
    }
  }
  for (const [id, item] of registry) {
    if (item.status !== "COMPLETE") continue;
    const criteria = maps.get(id);
    if (!criteria) {
      report(PLAN, `${id} is COMPLETE but has no acceptance map`);
      continue;
    }
    for (const c of criteria) {
      if (c.result !== "PASS" && c.result !== "N/A") {
        report(PLAN, `${id} is COMPLETE but ${c.id} is ${c.result}`);
      }
    }
  }
}

function checkAcceptanceMap(item, rel, text, report) {
  const threats = new Set();
  const criteria = [];
  const seen = new Set();
  for (const line of parseMarkdown(text).lines) {
    if (!line.startsWith("|")) continue;
    const cells = line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim());
    const id = cells[0].match(/^(MVP-\d{2})\.(AC|T)-\d{2}$/);
    if (!id) continue;
    if (id[1] !== item) report(rel, `${cells[0]} does not belong to ${item}`);
    if (seen.has(cells[0])) report(rel, `duplicate ID ${cells[0]}`);
    seen.add(cells[0]);
    if (id[2] === "T") {
      threats.add(cells[0]);
      continue;
    }
    const [, , threatCell = "", tests = "", result = ""] = cells;
    criteria.push({ id: cells[0], threatCell, tests, result });
  }
  for (const c of criteria) {
    for (const t of c.threatCell.split(",").map((s) => s.trim()).filter((s) => s && s !== "-")) {
      if (!threats.has(t)) report(rel, `${c.id} references undefined threat ${t}`);
    }
    if (!c.tests || c.tests === "-") report(rel, `${c.id} names no test`);
    if (!RESULTS.includes(c.result)) report(rel, `${c.id} has unknown result ${c.result}`);
  }
  return criteria;
}

// ---------------------------------------------------------------------------

function exists(root, rel) {
  return fs.existsSync(path.join(root, rel));
}

function read(root, rel) {
  return fs.readFileSync(path.join(root, rel), "utf8");
}

function main([command = "check", root = "."]) {
  if (command === "generate") {
    const catalog = JSON.parse(read(root, CATALOG));
    fs.writeFileSync(path.join(root, MATRIX), renderPermissionMatrix(catalog));
    console.log(`wrote ${MATRIX}`);
    return 0;
  }
  if (command !== "check") {
    console.error(`unknown command ${command}; use check or generate`);
    return 2;
  }
  const errors = checkRepository(root);
  for (const e of errors) console.error(e);
  console.log(errors.length ? `doccheck: ${errors.length} error(s)` : "doccheck: OK");
  return errors.length ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
