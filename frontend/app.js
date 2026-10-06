/* ==========================================================================
   VULNEX dashboard — vanilla SPA (hash router + fetch). No build step, no CDN.
   ========================================================================== */
"use strict";

const API = "/api";
// Set by the GitHub Pages build (vulnex export); null for the live API.
const STATIC = window.VULNEX_STATIC || null;
// The exported showcase has no backend, so it is always the read-only tier.
const STATIC_ROLE = (STATIC && STATIC.role) || null;
const EDITOR_KEY_STORAGE = "vulnex.editorKey";

const state = {
  stats: null,
  methodology: null,
  page: {},          // per-route pagination
  scanTimer: null,
  role: STATIC ? "viewer" : null,   // "viewer" | "editor"
  roleInfo: null,
};

/* ------------------------------- utilities ------------------------------- */
const $ = (sel, root = document) => root.querySelector(sel);

function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtNum(n) {
  return (n ?? 0).toLocaleString("en-US");
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function relTime(iso) {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (isNaN(then)) return iso;
  const diff = Math.round((Date.now() - then) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

const SEVERITIES = ["critical", "high", "medium", "low", "none", "unknown"];
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
const SEV_COLORS = {
  critical: "#ff4d6d", high: "#ff8f3d", medium: "#ffcb45",
  low: "#4dd2ff", none: "#7c8db5", unknown: "#5f7291",
};
const STATUS_COLORS = {
  affected: "#ff4d6d", patched: "#34d399", false_positive: "#7c8db5", unconfirmed: "#ffcb45",
};
const STATUS_LABELS = {
  affected: "Affected", patched: "Already Patched",
  false_positive: "False Positive", unconfirmed: "Needs Review",
};

function sevBadge(sev) {
  const s = (sev || "unknown").toLowerCase();
  return `<span class="badge sev-${esc(s)}"><span class="bdot"></span>${esc(s)}</span>`;
}

function statusBadge(st) {
  const s = (st || "").toLowerCase();
  return `<span class="badge st-${esc(s)}">${esc(STATUS_LABELS[s] || s)}</span>`;
}

function confBar(c) {
  const pct = Math.round((c ?? 0) * 100);
  return `<div class="conf"><div class="track"><div class="fill" style="width:${pct}%"></div></div><span class="pct">${pct}%</span></div>`;
}

function corrChips(list) {
  if (!list || !list.length) return '<span class="muted small">none</span>';
  return list.map((s) => `<span class="chip">${esc(s)}</span>`).join(" ");
}

function extLink(url, label) {
  if (!url) return "—";
  const text = label || url.replace(/^https?:\/\//, "").slice(0, 42);
  return `<a class="link" href="${esc(url)}" target="_blank" rel="noopener">${esc(text)}</a>`;
}

function blobUrl(specPath, branch) {
  const repo = state.stats?.repository;
  if (!repo || !specPath) return "";
  return `https://github.com/${repo.owner}/${repo.repo}/blob/${branch || ""}/${specPath}`;
}

/* ------------------------------ access tiers -----------------------------
   Viewers get the read-only showcase; editors can queue work and comment.
   The editor key never leaves the browser except as an X-VULNEX-Key header.
   ------------------------------------------------------------------------ */
function storedEditorKey() {
  try { return localStorage.getItem(EDITOR_KEY_STORAGE) || ""; } catch (_) { return ""; }
}

function setStoredEditorKey(key) {
  try {
    if (key) localStorage.setItem(EDITOR_KEY_STORAGE, key);
    else localStorage.removeItem(EDITOR_KEY_STORAGE);
  } catch (_) { /* storage unavailable: unlock still works for this session */ }
}

function isEditor() { return state.role === "editor"; }

function requireEditor() {
  if (isEditor()) return true;
  toast("Read-only view — assigning and triage comments need editor access.", true);
  return false;
}

async function resolveRole() {
  if (STATIC) {
    state.role = STATIC_ROLE === "editor" ? "editor" : "viewer";
    state.roleInfo = { role: state.role, write_enabled: state.role === "editor", key_required: true };
  } else {
    try {
      state.roleInfo = await api("/role");
      state.role = state.roleInfo.role === "editor" ? "editor" : "viewer";
    } catch (_) {
      state.role = "viewer";
      state.roleInfo = { role: "viewer", write_enabled: false, key_required: true };
    }
  }
  renderRoleChip();
}

function renderRoleChip() {
  const chip = $("#role-chip");
  if (!chip) return;
  const editor = isEditor();
  chip.hidden = false;
  chip.className = "role-chip " + (editor ? "editor" : "viewer");
  chip.textContent = editor ? "Editor mode" : "Read-only view";
  chip.title = editor
    ? "You can assign CVEs and leave triage comments. Click to lock."
    : "Visitors browse everything and change nothing. Click to enter an editor key.";
  const scanBtn = $("#scan-now");
  if (scanBtn) {
    scanBtn.disabled = !editor;
    scanBtn.title = editor ? "" : "Read-only view — running a scan needs editor access";
  }
}

async function api(path, opts = {}) {
  if (STATIC) return staticApi(path, opts);
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const key = storedEditorKey();
  if (key) headers["X-VULNEX-Key"] = key;
  const res = await fetch(API + path, {
    ...opts,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) {
    state.role = "viewer";
    renderRoleChip();
    throw new Error("Read-only view — that action needs editor access.");
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

/* ------------------- static snapshot data layer (Pages) ------------------ */
let STATIC_BUNDLE = null;

async function staticBundle() {
  if (STATIC_BUNDLE) return STATIC_BUNDLE;
  const base = STATIC.base || "./";
  const get = async (name) => {
    const res = await fetch(base + "api/" + name);
    if (!res.ok) throw new Error(`Static snapshot is missing ${name}`);
    return res.json();
  };
  const [stats, methodology, findings, packages, patches, scans] = await Promise.all([
    get("stats.json"), get("methodology.json"), get("findings.json"),
    get("packages.json"), get("patches.json"), get("scans.json"),
  ]);
  const counts = {};
  for (const f of findings) {
    const k = `${f.branch}\u0000${f.spec_path}`;
    if (!counts[k]) counts[k] = {};
    counts[k][f.status] = (counts[k][f.status] || 0) + 1;
  }
  STATIC_BUNDLE = {
    stats, methodology, findings, patches, scans,
    packages: packages.map((p) => ({
      ...p, finding_counts: counts[`${p.branch}\u0000${p.spec_path}`] || {},
    })),
  };
  return STATIC_BUNDLE;
}

function sevRank(s) { return SEV_ORDER[s] ?? 5; }

function paginate(items, limit, pageNo) {
  const p = Number(pageNo || 1) || 1;
  const l = Number(limit || 50) || 50;
  return { items: items.slice((p - 1) * l, p * l), total: items.length, page: p, limit: l };
}

async function staticApi(path, opts = {}) {
  if (opts.method && opts.method !== "GET") {
    throw new Error("Static snapshot: scanning and assignment are disabled here. Run `vulnex serve` locally for the live dashboard.");
  }
  const b = await staticBundle();
  const [pathPart, queryPart] = String(path).split("?");
  const q = Object.fromEntries(new URLSearchParams(queryPart || ""));
  const parts = pathPart.split("/").filter(Boolean);

  if (parts[0] === "stats") return b.stats;
  if (parts[0] === "methodology") return b.methodology;
  if (parts[0] === "assignments") return { items: [] };
  if (parts[0] === "scans") return { items: b.scans.items };
  if (parts[0] === "scan" && parts[1] === "status") {
    return { manager: b.scans.manager, latest_scan: b.scans.latest };
  }

  if (parts[0] === "findings") {
    let items = b.findings;
    if (q.status) items = items.filter((f) => f.status === q.status);
    if (q.severity) items = items.filter((f) => f.severity === q.severity);
    if (q.package) items = items.filter((f) => f.package_name === q.package);
    if (q.branch) items = items.filter((f) => f.branch === q.branch);
    if (q.search) {
      const s = q.search.toLowerCase();
      items = items.filter((f) =>
        (f.cve_id || "").toLowerCase().includes(s) ||
        (f.package_name || "").toLowerCase().includes(s) ||
        (f.description || "").toLowerCase().includes(s) ||
        (f.advisory_id || "").toLowerCase().includes(s));
    }
    items = [...items].sort((a, z) =>
      sevRank(a.severity) - sevRank(z.severity) ||
      (z.confidence || 0) - (a.confidence || 0) ||
      (a.cve_id || "").localeCompare(z.cve_id || ""));
    return paginate(items, q.limit, q.page);
  }

  if (parts[0] === "packages" && parts.length === 1) {
    let items = b.packages;
    if (q.search) {
      const s = q.search.toLowerCase();
      items = items.filter((p) => (p.name || "").toLowerCase().includes(s));
    }
    if (q.branch) items = items.filter((p) => p.branch === q.branch);
    items = [...items].sort((a, z) =>
      (a.name || "").localeCompare(z.name || "") ||
      (a.version || "").localeCompare(z.version || ""));
    return paginate(items, q.limit, q.page);
  }

  if (parts[0] === "packages" && parts.length === 2) {
    const name = decodeURIComponent(parts[1]);
    const byName = b.packages.filter((p) => p.name === name);
    let row;
    if (q.spec && q.branch) row = byName.find((p) => p.spec_path === q.spec && p.branch === q.branch);
    else if (q.spec) row = byName.filter((p) => p.spec_path === q.spec)[0];
    else if (q.branch) row = byName.filter((p) => p.branch === q.branch)[0];
    else row = byName[0];
    if (!row) throw new Error("Package not found in this snapshot");
    return {
      ...row,
      patches: b.patches.filter((p) => p.branch === row.branch && p.spec_path === row.spec_path),
      findings: b.findings.filter((f) => f.branch === row.branch && f.spec_path === row.spec_path),
      variants: byName
        .slice()
        .sort((a, z) => (z.is_primary || 0) - (a.is_primary || 0) || (a.branch || "").localeCompare(z.branch || ""))
        .map((p) => ({ branch: p.branch, spec_path: p.spec_path, version: p.version, release: p.release, evr: p.evr, is_primary: p.is_primary })),
    };
  }

  if (parts[0] === "cves" && parts.length === 2) {
    const id = decodeURIComponent(parts[1]).toUpperCase();
    const findings = b.findings.filter((f) => (f.cve_id || "").toUpperCase() === id);
    if (!findings.length) throw new Error("CVE not found in this snapshot");
    return { cve_id: id, findings, enrichment: null, assignment: null };
  }

  throw new Error(`Static snapshot: unsupported endpoint ${path}`);
}

function toast(message, isError = false) {
  const el = $("#toast");
  el.textContent = message;
  el.className = "toast" + (isError ? " error" : "");
  el.hidden = false;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => { el.hidden = true; }, 4200);
}

function qs(obj) {
  const p = new URLSearchParams();
  Object.entries(obj).forEach(([k, v]) => { if (v !== "" && v != null) p.set(k, v); });
  return p.toString();
}

/* -------------------------------- router --------------------------------- */
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [pathPart, queryPart] = raw.split("?");
  const parts = pathPart.split("/").filter(Boolean);
  const query = Object.fromEntries(new URLSearchParams(queryPart || ""));
  return { parts, query, key: parts[0] || "dashboard" };
}

const TITLES = {
  dashboard: ["Dashboard", "Azure Linux vulnerability posture"],
  affected: ["Affected Packages", "Confirmed exposures with no distro backport"],
  patched: ["Already Patched", "CVEs addressed by Azure Linux backport patches"],
  cves: ["All CVEs", "Every finding from the latest scan"],
  packages: ["Packages", "Every RPM spec collected from the repository"],
  package: ["Package detail", "RPM spec, sources, patches and verified CVEs"],
  cve: ["CVE detail", "Verification, provenance and patch automation"],
  assignments: ["Patch Automation Queue", "CVEs assigned for AI patch remediation"],
  scan: ["Scan Control", "Run a live scan against the Azure Linux repository"],
  project: ["Project", "The build, the engineering log and how to reach me"],
  about: ["Methodology", "How VULNEX detects and verifies vulnerabilities"],
};

async function render() {
  const route = parseHash();
  const name = route.key;
  const [title, sub] = TITLES[name] || TITLES.dashboard;
  $("#page-title").textContent = title;
  $("#page-sub").textContent = sub;
  document.querySelectorAll("#nav a").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === name ||
      (name === "cve" && a.dataset.route === "cves") ||
      (name === "package" && a.dataset.route === "packages"));
  });
  $("#sidebar")?.classList.remove("open");

  const view = $("#view");
  view.innerHTML = `<div class="loading"><div class="spinner"></div>Loading…</div>`;
  try {
    if (name === "dashboard") await renderDashboard(view, route);
    else if (name === "affected") await renderFindings(view, route, "affected");
    else if (name === "patched") await renderFindings(view, route, "patched");
    else if (name === "cves") await renderFindings(view, route, "");
    else if (name === "cve") await renderCveDetail(view, route.parts[1]);
    else if (name === "packages") await renderPackages(view, route);
    else if (name === "package") await renderPackageDetail(view, route.parts[1], route.query.branch, route.query.spec);
    else if (name === "assignments") await renderAssignments(view);
    else if (name === "scan") await renderScan(view);
    else if (name === "project") await renderProject(view);
    else if (name === "about") await renderAbout(view);
    else { location.hash = "#/"; }
  } catch (err) {
    view.innerHTML = `<div class="card error-box"><h2>Could not load this view</h2><p class="muted">${esc(err.message)}</p>
      <p class="muted small">If the dashboard is empty, run a scan from the Sync panel (\`vulnex scan\`) or click Scan Now.</p></div>`;
  }
}

/* ------------------------------ dashboard -------------------------------- */
async function renderDashboard(view, route) {
  const [stats, top] = await Promise.all([
    api("/stats"),
    api("/findings?" + qs({ status: "affected", limit: 8 })),
  ]);
  state.stats = stats;
  updateChrome();

  const sev = stats.severity || {};
  const last = stats.last_scan || {};
  const kpis = [
    ["info", "Packages scanned", fmtNum(stats.total_packages), `${(stats.last_scan?.branches || "").split(",").length || 0} branch(es)`],
    ["critical", "Critical", fmtNum(sev.critical), "highest severity"],
    ["high", "High", fmtNum(sev.high), "needs triage"],
    ["medium", "Medium", fmtNum(sev.medium), "scheduled"],
    ["low", "Low", fmtNum(sev.low), "informational"],
    ["patched", "Already patched", fmtNum(stats.patched), `${fmtNum(stats.total_patches)} patches parsed`],
    ["info", "Needs review", fmtNum(stats.unconfirmed), "unconfirmed findings"],
    ["info", "Total findings", fmtNum(stats.total_findings), `${fmtNum(stats.distinct_cves)} distinct CVEs`],
  ];

  const donutSegments = SEVERITIES
    .map((s) => ({ label: s, value: sev[s] || 0, color: SEV_COLORS[s] }))
    .filter((x) => x.value > 0);

  const statusSegments = [
    { label: "Affected", value: stats.affected, color: STATUS_COLORS.affected },
    { label: "Patched", value: stats.patched, color: STATUS_COLORS.patched },
    { label: "False positive", value: stats.false_positive, color: STATUS_COLORS.false_positive },
    { label: "Needs review", value: stats.unconfirmed, color: STATUS_COLORS.unconfirmed },
  ].filter((x) => x.value > 0);

  view.innerHTML = `
    <div class="grid kpis">${kpis.map(kpiCard).join("")}</div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <div class="card-head"><h2>Severity distribution</h2>
          <span class="muted small">${fmtNum(stats.total_findings)} findings</span></div>
        <div class="donut-wrap">
          ${donut(donutSegments, stats.total_findings, "Findings")}
          <div class="legend">
            ${SEVERITIES.map((s) => `
              <div class="row"><span class="sw" style="background:${SEV_COLORS[s]}"></span>
              <span style="text-transform:capitalize">${s}</span>
              <span class="n">${fmtNum(sev[s] || 0)}</span></div>`).join("")}
          </div>
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Verification outcome</h2></div>
        <div class="bar-stack">
          ${statusSegments.map((s) => `
            <span title="${s.label}: ${s.value}" style="background:${s.color};flex:${s.value}"></span>`).join("")}
        </div>
        <div class="bar-legend">
          ${statusSegments.map((s) => `<span><b>${fmtNum(s.value)}</b> ${esc(s.label)}</span>`).join("")}
        </div>
        <dl class="kv" style="margin-top:18px">
          <dt>Last scan</dt><dd>${esc(fmtTime(last.finished_at))} <span class="muted small">(${esc(relTime(last.finished_at))})</span></dd>
          <dt>Branches</dt><dd class="mono">${esc(last.branches || "—")}</dd>
          <dt>Advisory source</dt><dd class="mono">${esc(last.ecosystem || "—")}</dd>
          <dt>Duration</dt><dd>${last.duration_seconds != null ? esc(last.duration_seconds) + "s" : "—"}</dd>
          <dt>Patch queue</dt><dd>${fmtNum(stats.assignments)} assigned</dd>
        </dl>
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Top affected findings</h2>
        <a class="chip link" href="#/affected">View all</a></div>
      ${top.items.length ? findingsTable(top.items) : `<div class="empty">No affected packages in the current scan. ${stats.total_findings ? "Everything found is either patched or a known non-issue." : "Run a scan to populate the dashboard."}</div>`}
    </div>
  `;
}

function kpiCard([kind, label, value, sub]) {
  return `<div class="kpi ${kind}">
    <div class="k-label">${esc(label)}</div>
    <div class="k-value">${esc(value)}</div>
    <div class="k-sub">${esc(sub)}</div>
  </div>`;
}

function donut(segments, total, centerLabel) {
  const r = 74, c = 2 * Math.PI * r;
  let offset = 0;
  const arcs = segments.map((s) => {
    const frac = total ? s.value / total : 0;
    const len = frac * c;
    const seg = `<circle cx="95" cy="95" r="${r}" fill="none" stroke="${s.color}"
      stroke-width="17" stroke-dasharray="${len} ${c - len}"
      stroke-dashoffset="${-offset}" stroke-linecap="butt">
      <title>${s.label}: ${s.value}</title></circle>`;
    offset += len;
    return seg;
  }).join("");
  return `<div class="donut">
    <svg width="190" height="190" viewBox="0 0 190 190">
      <circle cx="95" cy="95" r="${r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="17"/>
      ${arcs}
    </svg>
    <div class="center"><div class="big">${fmtNum(total)}</div><div class="lbl">${esc(centerLabel)}</div></div>
  </div>`;
}

function updateChrome() {
  const repo = state.stats?.repository;
  if (repo) {
    $("#repo-pill").textContent = `${repo.owner}/${repo.repo}`;
    $("#branch-pill").textContent = (repo.branches || []).join("  ·  ");
  }
  const last = state.stats?.last_scan;
  $("#last-scan").innerHTML = last
    ? `Last scan ${esc(relTime(last.finished_at || last.started_at))}`
    : "No scan yet";
}

/* -------------------------------- tables --------------------------------- */
function findingsTable(items) {
  return `<div class="table-wrap"><table class="data">
    <thead><tr>
      <th>CVE</th><th>Package</th><th>Version</th><th>Severity</th>
      <th>Confidence</th><th>Fixed in</th><th>Description</th><th>Upstream fix</th>
    </tr></thead>
    <tbody>${items.map(findingRow).join("")}</tbody>
  </table></div>`;
}

function findingRow(f) {
  const fix = f.fixed_version
    ? `<span class="ver">${esc(f.fixed_version)}</span>`
    : `<span class="muted small">unfixed</span>`;
  const upstream = f.upstream_fix
    ? `<a class="chip link" href="${esc(f.upstream_fix)}" target="_blank" rel="noopener">fix ↗</a>`
    : (f.advisory_id ? `<span class="chip">${esc(f.advisory_id)}</span>` : "—");
  return `<tr class="clickable" data-cve="${esc(f.cve_id)}">
    <td><span class="cve-id">${esc(f.cve_id)}</span></td>
    <td><span class="pkg-name">${esc(f.package_name)}</span></td>
    <td><span class="ver">${esc(f.package_version)}</span></td>
    <td>${sevBadge(f.severity)}</td>
    <td>${confBar(f.confidence)}</td>
    <td>${fix}</td>
    <td class="desc">${esc((f.description || "").slice(0, 190))}${(f.description || "").length > 190 ? "…" : ""}</td>
    <td>${upstream}</td>
  </tr>`;
}

async function renderFindings(view, route, status) {
  const page = state.page[status || route.key] || 1;
  const q = route.query;
  const params = {
    status, severity: q.severity || "", search: q.search || "",
    branch: q.branch || "", page, limit: 50,
  };
  const data = await api("/findings?" + qs(params));

  const statusTabs = status
    ? ""
    : `<div class="tabs" id="status-tabs">
        ${["", "affected", "patched", "false_positive", "unconfirmed"].map((s) => `
          <button data-status="${s}" class="${(q.status || "") === s ? "active" : ""}">${s ? esc(STATUS_LABELS[s]) : "All"}</button>`).join("")}
      </div>`;

  view.innerHTML = `
    <div class="toolbar">
      <input class="input search" id="f-search" placeholder="Search CVE, package, description…" value="${esc(q.search || "")}"/>
      <select class="select" id="f-sev">
        <option value="">All severities</option>
        ${SEVERITIES.map((s) => `<option value="${s}" ${q.severity === s ? "selected" : ""}>${s}</option>`).join("")}
      </select>
      ${statusTabs}
      <span class="muted small" style="margin-left:auto">${fmtNum(data.total)} results</span>
    </div>
    ${data.items.length ? findingsTable(data.items) : `<div class="empty">No findings match these filters.</div>`}
    ${pagination(page, data.total, 50, route)}
  `;

  $("#f-search").addEventListener("keydown", (e) => {
    if (e.key === "Enter") updateQuery(route, { search: e.target.value, page: null });
  });
  $("#f-sev").addEventListener("change", (e) => updateQuery(route, { severity: e.target.value, page: null }));
  $("#status-tabs")?.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-status]");
    if (btn) updateQuery(route, { status: btn.dataset.status, page: null });
  });
  bindPager(route);
}

function pagination(page, total, limit, route) {
  const pages = Math.max(1, Math.ceil(total / limit));
  if (pages <= 1) return "";
  return `<div class="pagination">
    <button class="btn btn-sm" data-page="${page - 1}" ${page <= 1 ? "disabled" : ""}>‹ Prev</button>
    <span>Page ${page} of ${pages}</span>
    <button class="btn btn-sm" data-page="${page + 1}" ${page >= pages ? "disabled" : ""}>Next ›</button>
  </div>`;
}

function currentRoute() { return parseHash(); }

function updateQuery(route, patch) {
  const q = { ...route.query, ...patch };
  Object.keys(q).forEach((k) => { if (!q[k]) delete q[k]; });
  state.page[route.key] = Number(q.page || 1);
  const base = route.parts.join("/");
  location.hash = `#/${base}${qs(q) ? "?" + qs(q) : ""}`;
}

function bindPager(route) {
  const pager = $(".pagination");
  if (!pager) return;
  pager.addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-page]");
    if (!btn || btn.disabled) return;
    updateQuery(route, { page: btn.dataset.page });
  });
}

/* ------------------------------ CVE detail ------------------------------- */
async function renderCveDetail(view, cveId) {
  if (!cveId) { location.hash = "#/cves"; return; }
  state.stats = state.stats || await api("/stats");
  const data = await api(`/cves/${encodeURIComponent(cveId)}`);
  const enrichment = data.enrichment || {};
  const findings = data.findings || [];
  const primary = findings[0] || {};
  const sev = enrichment.severity || primary.severity || "unknown";
  const score = enrichment.cvss_score ?? primary.cvss_score;
  const desc = enrichment.description || primary.description || "No description available.";
  const refs = enrichment.references || primary.references || [];
  const assigned = data.assignment;
  const canWrite = isEditor();

  const affectedPkgs = findings.filter((f) => f.status === "affected");
  const patchedPkgs = findings.filter((f) => f.status === "patched");
  const falsePos = findings.filter((f) => f.status === "false_positive");

  view.innerHTML = `
    <a class="backlink" href="#/affected">‹ Back to findings</a>
    <div class="detail-grid">
      <div class="card">
        <div class="card-head">
          <h2 class="cve-id" style="font-size:18px">${esc(cveId)}</h2>
          <div>${sevBadge(sev)} ${score != null ? `<span class="chip">CVSS ${esc(score)}</span>` : ""}</div>
        </div>
        <p class="muted" style="margin-top:-4px">${esc(desc)}</p>

        ${primary.cvss_vector ? `<p class="mono small muted">${esc(primary.cvss_vector)}</p>` : ""}

        <div class="card-head" style="margin-top:18px"><h2>Verification</h2></div>
        ${primary.evidence?.length ? `<ul class="evidence">${primary.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul>` : `<p class="muted small">No verification notes.</p>`}
        <dl class="kv" style="margin-top:16px">
          <dt>Confidence</dt><dd>${confBar(primary.confidence)}</dd>
          <dt>Sources</dt><dd>${(enrichment.sources || primary.raw_sources || []).map((s) => `<span class="chip">${esc(s)}</span>`).join(" ") || "—"}</dd>
          <dt>Corroborated</dt><dd>${corrChips(primary.corroborating_sources)}</dd>
          <dt>Advisory</dt><dd class="mono">${esc(primary.advisory_id || "—")}</dd>
        </dl>

        ${refs.length ? `
        <div class="card-head" style="margin-top:18px"><h2>References &amp; upstream fix</h2></div>
        <div class="list">
          ${refs.slice(0, 12).map((r) => `
            <div class="list-item"><div class="grow">
              <h4>${esc(r.source || r.type || "reference")}</h4>
              <p>${extLink(r.url)}</p>
            </div></div>`).join("")}
        </div>` : ""}
      </div>

      <div>
        <div class="card">
          <div class="card-head"><h2>Assign to patch automation</h2></div>
          <p class="muted small" style="margin-top:-4px">Queue this CVE for the AI backport workflow. VULNEX prepares the work item; the remediation agents open the pull request against <span class="mono">${esc(state.stats?.repository?.patch_target_repo || "azurelinux-test")}</span> only.</p>
          ${canWrite ? `
          <div class="toolbar" style="margin:12px 0 0">
            <input class="input" id="assign-pkg" placeholder="package" value="${esc(primary.package_name || "")}"/>
            <input class="input" id="assign-notes" placeholder="triage notes (optional)"/>
          </div>
          <button class="btn btn-primary" id="assign-btn" style="margin-top:12px;width:100%;justify-content:center" ${assigned ? "disabled" : ""}>
            ${assigned ? "✓ Assigned to Patch Automation" : "Assign to Patch Automation"}
          </button>` : `
          <p class="viewer-note" style="margin-top:12px"><b>Read-only view.</b> You can inspect this finding, its range-match evidence, patch provenance and confidence. Assigning work and leaving triage comments is limited to editors — click <b>Read-only view</b> in the header if you have the key.</p>`}
          ${assigned ? `<p class="muted small" style="margin-bottom:0">Status: <b>${esc(assigned.status)}</b> · queued ${esc(fmtTime(assigned.created_at))}</p>` : ""}
          ${commentsBlock(assigned)}
        </div>

        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Automation workflow</h2></div>
          <div class="workflow">
            <span class="step ${assigned ? "active" : ""}">VULNEX</span><span class="arrow">→</span>
            <span class="step ${assigned ? "active" : ""}">Patch Queue</span><span class="arrow">→</span>
            <span class="step">AI Patch/Backport</span><span class="arrow">→</span>
            <span class="step">Security Review</span><span class="arrow">→</span>
            <span class="step">PR Agent</span><span class="arrow">→</span>
            <span class="step">GitHub PR</span>
          </div>
        </div>

        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Affected packages (${affectedPkgs.length})</h2></div>
          ${affectedPkgs.length ? affectedPkgs.map(pkgFindingCard).join("") : `<p class="muted small">No package is currently affected by this CVE.</p>`}
        </div>

        ${patchedPkgs.length ? `
        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Distro patch status (${patchedPkgs.length})</h2></div>
          ${patchedPkgs.map(pkgFindingCard).join("")}
        </div>` : ""}

        ${falsePos.length ? `
        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Marked not affected (${falsePos.length})</h2></div>
          ${falsePos.map(pkgFindingCard).join("")}
        </div>` : ""}
      </div>
    </div>
  `;

  $("#assign-btn")?.addEventListener("click", async (e) => {
    if (!requireEditor()) return;
    e.target.disabled = true;
    try {
      await api("/assignments", {
        method: "POST",
        body: {
          cve_id: cveId,
          package_name: $("#assign-pkg").value.trim() || primary.package_name,
          notes: $("#assign-notes").value.trim(),
        },
      });
      toast(`${cveId} assigned to Patch Automation`);
      render();
    } catch (err) {
      e.target.disabled = false;
      toast(err.message, true);
    }
  });
}

function pkgFindingCard(f) {
  const links = [];
  if (f.package_name) {
    const b = f.branch ? `?branch=${encodeURIComponent(f.branch)}` : "";
    links.push(`<a class="chip link" href="#/package/${encodeURIComponent(f.package_name)}${b}">package</a>`);
  }
  if (f.spec_path) links.push(`<a class="chip link" href="${esc(blobUrl(f.spec_path, f.branch))}" target="_blank" rel="noopener">spec ↗</a>`);
  if (f.upstream_fix) links.push(`<a class="chip link" href="${esc(f.upstream_fix)}" target="_blank" rel="noopener">upstream fix ↗</a>`);
  return `<div class="list-item">
    <div class="grow">
      <h4>${esc(f.package_name)} <span class="muted" style="font-family:var(--sans)">${esc(f.package_version)}</span> ${statusBadge(f.status)}</h4>
      <p>${f.patch_name ? `backport: <span class="mono">${esc(f.patch_name)}</span> · ` : ""}${f.fixed_version ? `fixed in ${esc(f.fixed_version)} · ` : ""}${esc(f.branch || "")}</p>
      ${f.affected_files?.length ? `<p title="${esc(f.affected_files.join(", "))}">files: <span class="mono">${esc(f.affected_files.slice(0, 4).join(", "))}${f.affected_files.length > 4 ? "…" : ""}</span></p>` : ""}
      <div class="tag-list" style="margin-top:7px">${links.join("")}</div>
    </div>
    <div style="text-align:right">${confBar(f.confidence)}</div>
  </div>`;
}

/* ------------------------------- packages -------------------------------- */
async function renderPackages(view, route) {
  const q = route.query;
  state.stats = state.stats || await api("/stats");
  const page = state.page.packages || 1;
  const data = await api("/packages?" + qs({ search: q.search || "", branch: q.branch || "", page, limit: 40 }));

  view.innerHTML = `
    <div class="toolbar">
      <input class="input search" id="p-search" placeholder="Search packages…" value="${esc(q.search || "")}"/>
      <span class="muted small" style="margin-left:auto">${fmtNum(data.total)} packages</span>
    </div>
    <div class="table-wrap"><table class="data">
      <thead><tr><th>Package</th><th>Version</th><th>Release</th><th>Branch</th><th>Patches</th><th>Findings</th><th>Source</th></tr></thead>
      <tbody>${data.items.map(packageRow).join("")}</tbody>
    </table></div>
    ${pagination(page, data.total, 40, route)}
  `;
  $("#p-search").addEventListener("keydown", (e) => {
    if (e.key === "Enter") updateQuery(route, { search: e.target.value, page: null });
  });
  bindPager(route);
}

function packageRow(p) {
  const fc = p.finding_counts || {};
  const total = Object.values(fc).reduce((a, b) => a + b, 0);
  const bits = Object.entries(fc).map(([s, n]) => `<span class="chip" style="color:${STATUS_COLORS[s] || "var(--muted)"}">${esc(n)} ${esc(s.replace("_", " "))}</span>`).join(" ");
  const src = p.tarball_available === 0
    ? `<span class="chip" title="not found in blob store">tarball ✗</span>`
    : (p.tarball_name ? `<span class="chip" title="${esc(p.tarball_url || "")}">tarball ✓</span>` : "—");
  return `<tr class="clickable" data-pkg="${esc(p.name)}" data-branch="${esc(p.branch)}">
    <td><span class="pkg-name">${esc(p.name)}</span>${p.is_primary ? "" : ` <span class="chip" title="versioned spec variant">variant</span>`}</td>
    <td><span class="ver">${esc(p.version)}</span></td>
    <td><span class="ver">${esc(p.release || "—")}</span></td>
    <td><span class="chip">${esc(p.branch)}</span></td>
    <td>${fmtNum(p.patch_count)}</td>
    <td>${total ? `<div class="tag-list">${bits}</div>` : `<span class="muted small">none</span>`}</td>
    <td>${src}</td>
  </tr>`;
}

async function renderPackageDetail(view, name, branch, spec) {
  if (!name) { location.hash = "#/packages"; return; }
  state.stats = state.stats || await api("/stats");
  const params = {};
  if (branch) params.branch = branch;
  if (spec) params.spec = spec;
  const pkg = await api(
    `/packages/${encodeURIComponent(name)}` + (qs(params) ? `?${qs(params)}` : "")
  );
  const findings = pkg.findings || [];
  const affected = findings.filter((f) => f.status === "affected");
  const patched = findings.filter((f) => f.status === "patched");
  const nopatch = findings.filter((f) => f.status === "false_positive");
  const sources = pkg.source_urls || [];

  view.innerHTML = `
    <a class="backlink" href="#/packages">‹ Back to packages</a>
    <div class="detail-grid">
      <div class="card">
        <div class="card-head">
          <h2 style="font-size:18px">${esc(pkg.name)}</h2>
          <div class="tag-list">
            <span class="chip">${esc(pkg.branch)}</span>
            ${pkg.tarball_available === 1 ? `<span class="chip" style="color:var(--accent-2)">source available</span>` : ""}
          </div>
        </div>
        <p class="muted" style="margin-top:-4px">${esc(pkg.summary || "")}</p>
        ${pkg.variants && pkg.variants.length > 1 ? `
        <div class="tag-list" style="margin:10px 0 2px">
          <span class="muted small" style="align-self:center">Spec variants:</span>
          ${pkg.variants.map((v) => {
            const active = v.spec_path === pkg.spec_path && v.branch === pkg.branch;
            const href = `#/package/${encodeURIComponent(pkg.name)}?` + qs({ branch: v.branch, spec: v.spec_path });
            return `<a class="chip link" href="${href}" title="${esc(v.spec_path)}" style="${active ? "border-color:var(--accent);color:var(--accent)" : ""}">${esc(v.evr)} · ${esc(v.branch)}${v.is_primary ? " ★" : ""}</a>`;
          }).join("")}
        </div>` : ""}
        <dl class="kv">
          <dt>Version</dt><dd class="mono">${esc(pkg.version)}-${esc(pkg.release || "")}</dd>
          <dt>EVR</dt><dd class="mono">${esc(pkg.evr)}</dd>
          <dt>License</dt><dd>${esc(pkg.license || "—")}</dd>
          <dt>Upstream URL</dt><dd>${extLink(pkg.url)}</dd>
          <dt>Spec file</dt><dd class="mono">${extLink(blobUrl(pkg.spec_path, pkg.branch), pkg.spec_path)}</dd>
          <dt>Source0</dt><dd class="mono">${extLink(pkg.source0_url)}</dd>
        </dl>

        <div class="card-head" style="margin-top:18px"><h2>Sources &amp; tarballs</h2></div>
        <div class="list">
          ${sources.length ? sources.map((s) => `
            <div class="list-item"><div class="grow">
              <h4>${esc(s.tag)}</h4>
              <p class="mono">${esc(s.url || "local file")}</p>
              ${s.blob_url ? `<p>blob: ${extLink(s.blob_url, s.blob_url)}</p>` : ""}
            </div>
            ${s.is_tarball ? `<span class="chip">tarball</span>` : ""}</div>`).join("") : `<span class="muted small">No sources declared.</span>`}
        </div>

        <div class="card-head" style="margin-top:18px"><h2>Patches in spec (${pkg.patches.length})</h2></div>
        <div class="table-wrap"><table class="data" style="min-width:520px">
          <thead><tr><th>Tag</th><th>Patch</th><th>CVEs</th><th>Status</th></tr></thead>
          <tbody>${pkg.patches.map((p) => `
            <tr><td class="mono">${esc(p.tag)}</td>
            <td class="mono">${esc(p.filename)}</td>
            <td><div class="tag-list">${(p.cve_ids || []).map((c) => `<a class="chip link" href="#/cve/${esc(c)}">${esc(c)}</a>`).join("") || "—"}</div></td>
            <td>${patchStatusBadge(p)}</td></tr>`).join("")}
          </tbody></table></div>
      </div>

      <div>
        <div class="card">
          <div class="card-head"><h2>Affected CVEs (${affected.length})</h2></div>
          ${affected.length ? affected.map(cveMiniCard).join("") : `<p class="muted small">No currently-exploitable CVEs detected for this version.</p>`}
        </div>
        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Already patched (${patched.length})</h2></div>
          ${patched.length ? patched.map(cveMiniCard).join("") : `<p class="muted small">No backport patches recorded.</p>`}
        </div>
        ${nopatch.length ? `
        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Marked not affected (${nopatch.length})</h2></div>
          ${nopatch.map(cveMiniCard).join("")}
        </div>` : ""}
      </div>
    </div>
  `;
}

function patchStatusBadge(p) {
  if (p.is_nopatch) return `<span class="badge st-false_positive">not affected</span>`;
  if (p.file_present === 0) return `<span class="badge st-unconfirmed">missing file</span>`;
  return `<span class="badge st-patched">applied</span>`;
}

function cveMiniCard(f) {
  return `<div class="list-item">
    <div class="grow">
      <h4><a class="cve-id" href="#/cve/${esc(f.cve_id)}">${esc(f.cve_id)}</a> ${sevBadge(f.severity)}</h4>
      <p>${esc((f.description || "No description").slice(0, 130))}${(f.description || "").length > 130 ? "…" : ""}</p>
    </div>
    <div style="text-align:right">${confBar(f.confidence)}</div>
  </div>`;
}

/* ------------------------------ assignments ------------------------------ */
function commentsBlock(a) {
  const comments = (a && a.comments) || [];
  if (!comments.length) return "";
  return `<div class="comment-list">${comments.map((c) => `
    <div class="comment"><span class="who">${esc(c.author || "editor")}</span>
    <span>${esc(c.body)}</span><span class="when">${esc(relTime(c.created_at))}</span></div>`).join("")}</div>`;
}

function bindCommentForms() {
  document.querySelectorAll("[data-comment-btn]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      if (!requireEditor()) return;
      const id = btn.dataset.commentBtn;
      const input = document.querySelector(`[data-comment-input="${id}"]`);
      const body = (input ? input.value : "").trim();
      if (!body) { toast("Write the comment first", true); return; }
      btn.disabled = true;
      try {
        await api(`/assignments/${id}/comments`, { method: "POST", body: { body } });
        toast("Triage comment added");
        render();
      } catch (err) {
        btn.disabled = false;
        toast(err.message, true);
      }
    });
  });
}

async function renderAssignments(view) {
  const data = await api("/assignments");
  const canWrite = isEditor();
  view.innerHTML = `
    <div class="card">
      <div class="card-head"><h2>Patch automation queue</h2>
        <span class="muted small">${fmtNum(data.items.length)} items</span></div>
      ${data.items.length ? `
      <div class="table-wrap"><table class="data">
        <thead><tr><th>CVE</th><th>Package</th><th>Target repo</th><th>Status</th><th>Notes</th><th>Queued</th></tr></thead>
        <tbody>${data.items.map((a) => `
          <tr><td><a class="cve-id" href="#/cve/${esc(a.cve_id)}">${esc(a.cve_id)}</a></td>
          <td><span class="pkg-name">${esc(a.package_name)}</span></td>
          <td><span class="mono small">${esc(a.target_repo)}</span></td>
          <td><span class="badge st-unconfirmed">${esc(a.status)}</span></td>
          <td class="desc">${esc(a.notes || "—")}${commentsBlock(a)}
            ${canWrite ? `<div class="comment-form">
              <input class="input" data-comment-input="${a.id}" placeholder="triage comment…"/>
              <button class="btn btn-sm" data-comment-btn="${a.id}">Comment</button>
            </div>` : ""}</td>
          <td class="muted small">${esc(relTime(a.created_at))}</td></tr>`).join("")}
        </tbody></table></div>` : `<div class="empty">Nothing queued yet.${canWrite ? " Open a CVE and choose <b>Assign to Patch Automation</b>." : ""}</div>`}
    </div>
    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Downstream workflow (interface ready)</h2></div>
      <div class="workflow">
        <span class="step active">VULNEX</span><span class="arrow">→</span>
        <span class="step active">Patch Queue</span><span class="arrow">→</span>
        <span class="step">AI Patch/Backport Agent</span><span class="arrow">→</span>
        <span class="step">Security Review Agent</span><span class="arrow">→</span>
        <span class="step">PR Agent</span><span class="arrow">→</span>
        <span class="step">GitHub Pull Request</span>
      </div>
      <p class="muted small">Assignments are persisted and exposed over the API so the future remediation agents can pick them up. PRs are only ever opened against the configured Azure Linux test repository.</p>
    </div>
    ${canWrite ? "" : `<div class="card" style="margin-top:16px"><p class="viewer-note"><b>Read-only view.</b> The queue, its statuses and every triage comment are visible to all visitors. Adding comments or changing status needs editor access.</p></div>`}
  `;
  if (canWrite) bindCommentForms();
}

/* --------------------------------- scan ---------------------------------- */
async function renderScan(view) {
  const status = await api("/scan/status");
  const history = await api("/scans");
  const canWrite = isEditor();
  view.innerHTML = `
    <div class="grid cols-2">
      <div class="card">
        <div class="card-head">
          <h2>Run a live scan</h2>
          <span id="scan-state">${status.manager.running ? `<span class="live-dot"></span> running` : "idle"}</span>
        </div>
        <p class="muted small" style="margin-top:-4px">Fetches the latest SPECS from the Azure Linux repository, extracts package versions and patches, queries OSV Azure Linux advisories, verifies distro backports, corroborates across distros and refreshes the dashboard.</p>
        ${canWrite ? `
        <div class="toolbar" style="margin-top:12px">
          <label class="muted small">Limit packages</label>
          <input class="input" id="scan-limit" type="number" min="0" value="0" style="min-width:110px"/>
          <label class="muted small"><input type="checkbox" id="scan-blobs" checked/> verify tarballs</label>
          <label class="muted small"><input type="checkbox" id="scan-enrich" checked/> enrich CVEs</label>
        </div>
        <button class="btn btn-primary" id="scan-start" ${status.manager.running ? "disabled" : ""} style="margin-top:6px">Run scan now</button>` : `
        <p class="viewer-note" style="margin-top:12px"><b>Read-only view.</b> Scan history and the latest run are visible to everyone; starting a scan needs editor access.</p>`}
        <div id="scan-log" class="list" style="margin-top:14px">
          ${(status.manager.log || []).slice(-8).map((l) => `<div class="list-item"><div class="grow"><p class="mono small">${esc(l.message)}</p></div><span class="muted small">${esc(fmtTime(l.at))}</span></div>`).join("")}
        </div>
      </div>

      <div class="card">
        <div class="card-head"><h2>Latest scan</h2></div>
        ${renderLatestScan(status.latest_scan)}
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Scan history</h2></div>
      <div class="table-wrap"><table class="data">
        <thead><tr><th>#</th><th>Started</th><th>Status</th><th>Packages</th><th>Findings</th><th>Affected</th><th>Patched</th><th>Duration</th></tr></thead>
        <tbody>${history.items.map((s) => `
          <tr><td class="mono">${s.id}</td>
          <td class="muted small">${esc(fmtTime(s.started_at))}</td>
          <td class="status-${esc(s.status)}">${esc(s.status)}</td>
          <td>${fmtNum(s.package_count)}</td><td>${fmtNum(s.finding_count)}</td>
          <td>${fmtNum(s.affected_count)}</td><td>${fmtNum(s.patched_count)}</td>
          <td class="muted small">${s.duration_seconds != null ? esc(s.duration_seconds) + "s" : "—"}</td></tr>`).join("")}
        </tbody></table></div>
    </div>
  `;

  $("#scan-start")?.addEventListener("click", async (e) => {
    if (!requireEditor()) return;
    e.target.disabled = true;
    try {
      await api("/scan", {
        method: "POST",
        body: {
          limit: Number($("#scan-limit").value || 0),
          verify_blobs: $("#scan-blobs").checked,
          enrich: $("#scan-enrich").checked,
        },
      });
      toast("Scan started — this can take a minute");
      pollScan();
    } catch (err) {
      toast(err.message, true);
      e.target.disabled = false;
    }
  });

  if (status.manager.running) pollScan();
  else clearInterval(state.scanTimer);
}

function renderLatestScan(s) {
  if (!s) return `<div class="empty">No scan recorded yet.</div>`;
  return `<dl class="kv">
    <dt>Status</dt><dd class="status-${esc(s.status)}">${esc(s.status)}</dd>
    <dt>Started</dt><dd>${esc(fmtTime(s.started_at))}</dd>
    <dt>Finished</dt><dd>${esc(fmtTime(s.finished_at))}</dd>
    <dt>Branches</dt><dd class="mono small">${esc(s.branches || "—")}</dd>
    <dt>Ecosystem</dt><dd class="mono small">${esc(s.ecosystem || "—")}</dd>
    <dt>Packages</dt><dd>${fmtNum(s.package_count)}</dd>
    <dt>Findings</dt><dd>${fmtNum(s.finding_count)}</dd>
    <dt>Affected</dt><dd>${fmtNum(s.affected_count)}</dd>
    <dt>Patched</dt><dd>${fmtNum(s.patched_count)}</dd>
    <dt>Message</dt><dd class="small">${esc(s.message || "—")}</dd>
  </dl>`;
}

function pollScan() {
  clearInterval(state.scanTimer);
  state.scanTimer = setInterval(async () => {
    try {
      const status = await api("/scan/status");
      const el = $("#scan-state");
      if (el) el.innerHTML = status.manager.running ? `<span class="live-dot"></span> running` : "idle";
      const log = $("#scan-log");
      if (log) log.innerHTML = (status.manager.log || []).slice(-8).map((l) => `<div class="list-item"><div class="grow"><p class="mono small">${esc(l.message)}</p></div><span class="muted small">${esc(fmtTime(l.at))}</span></div>`).join("");
      if (!status.manager.running) {
        clearInterval(state.scanTimer);
        toast("Scan complete");
        if (parseHash().key === "scan") render();
      }
    } catch (_) { /* keep polling */ }
  }, 2000);
}

/* --------------------------------- about --------------------------------- */
async function renderAbout(view) {
  const m = state.methodology || await api("/methodology");
  state.methodology = m;
  const repo = state.stats?.repository || {};
  view.innerHTML = `
    <div class="detail-grid">
      <div class="card">
        <div class="card-head"><h2>How VULNEX works</h2></div>
        <p class="muted">VULNEX reads the real Azure Linux RPM spec tree, matches each package against the official <b>Azure Linux advisory database</b> published on OSV, then verifies every hit against the distro's own backport patches before showing it as exploitable.</p>
        <div class="workflow" style="margin:14px 0">
          <span class="step active">Azure Linux SPECS</span><span class="arrow">→</span>
          <span class="step">OSV advisories</span><span class="arrow">→</span>
          <span class="step">RPM range match</span><span class="arrow">→</span>
          <span class="step">Patch verification</span><span class="arrow">→</span>
          <span class="step">Corroboration</span><span class="arrow">→</span>
          <span class="step active">VULNEX dashboard</span>
        </div>
        <h2 style="margin-top:18px">Range matching</h2>
        <p class="muted">${esc(m.range_matching)}</p>
        <h2 style="margin-top:18px">Status definitions</h2>
        <div class="list">
          ${Object.entries(m.statuses).map(([k, v]) => `
            <div class="list-item"><div class="grow"><h4>${statusBadge(k)} <span class="mono small muted">${esc(k)}</span></h4><p>${esc(v)}</p></div></div>`).join("")}
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-head"><h2>Intelligence sources</h2></div>
          <div class="list">
            ${m.sources.map((s) => `
              <div class="list-item"><div class="grow">
                <h4>${esc(s.name)}</h4>
                <p>${esc(s.role)}</p>
                <p>${extLink(s.url)}</p>
              </div></div>`).join("")}
          </div>
        </div>
        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Scan target</h2></div>
          <dl class="kv">
            <dt>Repository</dt><dd class="mono">${esc((repo.owner || "") + "/" + (repo.repo || ""))}</dd>
            <dt>Branches</dt><dd class="mono small">${esc((repo.branches || []).join(", "))}</dd>
            <dt>Ecosystem</dt><dd class="mono">${esc(repo.ecosystem || "")}</dd>
            <dt>PR target</dt><dd class="mono">${esc(repo.patch_target_repo || "")}</dd>
          </dl>
        </div>
      </div>
    </div>
  `;
}

/* -------------------------------- project -------------------------------- */
const PROJECT_HIGHLIGHTS = [
  {
    title: "Real RPM version semantics",
    body: "Every decision runs through a dependency-free port of lib/rpmvercmp.c: numeric segments beat alpha ones, `1.0~rc1` sorts before `1.0`, `1.0^git1` after it and `fc4` equals `fc.4` — exactly like rpm.",
  },
  {
    title: "Distro backports beat upstream ranges",
    body: "A package can sit below a CVE's upstream fix and still be fully patched, because Azure Linux backports fixes as Patch: entries. VULNEX reads those patches and the CVE-*.nopatch \"not affected\" markers straight out of the .spec and lets them override the range match.",
  },
  {
    title: "Identity is (branch, spec_path)",
    body: "Five specs ship under one golang name and two under rust. Keying by package name silently merges them, so VULNEX keeps every spec, marks the canonical <name>.spec as primary and exposes versioned siblings as variants.",
  },
  {
    title: "Every verdict carries its evidence",
    body: "Findings store the advisory id, the matched event boundary, the patch file, whether that file actually exists in the tree, cross-distro corroboration and a confidence score — the dashboard explains why something is affected or already patched.",
  },
];

const ENGINEERING_LOG = [
  {
    title: "A commented-out patch leaked a CVE",
    body: "`# Patch2: CVE-1999-0001.patch` was parsed as an applied backport, which flipped a real exposure into \"already patched\". The parser now skips commented lines that look like patches, sources or fields.",
  },
  {
    title: "\"Affected but unfixed\" was reported as unconfirmed",
    body: "Azure Linux advisories often bound a range with last_affected equal to the shipped version. Those are affected-and-unfixed, not uncertain, so they now land in `affected` with reason `unfixed` and a confidence penalty.",
  },
  {
    title: "Duplicate package names broke the snapshot",
    body: "Two UNIQUE constraints fired on real data: packages(branch, name) and findings(cve_id, spec_path). Both keys were wrong — the schema moved to (branch, spec_path) and findings(cve_id, branch, spec_path).",
  },
];

async function renderProject(view) {
  state.stats = state.stats || await api("/stats");
  const repo = state.stats?.repository || {};
  const author = repo.author || {};
  const s = state.stats || {};
  const last = s.last_scan || {};

  const links = [];
  if (repo.project_url) links.push(`<a class="chip link" href="${esc(repo.project_url)}" target="_blank" rel="noopener">Source code ↗</a>`);
  if (repo.demo_url) links.push(`<a class="chip link" href="${esc(repo.demo_url)}" target="_blank" rel="noopener">Live demo ↗</a>`);
  if (author.github) links.push(`<a class="chip link" href="${esc(author.github)}" target="_blank" rel="noopener">GitHub ↗</a>`);
  if (author.url) links.push(`<a class="chip link" href="${esc(author.url)}" target="_blank" rel="noopener">Profile ↗</a>`);

  view.innerHTML = `
    <div class="project-hero">
      <div class="card">
        <div class="card-head"><h2>VULNEX</h2><span class="chip">Python · FastAPI · SQLite · vanilla JS</span></div>
        <h2 style="font-size:22px;letter-spacing:-0.02em;margin:0 0 10px">An Azure Linux CVE scanner that verifies before it alarms</h2>
        <p class="lede">VULNEX reads the real RPM spec tree of Azure Linux, matches every package against Microsoft's own advisory feed on OSV using true RPM version semantics, then checks each hit against the distro's backport patches — so the dashboard shows what is actually exploitable instead of a keyword soup.</p>
        <div class="workflow" style="margin:14px 0 4px">
          <span class="step active">Azure Linux SPECS</span><span class="arrow">→</span>
          <span class="step">OSV advisories</span><span class="arrow">→</span>
          <span class="step">RPM range match</span><span class="arrow">→</span>
          <span class="step">Patch verification</span><span class="arrow">→</span>
          <span class="step">Corroboration</span><span class="arrow">→</span>
          <span class="step active">VULNEX dashboard</span>
        </div>
        <div class="grid kpis" style="margin-top:16px">
          <div class="kpi info"><div class="k-label">Packages scanned</div>
            <div class="k-value">${fmtNum(s.total_packages)}</div><div class="k-sub">every RPM spec, both branches</div></div>
          <div class="kpi critical"><div class="k-label">Verified findings</div>
            <div class="k-value">${fmtNum(s.total_findings)}</div><div class="k-sub">${fmtNum(s.distinct_cves)} distinct CVEs</div></div>
          <div class="kpi patched"><div class="k-label">Already patched</div>
            <div class="k-value">${fmtNum(s.patched)}</div><div class="k-sub">distro backports detected</div></div>
          <div class="kpi high"><div class="k-label">Last scan</div>
            <div class="k-value" style="font-size:20px">${esc(last.finished_at ? relTime(last.finished_at) : "—")}</div>
            <div class="k-sub">${last.duration_seconds != null ? esc(last.duration_seconds) + "s runtime" : "no run recorded"}</div></div>
        </div>
      </div>

      <div>
        <div class="card author-card">
          <div class="card-head"><h2>Built by</h2></div>
          <p class="name" style="margin:0">${esc(author.name || "—")}</p>
          ${author.tagline ? `<p class="muted small" style="margin:4px 0 0">${esc(author.tagline)}</p>` : ""}
          <p class="muted small" style="margin:8px 0 0">Solo build: collector, matcher, verifier, API, dashboard, scheduled CI and deployment.</p>
          <div class="links">${links.join(" ") || '<span class="muted small">—</span>'}</div>
        </div>

        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Who can do what</h2></div>
          <div class="list">
            <div class="list-item"><div class="grow">
              <h4 style="font-family:var(--sans);font-size:13.5px;color:var(--text)">Viewer — the public link</h4>
              <p>Sees every finding, patch, verification note and confidence score. Cannot assign work, comment or start scans.</p>
            </div></div>
            <div class="list-item"><div class="grow">
              <h4 style="font-family:var(--sans);font-size:13.5px;color:var(--text)">Editor — maintainer key</h4>
              <p>Unlocks on the live server with an editor key: queue a CVE for patch automation, move queue status and leave triage comments. Write endpoints answer 401 without the key.</p>
            </div></div>
          </div>
        </div>
      </div>
    </div>

    <div class="grid cols-2" style="margin-top:16px">
      <div class="card">
        <div class="card-head"><h2>What makes it non-trivial</h2></div>
        <div class="list">
          ${PROJECT_HIGHLIGHTS.map((h, i) => `
            <div class="list-item highlight"><span class="n">${i + 1}</span><div class="grow">
              <h4 style="font-family:var(--sans);font-size:13.5px;color:var(--text)">${esc(h.title)}</h4>
              <p>${esc(h.body)}</p>
            </div></div>`).join("")}
        </div>
      </div>

      <div>
        <div class="card">
          <div class="card-head"><h2>Engineering log — bugs found on real data</h2></div>
          <div class="list">
            ${ENGINEERING_LOG.map((e) => `
              <div class="list-item log-entry"><div class="grow">
                <h4 style="font-family:var(--sans);font-size:13.5px;color:var(--text)">${esc(e.title)}</h4>
                <p>${esc(e.body)}</p>
              </div></div>`).join("")}
          </div>
        </div>

        <div class="card" style="margin-top:16px">
          <div class="card-head"><h2>Run it yourself</h2></div>
          <pre class="code-block">git clone ${esc(repo.project_url || "https://github.com/akhila-dev5/vulnex")}
cd vulnex
make install   # venv + runtime deps
make test      # 41 tests
make serve     # http://localhost:8000
make scan      # re-run the full two-branch scan</pre>
          <div class="tag-list" style="margin-top:12px">
            ${["Python 3.10", "FastAPI", "SQLite", "OSV.dev", "NVD", "MITRE CVE", "Red Hat", "vanilla JS (no build)", "GitHub Actions", "GitHub Pages"].map((t) => `<span class="chip">${esc(t)}</span>`).join("")}
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Data sources &amp; methodology</h2>
        <a class="chip link" href="#/about">Methodology page →</a></div>
      <p class="muted small" style="margin:0">Detection uses the official Azure Linux advisory feed (OSV ecosystem <span class="mono">${esc(repo.ecosystem || "Azure Linux:3")}</span>), cross-distro corroboration from Red Hat, Debian, Ubuntu and Alpine, and enrichment from NVD, MITRE CVE and GitHub Security Advisories. Everything runs on free public data — no paid API anywhere in the stack.</p>
    </div>
  `;
}

/* ------------------------------- events ---------------------------------- */
document.addEventListener("click", (e) => {
  const cveRow = e.target.closest("tr[data-cve]");
  if (cveRow) { location.hash = `#/cve/${encodeURIComponent(cveRow.dataset.cve)}`; return; }
  const pkgRow = e.target.closest("tr[data-pkg]");
  if (pkgRow) {
    const b = pkgRow.dataset.branch ? `?branch=${encodeURIComponent(pkgRow.dataset.branch)}` : "";
    location.hash = `#/package/${encodeURIComponent(pkgRow.dataset.pkg)}${b}`;
    return;
  }
});

$("#scan-now")?.addEventListener("click", async () => {
  if (!requireEditor()) return;
  try {
    await api("/scan", { method: "POST", body: {} });
    toast("Scan started");
    location.hash = "#/scan";
  } catch (err) {
    toast(err.message, true);
  }
});

$("#nav-toggle")?.addEventListener("click", () => {
  document.querySelector(".sidebar")?.classList.toggle("open");
});

/* --------------------------- access tier controls ------------------------ */
function openUnlockModal() {
  const modal = $("#unlock-modal");
  if (!modal) return;
  modal.hidden = false;
  $("#unlock-key").value = "";
  setTimeout(() => $("#unlock-key").focus(), 30);
}

function closeUnlockModal() {
  const modal = $("#unlock-modal");
  if (modal) modal.hidden = true;
}

$("#role-chip")?.addEventListener("click", async () => {
  if (isEditor()) {
    if (state.roleInfo && state.roleInfo.key_required === false) {
      toast("This server has no editor key set, so it stays in editor mode.");
      return;
    }
    setStoredEditorKey("");
    state.role = "viewer";
    state.roleInfo = { role: "viewer", write_enabled: false, key_required: true };
    renderRoleChip();
    toast("Locked — back to the read-only view");
    render();
    return;
  }
  if (STATIC) {
    toast("This hosted build is read-only. Run `vulnex serve` locally for editor mode.");
    return;
  }
  if (state.roleInfo && state.roleInfo.key_required === false) {
    toast("No editor key is configured on this server — it is already open for editing.");
    return;
  }
  openUnlockModal();
});

$("#unlock-cancel")?.addEventListener("click", closeUnlockModal);
$("#unlock-modal")?.addEventListener("click", (e) => {
  if (e.target.id === "unlock-modal") closeUnlockModal();
});
$("#unlock-key")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#unlock-submit").click();
});
$("#unlock-submit")?.addEventListener("click", async () => {
  const key = ($("#unlock-key").value || "").trim();
  if (!key) { toast("Enter the editor key", true); return; }
  setStoredEditorKey(key);
  try {
    const info = await api("/role");
    if (info.role !== "editor") throw new Error("That key was not accepted.");
    state.role = "editor";
    state.roleInfo = info;
    closeUnlockModal();
    renderRoleChip();
    toast("Editor mode unlocked");
    render();
  } catch (err) {
    setStoredEditorKey("");
    toast(err.message, true);
  }
});

$("#share-btn")?.addEventListener("click", async () => {
  const url = location.href;
  try {
    await navigator.clipboard.writeText(url);
    toast("Link copied — paste it anywhere");
  } catch (_) {
    window.prompt("Copy this link:", url);
  }
});

window.addEventListener("hashchange", render);
window.addEventListener("DOMContentLoaded", async () => {
  // Warm the static snapshot so the first navigation is instant on Pages.
  if (STATIC) staticBundle().catch(() => {});
  // Resolve the access tier before the first paint so editor-only controls
  // never flash for a viewer.
  await resolveRole();
  render();
  // keep the KPI chrome fresh
  setInterval(async () => {
    try { state.stats = await api("/stats"); updateChrome(); } catch (_) {}
  }, 60000);
});
