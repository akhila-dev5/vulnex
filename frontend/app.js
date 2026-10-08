/* ==========================================================================
   VULNEX dashboard — vanilla SPA (hash router + fetch). No build step, no CDN.
   ========================================================================== */
"use strict";

const API = "/api";
// Set by the GitHub Pages build (vulnex export); null for the live API.
const STATIC = window.VULNEX_STATIC || null;
// The exported snapshot has no backend, so it is always the read-only tier.
const STATIC_ROLE = (STATIC && STATIC.role) || null;
// Holds the admin session token (or the automation key) — never a password.
const KEY_STORAGE = "vulnex.session";

const NO_CAPS = {
  write_enabled: false, can_comment: false, can_dispute: false,
  can_triage: false, can_scan: false, can_set_patch_verdict: false, can_set_pr: false,
};

const state = {
  stats: null,
  page: {},          // per-route pagination
  scanTimer: null,
  expanded: {},      // triage rows that are expanded
  deep: {},          // cveId -> deep payload
  role: STATIC ? "viewer" : null,   // "viewer" | "admin" | "automation"
  caps: STATIC ? { ...NO_CAPS } : null,
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

function patchBlobUrl(specPath, branch, filename) {
  const repo = state.stats?.repository;
  if (!repo || !specPath || !filename) return "";
  const dir = specPath.includes("/") ? specPath.slice(0, specPath.lastIndexOf("/")) : "";
  const path = [dir, filename].filter(Boolean).join("/");
  return `https://github.com/${repo.owner}/${repo.repo}/blob/${branch || ""}/${path}`;
}

/* ------------------------------ access tiers -----------------------------
   VULNEX is read-only until an admin signs in. Signing in is email + password
   or GitHub; the server answers with an opaque session token that is kept here
   and sent as the X-VULNEX-Key header on every request. Three roles exist:
     viewer      read everything, change nothing
     admin       triage, dispute, patch verdicts, PR reference, scans
     automation  a machine key that may ONLY set the GitHub CVE PR
   ------------------------------------------------------------------------ */
function storedKey() {
  try { return localStorage.getItem(KEY_STORAGE) || ""; } catch (_) { return ""; }
}

function setStoredKey(key) {
  try {
    if (key) localStorage.setItem(KEY_STORAGE, key);
    else localStorage.removeItem(KEY_STORAGE);
  } catch (_) { /* storage unavailable: sign-in still works for this session */ }
}

function isAdmin() { return state.role === "admin"; }
const can = (name) => Boolean(state.caps && state.caps[name]);

function applyRole(info) {
  state.roleInfo = info || { role: "viewer", ...NO_CAPS };
  state.role = state.roleInfo.role || "viewer";
  state.caps = {
    write_enabled: Boolean(state.roleInfo.write_enabled),
    can_comment: Boolean(state.roleInfo.can_comment),
    can_dispute: Boolean(state.roleInfo.can_dispute),
    can_triage: Boolean(state.roleInfo.can_triage),
    can_scan: Boolean(state.roleInfo.can_scan),
    can_set_patch_verdict: Boolean(state.roleInfo.can_set_patch_verdict),
    can_set_pr: Boolean(state.roleInfo.can_set_pr),
  };
  renderAuthArea();
}

function requireCap(name, message) {
  if (can(name)) return true;
  toast(message || "Read-only — sign in as admin to make changes.", true);
  return false;
}

async function resolveRole() {
  if (STATIC) {
    applyRole({ role: STATIC_ROLE || "viewer", ...NO_CAPS });
    return;
  }
  try {
    applyRole(await api("/role"));
  } catch (_) {
    applyRole({ role: "viewer", ...NO_CAPS });
  }
}

function renderAuthArea() {
  const loginBtn = $("#login-btn");
  const chip = $("#identity-chip");
  const out = $("#logout-btn");
  if (loginBtn && chip && out) {
    const signedIn = state.role === "admin" || state.role === "automation";
    // A static snapshot has no backend to authenticate against, so never offer sign-in.
    loginBtn.hidden = signedIn || Boolean(STATIC);
    chip.hidden = !signedIn;
    out.hidden = !signedIn;
    if (signedIn) {
      const id = (state.roleInfo && state.roleInfo.identity) || {};
      const who = id.identity || state.role;
      chip.className = "identity-chip " + state.role;
      chip.textContent = state.role === "automation" ? `${who} · PR only` : `${who} · admin`;
      chip.title = id.email ? `${who} (${id.email})` : who;
    }
  }
  const scanBtn = $("#scan-now");
  if (scanBtn) {
    scanBtn.disabled = !can("can_scan");
    scanBtn.title = can("can_scan") ? "" : "Read-only — running a scan needs admin access";
  }
}

async function api(path, opts = {}) {
  if (STATIC) return staticApi(path, opts);
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const key = storedKey();
  if (key) headers["X-VULNEX-Key"] = key;
  const res = await fetch(API + path, {
    ...opts,
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    if (res.status === 401 && path !== "/auth/login") {
      // A rejected write means the stored credential is no longer valid: drop to
      // read-only. A rejected *sign-in* is an ordinary form error, not a demotion.
      applyRole({ role: "viewer", ...NO_CAPS });
    }
    throw new Error(detail || "Read-only — that action needs admin access.");
  }
  return res.json();
}

/* ------------------- static snapshot data layer (Pages) ------------------ */
let STATIC_BUNDLE = null;

function triageKey(cve, branch, spec) {
  return `${(cve || "").toUpperCase()}\u0000${branch || ""}\u0000${spec || ""}`;
}

function findingKey(f) {
  return triageKey(f.cve_id, f.branch, f.spec_path);
}

async function staticBundle() {
  if (STATIC_BUNDLE) return STATIC_BUNDLE;
  const base = STATIC.base || "./";
  const get = async (name) => {
    const res = await fetch(base + "api/" + name);
    if (!res.ok) throw new Error(`Static snapshot is missing ${name}`);
    return res.json();
  };
  const [stats, findings, packages, patches, scans, triage] = await Promise.all([
    get("stats.json"), get("findings.json"), get("packages.json"),
    get("patches.json"), get("scans.json"),
    get("triage.json").catch(() => []),
  ]);
  const counts = {};
  const triageByKey = {};
  for (const t of triage) triageByKey[triageKey(t.cve_id, t.branch, t.spec_path)] = t;
  for (const f of findings) {
    const k = `${f.branch}\u0000${f.spec_path}`;
    if (!counts[k]) counts[k] = {};
    counts[k][f.status] = (counts[k][f.status] || 0) + 1;
    f.triage = triageByKey[findingKey(f)] || null;
  }
  STATIC_BUNDLE = {
    stats, findings, patches, scans, triageByKey,
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
    throw new Error("This is a read-only static snapshot. Run `vulnex serve` for the live tool.");
  }
  const b = await staticBundle();
  const [pathPart, queryPart] = String(path).split("?");
  const q = Object.fromEntries(new URLSearchParams(queryPart || ""));
  const parts = pathPart.split("/").filter(Boolean);

  if (parts[0] === "stats") return b.stats;
  if (parts[0] === "assignments") return { items: [] };
  if (parts[0] === "scans") return { items: b.scans.items };
  if (parts[0] === "scan" && parts[1] === "status") {
    return { manager: b.scans.manager, latest_scan: b.scans.latest };
  }

  if (parts[0] === "triage") {
    const status = q.status === undefined ? "affected" : q.status;
    let items = b.findings;
    if (status) items = items.filter((f) => f.status === status);
    if (q.search) {
      const s = q.search.toLowerCase();
      items = items.filter((f) =>
        (f.cve_id || "").toLowerCase().includes(s) ||
        (f.package_name || "").toLowerCase().includes(s));
    }
    items = items.map((f) => ({ ...f, comments: (f.triage && f.triage.comments) || [] }));
    return paginate(items, q.limit, q.page);
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
    return { cve_id: id, findings, enrichment: null, assignment: null, links: [] };
  }

  if (parts[0] === "cves" && parts[2] === "deep") {
    const id = decodeURIComponent(parts[1]).toUpperCase();
    const match = b.findings.find((f) =>
      (f.cve_id || "").toUpperCase() === id &&
      (!q.spec || f.spec_path === q.spec) && (!q.branch || f.branch === q.branch)) ||
      b.findings.find((f) => (f.cve_id || "").toUpperCase() === id);
    if (!match) throw new Error("CVE not found in this snapshot");
    const pkg = b.packages.find((p) =>
      p.branch === match.branch && p.spec_path === match.spec_path) || {};
    const affected = match.affected_files || [];
    const patchName = match.patch_name && !String(match.patch_name).endsWith(".nopatch")
      ? match.patch_name : null;
    return {
      cve_id: match.cve_id, package_name: match.package_name,
      package_version: match.package_version, branch: match.branch,
      spec_path: match.spec_path, spec_url: pkg.spec_url || "",
      tarball: pkg.tarball_name
        ? { name: pkg.tarball_name, url: pkg.tarball_url || "", available: pkg.tarball_available }
        : null,
      affected_files: affected,
      backport_patches: patchName
        ? [{ filename: patchName, url: patchBlobUrl(match.spec_path, match.branch, patchName), present: null }]
        : [],
      notes: [affected.length
        ? "Files listed are the paths touched by the upstream fix commit for this CVE."
        : "No upstream fix commit was resolvable, so the touched files could not be listed from that source."],
    };
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
  packages: ["Packages", "Every RPM spec collected from the repository"],
  package: ["Package detail", "RPM spec, sources, patches and verified CVEs"],
  cve: ["CVE detail", "Verdict, patch availability and triage trail"],
  triage: ["Triage", "Patch availability, status and owner per finding"],
  scan: ["Scan Control", "Run a live scan against the Azure Linux repository"],
};

async function render() {
  const route = parseHash();
  const name = route.key;
  const [title, sub] = TITLES[name] || TITLES.dashboard;
  $("#page-title").textContent = title;
  $("#page-sub").textContent = sub;
  document.querySelectorAll("#nav a").forEach((a) => {
    a.classList.toggle("active", a.dataset.route === name ||
      (name === "cve" && a.dataset.route === "affected") ||
      (name === "package" && a.dataset.route === "packages"));
  });
  $("#sidebar")?.classList.remove("open");

  const view = $("#view");
  view.innerHTML = `<div class="loading"><div class="spinner"></div>Loading…</div>`;
  try {
    if (name === "dashboard") await renderDashboard(view, route);
    else if (name === "affected") await renderFindings(view, route, "affected");
    else if (name === "cve") await renderCveDetail(view, route.parts[1]);
    else if (name === "packages") await renderPackages(view, route);
    else if (name === "package") await renderPackageDetail(view, route.parts[1], route.query.branch, route.query.spec);
    else if (name === "triage") await renderTriage(view, route);
    else if (name === "scan") await renderScan(view);
    else { location.hash = "#/"; }
  } catch (err) {
    view.innerHTML = `<div class="card error-box"><h2>Could not load this view</h2><p class="muted">${esc(err.message)}</p>
      <p class="muted small">If the dashboard is empty the snapshot has no data yet.</p></div>`;
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
    ["info", "Open exposures", fmtNum(stats.total_findings), `${fmtNum(stats.distinct_cves)} distinct CVEs`],
  ];

  const donutSegments = SEVERITIES
    .map((s) => ({ label: s, value: sev[s] || 0, color: SEV_COLORS[s] }))
    .filter((x) => x.value > 0);

  // The console lists open exposures only; anything already fixed or ruled out
  // is reported as a single excluded number, never as a finding.
  const statusSegments = [
    { label: "Open exposure", value: stats.affected, color: STATUS_COLORS.affected },
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
        <div class="card-head"><h2>Scope</h2>
          <span class="muted small">open exposures only</span></div>
        <div class="bar-stack">
          ${statusSegments.map((s) => `
            <span title="${s.label}: ${s.value}" style="background:${s.color};flex:${s.value}"></span>`).join("")}
        </div>
        <div class="bar-legend">
          ${statusSegments.map((s) => `<span><b>${fmtNum(s.value)}</b> ${esc(s.label)}</span>`).join("")}
        </div>
        <p class="muted small" style="margin:12px 0 0">
          ${fmtNum(stats.excluded_findings)} further findings are already fixed or ruled out on this
          distro and are not listed anywhere in this console.
        </p>
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
      <th>Patch</th><th>Confidence</th><th>Fixed in</th><th>Description</th>
    </tr></thead>
    <tbody>${items.map(findingRow).join("")}</tbody>
  </table></div>`;
}

function patchMark(f) {
  const pa = f.patch_availability || {};
  return pa.available
    ? `<span class="verdict-dot ok" title="${esc(pa.final_verdict || "Patch Available")}">✓</span>`
    : `<span class="verdict-dot no" title="${esc(pa.final_verdict || "No Patch Found")}">✕</span>`;
}

function findingRow(f) {
  const fix = f.fixed_version
    ? `<span class="ver">${esc(f.fixed_version)}</span>`
    : `<span class="muted small">unfixed</span>`;
  return `<tr class="clickable" data-cve="${esc(f.cve_id)}" data-spec="${esc(f.spec_path || "")}" data-branch="${esc(f.branch || "")}">
    <td><span class="cve-id">${esc(f.cve_id)}</span></td>
    <td><span class="pkg-name">${esc(f.package_name)}</span></td>
    <td><span class="ver">${esc(f.package_version)}</span></td>
    <td>${sevBadge(f.severity)}</td>
    <td>${patchMark(f)}</td>
    <td>${confBar(f.confidence)}</td>
    <td>${fix}</td>
    <td class="desc">${esc((f.description || "").slice(0, 190))}${(f.description || "").length > 190 ? "…" : ""}</td>
  </tr>`;
}

async function renderFindings(view, route, status) {
  const page = state.page[status || route.key] || 1;
  const q = route.query;  const params = {
    severity: q.severity || "", search: q.search || "",
    branch: q.branch || "", page, limit: 50,
  };
  const data = await api("/findings?" + qs(params));

  view.innerHTML = `
    <div class="toolbar">
      <input class="input search" id="f-search" placeholder="Search CVE, package, description…" value="${esc(q.search || "")}"/>
      <select class="select" id="f-sev">
        <option value="">All severities</option>
        ${SEVERITIES.map((s) => `<option value="${s}" ${q.severity === s ? "selected" : ""}>${s}</option>`).join("")}
      </select>
      <span class="muted small" style="margin-left:auto">${fmtNum(data.total)} open exposures</span>
    </div>
    ${data.items.length ? findingsTable(data.items) : `<div class="empty">No open exposures match these filters.</div>`}
    ${pagination(page, data.total, 50, route)}
  `;

  $("#f-search").addEventListener("keydown", (e) => {
    if (e.key === "Enter") updateQuery(route, { search: e.target.value, page: null });
  });
  $("#f-sev").addEventListener("change", (e) => updateQuery(route, { severity: e.target.value, page: null }));
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
  if (!cveId) { location.hash = "#/affected"; return; }
  state.stats = state.stats || await api("/stats");
  const data = await api(`/cves/${encodeURIComponent(cveId)}`);
  const enrichment = data.enrichment || {};
  const findings = data.findings || [];
  const primary = findings[0] || {};
  const sev = (enrichment.severity || primary.severity || "unknown").toLowerCase();
  const score = enrichment.cvss_score ?? primary.cvss_score;
  const vector = primary.cvss_vector || enrichment.cvss_vector || "";
  const published = enrichment.published || "";
  const desc = enrichment.description || primary.description || "No description available.";
  const refs = enrichment.references || primary.references || [];
  const links = (data.links && data.links.length) ? data.links : cveLinks(cveId);

  // The API serves open exposures only, so every finding here is affected.
  const affectedPkgs = findings;

  view.innerHTML = `
    <a class="backlink" href="#/affected">‹ Back to findings</a>
    <div class="cve-hero">
      <div class="card">
        <div class="card-head">
          <h2 class="cve-title">${esc(cveId)}
            <a class="cve-ext" href="${esc((links[3] || {}).url || "")}" target="_blank" rel="noopener" title="Open the CVE record">→</a>
          </h2>
          <div class="row-actions">${actionsMenu(primary, "cve")}</div>
        </div>
        <dl class="cve-meta">
          <dt>Original Vector</dt><dd class="mono small">${esc(vector || "—")}</dd>
          <dt>NVD Published Date</dt><dd>${esc(published ? fmtDate(published) : "—")}</dd>
        </dl>
        <div class="src-links">${links.map((l) => `<a class="src-link" href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.label)}</a>`).join('<span class="arrow">→</span>')}</div>
        <blockquote class="cve-desc">${esc(desc)}</blockquote>
        ${primary.evidence?.length ? `<details class="evidence-wrap"><summary>Verification notes</summary><ul class="evidence">${primary.evidence.map((e) => `<li>${esc(e)}</li>`).join("")}</ul></details>` : ""}
        ${refs.length ? `
        <details class="evidence-wrap">
          <summary>Advisory references (${refs.length})</summary>
          <div class="list">
            ${refs.slice(0, 15).map((r) => `
              <div class="list-item"><div class="grow">
                <h4>${esc(r.source || r.type || "reference")}</h4>
                <p>${extLink(r.url)}</p>
              </div></div>`).join("")}
          </div>
        </details>` : ""}
      </div>

      <div class="card triage-score">
        <div class="ts-label">Triaged Severity</div>
        <div class="ts-value sev-${esc(sev)}">${esc(sev)}</div>
        <div class="ts-row"><span>Triaged Score:</span><b>${score != null ? esc(score) : "—"}</b></div>
        <div class="ts-row"><span>Original Score:</span><b>${score != null ? esc(score) : "—"}</b></div>
        <p class="muted small">Please note that as part of the triage process, our security experts may adjust this verdict. Confidence ${Math.round((primary.confidence || 0) * 100)}%.</p>
      </div>
    </div>

    <div class="stack" style="margin-top:16px">
      ${patchAvailabilityCard(primary)}
      ${githubPrCard(primary)}
      ${triageInfoCard(primary)}
    </div>

    <div class="card" style="margin-top:16px">
      <div class="card-head"><h2>Affected packages (${affectedPkgs.length})</h2></div>
      ${affectedPkgs.length ? affectedPkgs.map(pkgFindingCard).join("") : `<p class="muted small">No package is currently affected by this CVE.</p>`}
    </div>

  `;

  bindTriageControls(view, primary);
}

/* --------------------- shared triage pieces ------------------------------ */
function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (isNaN(d)) return String(iso).slice(0, 10);
  return d.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

const CVE_TRACKERS = [
  ["Ubuntu", "https://ubuntu.com/security/{cve}"],
  ["Debian", "https://security-tracker.debian.org/tracker/{cve}"],
  ["Red Hat", "https://access.redhat.com/security/cve/{cve}"],
  ["Mitre", "https://www.cve.org/CVERecord?id={cve}"],
  ["OSV", "https://osv.dev/vulnerability/{cve}"],
];

function cveLinks(cveId) {
  const cve = (cveId || "").toUpperCase();
  if (!cve) return [];
  return CVE_TRACKERS.map(([label, url]) => ({
    label, url: url.replace("{cve}", cve),
  }));
}

function titleCase(value) {
  return String(value || "").replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

const RESOLUTION_KINDS = {
  completed: "ok", resolved: "ok", done: "ok",
  in_progress: "info", queued: "warn", open: "warn", disputed: "bad",
};

function pill(text, kind) {
  return `<span class="pill ${kind || "info"}">${esc(text)}</span>`;
}

function triageStatusPill(status) {
  return pill(titleCase(status || "open"), RESOLUTION_KINDS[status] || "info");
}

function resolutionPill(status) {
  return pill(titleCase(status), RESOLUTION_KINDS[status] || "info");
}

const ROW_REGISTRY = new Map();
let ROW_SEQ = 0;

function registerRow(f) {
  if (!f._domId) {
    f._domId = `row${++ROW_SEQ}`;
    ROW_REGISTRY.set(f._domId, f);
  }
  return f._domId;
}

function actionsMenu(f, scope) {
  const id = registerRow(f);
  const items = [];
  if (can("can_dispute")) items.push(`<button class="menu-item" data-action="dispute" data-row="${id}">Dispute</button>`);
  if (can("can_set_pr")) items.push(`<button class="menu-item" data-action="pr" data-row="${id}">Set GitHub PR</button>`);
  if (can("can_set_patch_verdict")) items.push(`<button class="menu-item" data-action="patch" data-row="${id}">Patch verdict</button>`);
  const title = items.length ? "Actions" : "Read-only — sign in as admin";
  return `<div class="actions-wrap" data-scope="${esc(scope || "")}">
    <button class="btn btn-sm actions-toggle" type="button" data-actions-toggle ${items.length ? "" : "disabled"}>Actions ▾</button>
    <div class="actions-menu" hidden>${items.join("") || '<span class="menu-empty">Sign in to act</span>'}</div>
  </div>`;
}

function patchAvailabilityCard(f) {
  const pa = f.patch_availability || {};
  const id = registerRow(f);
  const ok = String(pa.final_verdict || "").toLowerCase().includes("available");
  const possible = pa.possible_links || [];
  return `<div class="card">
    <div class="card-head"><h2>Patch Availability</h2>
      <button class="btn btn-sm btn-primary" type="button" data-deep data-row="${id}">Deep</button>
    </div>
    <div class="pa-grid">
      <div class="pa-left">
        <div class="pa-label">AI Verdict</div>
        <div class="pa-verdict">${esc(pa.ai_verdict || "—")} <span class="verdict-dot ${ok ? "ok" : "no"}">${ok ? "✓" : "✕"}</span></div>
        <div class="pa-label" style="margin-top:14px">AI Possible Patch Links</div>
        ${possible.length ? `<ul class="pa-links">${possible.slice(0, 6).map((u) => `<li>${extLink(u, u)}</li>`).join("")}</ul>` : '<p class="muted small">No patchable reference found.</p>'}
        <div class="pa-label" style="margin-top:14px">Analysis</div>
        <details class="evidence-wrap"><summary class="btn btn-sm">View</summary>
          <ul class="evidence">${(pa.analysis || []).map((a) => `<li>${esc(a)}</li>`).join("")}</ul>
        </details>
      </div>
      <div class="pa-right">
        <div class="pa-label">Final Verdict</div>
        <div class="pill-verdict ${ok ? "ok" : "no"}"><span class="verdict-dot ${ok ? "ok" : "no"}">${ok ? "✓" : "✕"}</span> ${esc(pa.final_verdict || "—")}</div>
        <div class="pa-row"><span>Patch Link</span><span>${pa.patch_link ? extLink(pa.patch_link, pa.patch_link) : '<span class="muted small">—</span>'}</span></div>
        <div class="pa-row"><span>Available Since</span><span>${esc(pa.available_since ? fmtDate(pa.available_since) : "—")}</span></div>
        ${pa.overridden ? '<p class="muted small">Verdict set manually during triage.</p>' : ""}
      </div>
    </div>
    <div class="deep-panel" data-deep-panel="${id}" hidden></div>
  </div>`;
}

function githubPrCard(f) {
  const t = f.triage || {};
  const num = t.github_pr_number;
  const link = num
    ? (t.github_pr_url
      ? `<a class="link mono" href="${esc(t.github_pr_url)}" target="_blank" rel="noopener">#${esc(num)}</a>`
      : `<span class="mono">#${esc(num)}</span>`)
    : '<span class="muted small">not set</span>';
  return `<div class="card">
    <div class="card-head"><h2>Github PR</h2></div>
    <div class="pa-grid">
      <div class="pa-left"><div class="pa-label">PR Number</div><div class="strong">${link}</div></div>
      <div class="pa-right"><div class="pa-label">Set by</div>
        <div class="strong">${esc(t.github_pr_set_by || "—")}${t.github_pr_set_at ? ` <span class="muted small">· ${esc(fmtDate(t.github_pr_set_at))}</span>` : ""}</div>
      </div>
    </div>
  </div>`;
}

function triageInfoCard(f) {
  const t = f.triage || {};
  const id = registerRow(f);
  const status = t.triage_status || (f.status === "affected" ? "open" : "completed");
  const comments = t.comments || [];
  return `<div class="card">
    <div class="card-head"><h2>Triage Information</h2>
      <span class="tag-list">${triageStatusPill(status)}${t.resolution_status ? resolutionPill(t.resolution_status) : ""}</span>
    </div>
    <div class="pa-grid">
      <div class="pa-left">
        <div class="pa-label">Status</div><div class="strong">${esc(titleCase(status))}</div>
        <div class="pa-label" style="margin-top:12px">Score</div><div class="strong">${f.cvss_score != null ? esc(f.cvss_score) : "—"}</div>
        <div class="pa-label" style="margin-top:12px">Triage Comments</div>
        <div class="comment-list">${comments.length
          ? comments.map((c) => `<div class="comment ${c.kind === "dispute" ? "dispute" : ""}"><span class="who">${esc(c.author || "admin")}</span><span>${esc(c.body)}</span><span class="when">${esc(fmtTime(c.created_at))}</span></div>`).join("")
          : '<p class="muted small">No triage comments yet.</p>'}</div>
        ${can("can_comment") ? `<div class="comment-form"><input class="input" data-comment-input="${id}" placeholder="Triage comment…"/><button class="btn btn-sm" data-comment-submit="${id}">Comment</button></div>` : `<p class="viewer-note" style="margin-top:10px"><b>Read-only.</b> Sign in as admin to comment or dispute.</p>`}
      </div>
      <div class="pa-right">
        <div class="pa-label">Vector</div><div class="mono small">${esc(f.cvss_vector || "—")}</div>
        <div class="pa-label" style="margin-top:12px">Severity</div><div>${sevBadge(f.severity)}</div>
        <div class="pa-label" style="margin-top:12px">Vuln ID</div><div class="mono">${esc(f.cve_id)}</div>
        <div class="pa-label" style="margin-top:12px">Owner</div><div class="strong">${esc(t.owner || "—")}</div>
      </div>
    </div>
  </div>`;
}

function deepPanelHtml(deep) {
  const d = deep || {};
  const files = d.affected_files || [];
  return `<div class="deep-body">
    <div class="pa-label">Affected files in the source tarball</div>
    ${files.length
      ? `<ul class="file-list">${files.map((name) => `<li class="mono">${esc(name)}</li>`).join("")}</ul>`
      : '<p class="muted small">No file list available for this CVE (no resolvable upstream fix commit).</p>'}
    <div class="pa-label" style="margin-top:12px">Source tarball</div>
    ${d.tarball
      ? `<p>${d.tarball.url ? extLink(d.tarball.url, d.tarball.name) : `<span class="mono">${esc(d.tarball.name)}</span>`}</p>`
      : '<p class="muted small">No source tarball declared in the .spec.</p>'}
    ${(d.backport_patches || []).length ? `<div class="pa-label" style="margin-top:12px">Backport patches</div>
      <ul class="pa-links">${d.backport_patches.map((p) => `<li>${p.url ? extLink(p.url, p.filename) : esc(p.filename)}</li>`).join("")}</ul>` : ""}
    <ul class="evidence" style="margin-top:12px">${(d.notes || []).map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
  </div>`;
}

async function toggleDeep(f, btn) {
  const id = registerRow(f);
  const panel = document.querySelector(`[data-deep-panel="${id}"]`);
  if (!panel) return;
  if (!panel.hidden) { panel.hidden = true; if (btn) btn.textContent = "Deep"; return; }
  panel.hidden = false;
  if (btn) { btn.disabled = true; }
  try {
    const params = qs({ branch: f.branch || "", spec: f.spec_path || "" });
    const deep = await api(`/cves/${encodeURIComponent(f.cve_id)}/deep` + (params ? `?${params}` : ""));
    panel.innerHTML = deepPanelHtml(deep);
  } catch (err) {
    panel.innerHTML = `<p class="muted small">${esc(err.message)}</p>`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

function bindTriageControls(scope, fallback) {
  const root = scope || document;
  root.querySelectorAll("[data-actions-toggle]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const menu = btn.parentElement.querySelector(".actions-menu");
      const open = menu && !menu.hidden;
      document.querySelectorAll(".actions-menu").forEach((m) => { m.hidden = true; });
      if (menu) menu.hidden = open;
    });
  });
  root.querySelectorAll("[data-action]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const f = ROW_REGISTRY.get(btn.dataset.row) || fallback;
      if (!f) return;
      const menu = btn.closest(".actions-menu");
      if (menu) menu.hidden = true;
      if (btn.dataset.action === "dispute") openDisputeModal(f, btn.dataset.row);
      else if (btn.dataset.action === "pr") openPrModal(f, btn.dataset.row);
      else if (btn.dataset.action === "patch") openPatchModal(f, btn.dataset.row);
    });
  });
  root.querySelectorAll("[data-deep]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.stopPropagation();
      const f = ROW_REGISTRY.get(btn.dataset.row) || fallback;
      if (f) toggleDeep(f, btn);
    });
  });
  root.querySelectorAll("[data-comment-submit]").forEach((btn) => {
    const submit = async () => {
      if (!requireCap("can_comment", "Read-only — triage comments need admin access.")) return;
      const id = btn.dataset.commentSubmit;
      const input = document.querySelector(`[data-comment-input="${id}"]`);
      const body = (input ? input.value : "").trim();
      if (!body) { toast("Write the comment first", true); return; }
      const f = ROW_REGISTRY.get(id) || fallback;
      if (!f) return;
      btn.disabled = true;
      try {
        await api("/triage/comment", {
          method: "POST",
          body: { cve_id: f.cve_id, branch: f.branch || "", spec_path: f.spec_path || "", body },
        });
        toast("Triage comment added");
        render();
      } catch (err) {
        btn.disabled = false;
        toast(err.message, true);
      }
    };
    btn.addEventListener("click", (e) => { e.stopPropagation(); submit(); });
  });
  root.querySelectorAll("[data-comment-input]").forEach((input) => {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const btn = root.querySelector(`[data-comment-submit="${input.dataset.commentInput}"]`);
        if (btn) btn.click();
      }
    });
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
  // The API serves open exposures; a package page never lists fixed CVEs.
  const affected = pkg.findings || [];
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

/* --------------------------------- triage -------------------------------- */
const GH_ICON = `<svg viewBox="0 0 16 16" width="13" height="13" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>`;

function patchCell(f) {
  const ok = (f.patch_availability || {}).available;
  return ok
    ? `<span class="verdict-dot ok" title="Patch Available">✓</span>`
    : `<span class="verdict-dot no" title="No Patch Found">✕</span>`;
}

function triageRow(f, detectedOn) {
  const t = f.triage || {};
  const id = registerRow(f);
  const status = t.triage_status || (f.status === "affected" ? "open" : "completed");
  const spec = blobUrl(f.spec_path, f.branch);
  return `<tr class="triage-row" data-row="${id}">
    <td><span class="pkg-name">${esc(f.package_name)}</span>
      ${spec ? `<a class="gh-icon" href="${esc(spec)}" target="_blank" rel="noopener" title="Open the .spec on GitHub">${GH_ICON}</a>` : ""}</td>
    <td class="muted small">${esc(detectedOn)}</td>
    <td><span class="chip">${esc(f.branch)}</span></td>
    <td>${patchCell(f)}</td>
    <td>${triageStatusPill(status)}</td>
    <td>${t.resolution_status ? resolutionPill(t.resolution_status) : '<span class="muted small">—</span>'}</td>
    <td><span class="ver">${esc(f.fixed_version || "—")}</span></td>
    <td class="muted small">${esc(t.available_since ? fmtDate(t.available_since) : ((f.patch_availability || {}).available_since ? fmtDate(f.patch_availability.available_since) : "—"))}</td>
    <td><a class="cve-id" href="#/cve/${esc(f.cve_id)}">${esc(f.cve_id)}</a></td>
    <td class="mono small">${esc(t.qualys_ids || "—")}</td>
    <td class="muted small">${esc(t.owner || "—")}</td>
    <td><button class="btn btn-sm btn-primary" type="button" data-deep data-row="${id}">Deep</button></td>
    <td>${actionsMenu(f, "triage")}</td>
    <td><button class="chevron" type="button" data-expand="${id}" aria-label="Expand">⌃</button></td>
  </tr>
  <tr class="expand-row" data-expand-for="${id}" hidden><td colspan="14">
    <div class="stack">${githubPrCard(f)}${patchAvailabilityCard(f)}${triageInfoCard(f)}</div>
  </td></tr>`;
}

function bindTriageTable(view) {
  view.querySelectorAll("[data-expand]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const id = btn.dataset.expand;
      const row = view.querySelector(`[data-expand-for="${id}"]`);
      if (!row) return;
      row.hidden = !row.hidden;
      btn.classList.toggle("open", !row.hidden);
    });
  });
  bindTriageControls(view);
}

async function renderTriage(view, route) {
  const q = route.query;
  state.stats = state.stats || await api("/stats");
  const page = state.page.triage || 1;
  // One queue: only CVEs this distro has not fixed yet.
  const data = await api("/triage?" + qs({ search: q.search || "", page, limit: 20 }));
  const last = state.stats.last_scan || {};
  const detectedOn = fmtDate(last.finished_at || last.started_at);
  view.innerHTML = `
    <div class="toolbar">
      <input class="input search" id="t-search" placeholder="Search CVE or package…" value="${esc(q.search || "")}"/>
      <span class="muted small" style="margin-left:auto">${fmtNum(data.total)} open exposures</span>
    </div>
    <div class="table-wrap"><table class="data triage-table">
      <thead><tr><th>Package</th><th>Detected On</th><th>Branch</th><th>Patch Available</th>
        <th>Triage Status</th><th>Resolution Status</th><th>Fixed Version</th><th>Fix Released On</th>
        <th>Vuln ID</th><th>Qualys IDs</th><th>Owner</th><th>Scan</th><th>Actions</th><th></th></tr></thead>
      <tbody>${data.items.map((f) => triageRow(f, detectedOn)).join("")}</tbody>
    </table></div>
    ${pagination(page, data.total, 20, route)}
  `;
  $("#t-search").addEventListener("keydown", (e) => {
    if (e.key === "Enter") updateQuery(route, { search: e.target.value, page: null });
  });
  bindPager(route);
  bindTriageTable(view);
}

/* --------------------------------- scan ---------------------------------- */
async function renderScan(view) {
  const status = await api("/scan/status");
  const history = await api("/scans");
  const canWrite = can("can_scan");
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
        <p class="viewer-note" style="margin-top:12px"><b>Read-only.</b> Scan history and the latest run are visible to everyone; starting a scan needs admin access.</p>`}
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
    if (!requireCap("can_scan", "Read-only — starting a scan needs admin access.")) return;
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

/* ------------------------------- events ---------------------------------- */
document.addEventListener("click", (e) => {
  // Any plain click closes an open Actions menu.
  document.querySelectorAll(".actions-menu").forEach((m) => { m.hidden = true; });
  if (e.target.closest("a,button,input,select,textarea")) return;
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
  if (!requireCap("can_scan", "Read-only — running a scan needs admin access.")) return;
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

/* --------------------------- access controls ----------------------------- */
const MODALS = ["#login-modal", "#dispute-modal", "#pr-modal", "#patch-modal"];

function openModal(id) {
  const m = $(id);
  if (!m) return;
  m.hidden = false;
}

function closeModal(id) {
  const m = $(id);
  if (m) m.hidden = true;
}

function closeAllModals() { MODALS.forEach(closeModal); }

const modalTarget = { rowId: null };

function openDisputeModal(f, rowId) {
  modalTarget.rowId = rowId;
  $("#dispute-target").innerHTML = `<b>${esc(f.cve_id)}</b> · ${esc(f.package_name || "")} <span class="mono">${esc(f.branch || "")}</span>`;
  $("#dispute-reason").value = "";
  openModal("#dispute-modal");
  setTimeout(() => $("#dispute-reason").focus(), 30);
}

function openPrModal(f, rowId) {
  modalTarget.rowId = rowId;
  const t = f.triage || {};
  $("#pr-target").innerHTML = `<b>${esc(f.cve_id)}</b> · the PR is opened against <span class="mono">${esc((state.stats?.repository || {}).patch_target_repo || "")}</span>`;
  $("#pr-number").value = t.github_pr_number || "";
  $("#pr-url").value = t.github_pr_url || "";
  openModal("#pr-modal");
  setTimeout(() => $("#pr-number").focus(), 30);
}

function openPatchModal(f, rowId) {
  modalTarget.rowId = rowId;
  const t = f.triage || {};
  const pa = f.patch_availability || {};
  $("#patch-target").innerHTML = `<b>${esc(f.cve_id)}</b> · current AI verdict: ${esc(pa.ai_verdict || "—")}`;
  $("#patch-verdict").value = t.final_verdict || "";
  $("#patch-link").value = t.patch_link || "";
  $("#patch-since").value = t.available_since || "";
  openModal("#patch-modal");
}

function modalFinding() {
  return ROW_REGISTRY.get(modalTarget.rowId) || null;
}

function showLoginError(message) {
  const el = $("#login-error");
  if (!el) return;
  el.textContent = message || "";
  el.hidden = !message;
}

function openLoginModal() {
  const methods = (state.roleInfo && state.roleInfo.methods) || {};
  $("#login-email").value = "";
  $("#login-password").value = "";
  showLoginError("");
  // Only offer the methods this server actually has configured.
  const canPassword = methods.password !== false;
  $("#login-submit").disabled = !canPassword;
  $("#login-email").disabled = !canPassword;
  $("#login-password").disabled = !canPassword;
  $("#login-github-wrap").hidden = !methods.github;
  $("#login-github-hint").textContent = methods.github
    ? `Only @${methods.github_login} may sign in this way.`
    : "";
  openModal("#login-modal");
  setTimeout(() => { if (canPassword) $("#login-email").focus(); }, 30);
}

$("#login-btn")?.addEventListener("click", openLoginModal);
$("#login-cancel")?.addEventListener("click", () => closeModal("#login-modal"));
$("#login-password")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("#login-submit").click();
});
$("#login-submit")?.addEventListener("click", async () => {
  const email = ($("#login-email").value || "").trim();
  const password = $("#login-password").value || "";
  showLoginError("");
  if (!email || !password) {
    showLoginError("Enter your admin email and password.");
    return;
  }
  const btn = $("#login-submit");
  btn.disabled = true;
  try {
    const info = await api("/auth/login", { method: "POST", body: { email, password } });
    setStoredKey(info.token);
    // Keep the advertised methods from the last /role call.
    applyRole({ ...(state.roleInfo || {}), ...info });
    closeModal("#login-modal");
    toast("Signed in as admin");
    render();
  } catch (err) {
    showLoginError(err.message);
  } finally {
    btn.disabled = false;
  }
});
$("#logout-btn")?.addEventListener("click", async () => {
  try { await api("/auth/logout", { method: "POST" }); } catch (_) { /* stale token */ }
  setStoredKey("");
  await resolveRole();
  toast("Signed out — back to read-only");
  render();
});

$("#dispute-cancel")?.addEventListener("click", () => closeModal("#dispute-modal"));
$("#dispute-submit")?.addEventListener("click", async () => {
  if (!requireCap("can_dispute", "Read-only — raising a dispute needs admin access.")) return;
  const f = modalFinding();
  const reason = ($("#dispute-reason").value || "").trim();
  if (!f) { toast("Pick a finding first", true); return; }
  if (!reason) { toast("A dispute needs a reason", true); return; }
  try {
    await api("/triage/dispute", {
      method: "POST",
      body: { cve_id: f.cve_id, branch: f.branch || "", spec_path: f.spec_path || "", reason },
    });
    closeModal("#dispute-modal");
    toast("Dispute raised — the reason is now under the triage comments");
    render();
  } catch (err) {
    toast(err.message, true);
  }
});

$("#pr-cancel")?.addEventListener("click", () => closeModal("#pr-modal"));
$("#pr-submit")?.addEventListener("click", async () => {
  if (!requireCap("can_set_pr", "Read-only — setting the GitHub PR needs the automation identity or admin.")) return;
  const f = modalFinding();
  const number = ($("#pr-number").value || "").trim();
  if (!f) { toast("Pick a finding first", true); return; }
  if (!number) { toast("Enter the PR number", true); return; }
  try {
    await api("/triage/github-pr", {
      method: "POST",
      body: {
        cve_id: f.cve_id, branch: f.branch || "", spec_path: f.spec_path || "",
        number, url: ($("#pr-url").value || "").trim(),
      },
    });
    closeModal("#pr-modal");
    toast("GitHub PR recorded");
    render();
  } catch (err) {
    toast(err.message, true);
  }
});

$("#patch-cancel")?.addEventListener("click", () => closeModal("#patch-modal"));
$("#patch-submit")?.addEventListener("click", async () => {
  if (!requireCap("can_set_patch_verdict", "Read-only — patch verdicts need admin access.")) return;
  const f = modalFinding();
  if (!f) { toast("Pick a finding first", true); return; }
  try {
    await api("/triage/patch", {
      method: "POST",
      body: {
        cve_id: f.cve_id, branch: f.branch || "", spec_path: f.spec_path || "",
        final_verdict: $("#patch-verdict").value,
        patch_link: ($("#patch-link").value || "").trim(),
        available_since: ($("#patch-since").value || "").trim(),
      },
    });
    closeModal("#patch-modal");
    toast("Patch verdict saved");
    render();
  } catch (err) {
    toast(err.message, true);
  }
});

MODALS.forEach((id) => {
  $(id)?.addEventListener("click", (e) => {
    if (e.target.id === id.slice(1)) closeModal(id);
  });
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
  // A GitHub sign-in comes back as ``#vulnex_token=…``; keep it and clean the URL
  // so the token never sticks around in the address bar or history.
  const handed = location.hash.match(/vulnex_token=([A-Za-z0-9_\-]+)/);
  if (handed) {
    setStoredKey(handed[1]);
    history.replaceState(null, "", location.pathname + location.search + "#/triage");
  }
  // Warm the static snapshot so the first navigation is instant on Pages.
  if (STATIC) staticBundle().catch(() => {});
  // Resolve the access tier before the first paint so permission-gated controls
  // never flash for a viewer.
  await resolveRole();
  render();
  setInterval(async () => {
    try { state.stats = await api("/stats"); updateChrome(); } catch (_) {}
  }, 60000);
});
