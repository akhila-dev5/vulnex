import React, { useCallback, useEffect, useState } from "react";
import {
  Activity, AlertCircle, AlertTriangle, ArrowUpRight, CheckCircle2,
  ChevronDown, ChevronRight, Clock3, FileSearch, Filter, GitPullRequest,
  LayoutDashboard, LogIn, LogOut, Package, RefreshCw, Search, ShieldCheck,
  SlidersHorizontal, ShieldAlert, X,
} from "lucide-react";

type RoleInfo = {
  role: "viewer" | "admin" | "automation";
  identity?: { identity?: string; email?: string };
  methods?: { google?: boolean; google_email?: string };
  write_enabled?: boolean;
  can_comment?: boolean;
  can_dispute?: boolean;
  can_triage?: boolean;
  can_scan?: boolean;
  can_set_patch_verdict?: boolean;
  can_set_pr?: boolean;
};
type Finding = {
  cve_id: string; package_name: string; package_version?: string; branch: string;
  spec_path: string; severity?: string; cvss_score?: number | null; description?: string;
  status?: string; detected_on?: string; triage?: Record<string, unknown> | null;
  patch_availability?: { ai_verdict?: string; patch_link?: string; available_since?: string };
};
type PageResult<T> = { items: T[]; total: number; page?: number; limit?: number };
type Stats = {
  total_packages?: number; total_findings?: number; distinct_cves?: number;
  severity?: Record<string, number>; last_scan?: { finished_at?: string; started_at?: string; branches?: string };
  repository?: { owner?: string; repo?: string; branches?: string[] };
};

const API = "/api";
const severityClass = (value?: string) => {
  const v = (value || "unknown").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(v) ? v : "unknown";
};
const messageOf = (error: unknown) => error instanceof Error ? error.message : "Unexpected request error";

async function request<T>(path: string, init: RequestInit = {}, token = ""): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("X-VULNEX-Key", token);
  const response = await fetch(API + path, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    let detail = response.statusText || "Request failed";
    try { detail = (await response.json()).detail || detail; } catch { /* Non-JSON errors. */ }
    throw new Error(detail);
  }
  return response.json() as Promise<T>;
}

function StatusPill({ children, tone = "neutral" }: { children: React.ReactNode; tone?: string }) {
  return <span className={`status-pill ${tone}`}>{children}</span>;
}

function App() {
  const [roleInfo, setRoleInfo] = useState<RoleInfo>({ role: "viewer" });
  const [token, setToken] = useState("");
  const [stats, setStats] = useState<Stats>({});
  const [rows, setRows] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const [branch, setBranch] = useState("3.0");
  const [page, setPage] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [toast, setToast] = useState("");
  const [activeTab, setActiveTab] = useState<"triage" | "affected" | "packages">("triage");
  const [expandedKey, setExpandedKey] = useState("");
  const [modal, setModal] = useState<"dispute" | "comment" | "patch" | "pr" | null>(null);
  const [target, setTarget] = useState<Finding | null>(null);
  const [formText, setFormText] = useState("");
  const [patchLink, setPatchLink] = useState("");
  const [patchVerdict, setPatchVerdict] = useState("");
  const [availableSince, setAvailableSince] = useState("");
  const [prNumber, setPrNumber] = useState("");
  const [prUrl, setPrUrl] = useState("");
  const [scanStatus, setScanStatus] = useState("idle");
  const [packageRows, setPackageRows] = useState<Array<{name: string; version?: string; branch?: string; spec_path?: string}>>([]);
  const [packageTotal, setPackageTotal] = useState(0);

  const canAdmin = roleInfo.role === "admin";
  const canWrite = Boolean(roleInfo.write_enabled && canAdmin);

  const load = useCallback(async () => {
    setBusy(true);
    setError("");
    try {
      const nextStats = await request<Stats>("/stats", {}, token);
      const [findings, packages] = await Promise.all([
        request<PageResult<Finding>>("/triage?" + new URLSearchParams({
          search: query, page: String(page), limit: "25",
        }).toString(), {}, token),
        request<PageResult<{name: string; version?: string; branch?: string; spec_path?: string}>>("/packages?" + new URLSearchParams({
          search: query, branch: "3.0", page: String(page), limit: "25",
        }).toString(), {}, token),
      ]);
      setStats(nextStats);
      const filtered = severity === "all"
        ? findings.items
        : findings.items.filter(item => severityClass(item.severity) === severity);
      const branchFiltered = filtered.filter(item => item.branch === "3.0");
      setRows(activeTab === "packages" ? [] : branchFiltered);
      setTotal(activeTab === "packages" ? packages.total : branchFiltered.length);
      setPackageRows(packages.items);
      setPackageTotal(packages.total);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }, [token, query, severity, branch, page, activeTab]);

  useEffect(() => {
    const handoff = window.location.hash.match(/vulnex_token=([A-Za-z0-9_-]+)/);
    if (handoff) {
      const newToken = handoff[1];
      setToken(newToken);
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
      void request<RoleInfo>("/role", {}, newToken).then(setRoleInfo).catch(() => setRoleInfo({ role: "viewer" }));
      return;
    }
    const timer = window.setTimeout(() => {
      void request<RoleInfo>("/role", {}, token).then(setRoleInfo).catch(() => setRoleInfo({ role: "viewer" }));
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => { void load(); }, [load]);

  const refresh = () => { void load(); };

  const submitTriage = async () => {
    if (!target || !modal) return;
    const ref = { cve_id: target.cve_id, branch: target.branch, spec_path: target.spec_path };
    const requestBody: Record<string, string> = { ...ref };
    let path = "";
    if (modal === "dispute") { path = "/triage/dispute"; requestBody.reason = formText.trim(); }
    if (modal === "comment") { path = "/triage/comment"; requestBody.body = formText.trim(); }
    if (modal === "patch") {
      path = "/triage/patch"; requestBody.final_verdict = patchVerdict;
      requestBody.patch_link = patchLink.trim(); requestBody.available_since = availableSince.trim();
    }
    if (modal === "pr") {
      path = "/triage/github-pr"; requestBody.number = prNumber.trim(); requestBody.url = prUrl.trim();
    }
    try {
      await request(path, { method: "POST", body: JSON.stringify(requestBody) }, token);
      setToast(modal === "dispute" ? "Dispute recorded" : modal === "comment" ? "Comment saved" : modal === "patch" ? "Patch verdict updated" : "GitHub PR recorded");
      setModal(null); setTarget(null); setFormText(""); await load();
    } catch (e) { setToast(messageOf(e)); }
  };

  const runScan = async () => {
    if (!canWrite) return;
    setScanStatus("starting");
    try {
      await request("/scan", { method: "POST", body: JSON.stringify({ branches: ["3.0"] }) }, token);
      setScanStatus("running"); setToast("Azure Linux 3.0 scan started");
    } catch (e) { setScanStatus("idle"); setToast(messageOf(e)); }
  };

  const openAction = (action: "dispute" | "comment" | "patch" | "pr", row: Finding) => {
    setTarget(row); setModal(action); setFormText("");
    setPatchVerdict(String(row.triage?.final_verdict || ""));
    setPatchLink(row.patch_availability?.patch_link || "");
    setAvailableSince(String(row.patch_availability?.available_since || ""));
    setPrNumber(String(row.triage?.github_pr_number || ""));
    setPrUrl(String(row.triage?.github_pr_url || ""));
  };

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="#/">
          <span className="brand-mark"><ShieldCheck size={22} /></span>
          <span><strong>Vulnex</strong><small>Security Intelligence</small></span>
        </a>
        <div className="scope-card">
          <span className="scope-dot" /><div><small>SCAN SCOPE</small><strong>Azure Linux · 3.0</strong></div>
          <StatusPill tone="good">Active</StatusPill>
        </div>
        <nav className="side-nav" aria-label="Main navigation">
          <button className={activeTab === "triage" ? "active" : ""} onClick={() => { setActiveTab("triage"); setPage(1); }}><LayoutDashboard size={17} /> Dashboard & triage</button>
          <button className={activeTab === "affected" ? "active" : ""} onClick={() => { setActiveTab("affected"); setPage(1); }}><ShieldAlert size={17} /> Affected findings</button>
          <button className={activeTab === "packages" ? "active" : ""} onClick={() => { setActiveTab("packages"); setPage(1); }}><Package size={17} /> Packages</button>
        </nav>
        <div className="sidebar-bottom">
          <div className="source-mini"><Activity size={16} /><span>Azure Linux source</span><b>3.0</b></div>
          <small>Read-only for guests · Admin triage enabled</small>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div className="mobile-brand"><ShieldCheck size={20} /><b>Vulnex</b></div>
          <div className="heading">
            <h1>{activeTab === "triage" ? "Security overview" : activeTab === "affected" ? "Affected findings" : "Package inventory"}</h1>
            <p>Security findings, patch availability and review history for Azure Linux 3.0.</p>
          </div>
          <div className="top-actions">
            <StatusPill tone={canWrite ? "good" : "neutral"}>{canWrite ? "Administrator" : "Guest · read-only"}</StatusPill>
            {canWrite ? <button className="btn secondary" onClick={() => { setToken(""); setRoleInfo({ role: "viewer" }); void request("/auth/logout", { method: "POST" }, token); }}><LogOut size={16} /> Sign out</button>
            : roleInfo.role !== "automation" && <a className="btn primary" href="/api/auth/google"><LogIn size={16} /> Sign in with Google</a>}
            <button className="icon-btn" title="Refresh data" onClick={refresh} disabled={busy}><RefreshCw size={17} /></button>
          </div>
        </header>

        <section className="summary-grid">
          <article className="metric-card"><span className="metric-icon blue"><Package size={18} /></span><small>Packages scanned</small><strong>{(stats.total_packages ?? 0).toLocaleString()}</strong><span>Azure Linux 3.0</span></article>
          <article className="metric-card"><span className="metric-icon red"><ShieldAlert size={18} /></span><small>Open findings</small><strong>{(stats.total_findings ?? total).toLocaleString()}</strong><span>Current snapshot</span></article>
          <article className="metric-card"><span className="metric-icon amber"><AlertTriangle size={18} /></span><small>High severity</small><strong>{((stats.severity?.critical ?? 0) + (stats.severity?.high ?? 0)).toLocaleString()}</strong><span>Critical + high</span></article>
          <article className="metric-card"><span className="metric-icon green"><CheckCircle2 size={18} /></span><small>Last completed scan</small><strong>{stats.last_scan?.finished_at ? new Date(stats.last_scan.finished_at).toLocaleDateString() : "—"}</strong><span>{stats.last_scan?.branches || "3.0 only"}</span></article>
        </section>

        <section className="toolbar-panel">
          <div className="search-field"><Search size={17} /><input value={query} onChange={e => { setQuery(e.target.value); setPage(1); }} placeholder="Search CVE or package name…" aria-label="Search CVE or package name" /></div>
          <label className="filter-select"><Filter size={15} /><span>Severity</span><select value={severity} onChange={e => { setSeverity(e.target.value); setPage(1); }}><option value="all">All severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></label>
          <label className="filter-select"><SlidersHorizontal size={15} /><span>Branch</span><select value={branch} onChange={e => { setBranch(e.target.value); setPage(1); }}><option value="3.0">3.0</option></select></label>
          <button className="btn secondary" onClick={refresh}><RefreshCw size={15} /> Apply filters</button>
        </section>

        {error && <div className="alert error"><AlertCircle size={17} />{error}</div>}
        <section className="table-card">
          <div className="table-head">
            <div><h2>{activeTab === "triage" ? "Triage queue" : activeTab === "affected" ? "Affected findings" : "Packages"}</h2><p>{total.toLocaleString()} result{total === 1 ? "" : "s"} · Azure Linux 3.0</p></div>
            <div className="head-meta"><span><Clock3 size={14} /> {stats.last_scan?.finished_at ? new Date(stats.last_scan.finished_at).toLocaleString() : "Waiting for first scan"}</span><button className="icon-btn" onClick={runScan} disabled={!canWrite || scanStatus === "running"} title="Run a 3.0 scan"><Activity size={16} /></button></div>
          </div>
          {busy ? <div className="empty-state"><RefreshCw className="spin" /> Loading vulnerability records…</div>
          : activeTab === "packages" ? <div className="table-scroll"><table>
            <thead><tr><th>Package</th><th>Version</th><th>Branch</th><th>Spec path</th></tr></thead>
            <tbody>{packageRows.map((pkg, index) => <tr key={pkg.spec_path || pkg.name + index}><td><strong>{pkg.name}</strong></td><td>{pkg.version || "—"}</td><td><code>{pkg.branch || "3.0"}</code></td><td className="spec-path">{pkg.spec_path || "—"}</td></tr>)}</tbody>
          </table></div>
          : rows.length === 0 ? <div className="empty-state"><FileSearch size={26} /><strong>No findings in this view</strong><span>Try another search or run a fresh scan for branch 3.0.</span></div>
          : <div className="table-scroll"><table>
            <thead><tr><th>Vulnerability / package</th><th>Branch</th><th>Severity</th><th>Patch availability</th><th>Triage status</th><th>Resolution</th><th>Owner</th><th>Actions</th><th /></tr></thead>
            <tbody>{rows.map(row => {
              const key = [row.cve_id, row.branch, row.spec_path].join("::");
              const triage = row.triage || {};
              return <React.Fragment key={key}>
                <tr>
                  <td><button className="link-button" onClick={() => setExpandedKey(expandedKey === key ? "" : key)}><strong>{row.package_name || "Unknown package"}</strong><small>{row.package_version || row.cve_id}</small></button><a className="sub-link" href={`#/cve/${encodeURIComponent(row.cve_id)}`}>{row.cve_id} <ArrowUpRight size={12} /></a></td>
                  <td><code>{row.branch}</code></td><td><StatusPill tone={severityClass(row.severity)}>{row.severity || "Unknown"}</StatusPill></td>
                  <td><StatusPill tone={String(row.patch_availability?.ai_verdict || "").toLowerCase().includes("available") ? "good" : "warning"}>{row.patch_availability?.ai_verdict || "Not analysed"}</StatusPill>{row.patch_availability?.patch_link && <a className="sub-link" href={row.patch_availability.patch_link} target="_blank" rel="noreferrer">Patch link <ArrowUpRight size={12} /></a>}</td>
                  <td>{String(triage.triage_status || "Untriaged")}</td><td>{String(triage.resolution_status || row.status || "In progress")}</td><td>{String(triage.owner || "—")}</td>
                  <td><div className="action-wrap">
                    <button className="btn action-btn" onClick={() => setExpandedKey(expandedKey === key ? "" : key)}><FileSearch size={14} /> Deep</button>
                    <div className="action-menu">
                      <button disabled={!canAdmin} onClick={() => openAction("pr", row)}><GitPullRequest size={14} /> Set GitHub PR</button>
                      <button disabled={!canAdmin} onClick={() => openAction("patch", row)}><CheckCircle2 size={14} /> Patch verdict</button>
                      <button disabled={!canAdmin} onClick={() => openAction("comment", row)}><Activity size={14} /> Add comment</button>
                      <button disabled={!canAdmin} onClick={() => openAction("dispute", row)}><AlertTriangle size={14} /> Dispute</button>
                    </div>
                  </div></td>
                  <td><button className="icon-btn" onClick={() => setExpandedKey(expandedKey === key ? "" : key)} aria-label="Expand row">{expandedKey === key ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></td>
                </tr>
                {expandedKey === key && <tr className="expanded"><td colSpan={9}>
                  <div className="expanded-grid">
                    <div><small>AI verdict</small><strong>{row.patch_availability?.ai_verdict || "No verdict recorded"}</strong><small>Source package specification</small><a href={`https://github.com/akhila-dev5/azurelinux-test/blob/3.0/${row.spec_path}`} target="_blank" rel="noreferrer">{row.spec_path || "Not available"}</a></div>
                    <div><small>Finding</small><strong>{row.cve_id}</strong><p>{row.description || "The source does not provide a description for this finding."}</p><small>Patch link</small>{row.patch_availability?.patch_link ? <a href={row.patch_availability.patch_link} target="_blank" rel="noreferrer">{row.patch_availability.patch_link}</a> : "No patch link found in current record."}</div>
                  </div>
                </td></tr>}
              </React.Fragment>;
            })}</tbody>
          </table></div>}
          <div className="pagination"><span>Page {page} · {(activeTab === "packages" ? packageTotal : total).toLocaleString()} rows</span><div><button className="btn secondary" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1 || busy}>Previous</button><button className="btn secondary" onClick={() => setPage(p => p + 1)} disabled={busy || (activeTab === "packages" ? packageRows.length < 25 : rows.length < 25)}>Next</button></div></div>
        </section>
      </main>

      {modal && target && <div className="modal-backdrop" role="presentation" onClick={e => { if (e.target === e.currentTarget) setModal(null); }}>
        <section className="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title">
          <button className="modal-close icon-btn" aria-label="Close" onClick={() => setModal(null)}><X size={16} /></button>
          <small>TRIAGE ACTION · {target.cve_id}</small>
          <h2 id="modal-title">{modal === "dispute" ? "Dispute finding" : modal === "comment" ? "Add triage comment" : modal === "patch" ? "Patch availability" : "Set GitHub pull request"}</h2>
          {modal === "dispute" || modal === "comment" ? <label>Details<textarea value={formText} onChange={e => setFormText(e.target.value)} rows={5} placeholder={modal === "dispute" ? "Explain why this verdict should be reviewed…" : "Add a comment to the triage history…"} /></label> : null}
          {modal === "patch" && <><label>Final verdict<select value={patchVerdict} onChange={e => setPatchVerdict(e.target.value)}><option value="">No override</option><option>Patch Available</option><option>No Patch Found</option></select></label><label>Patch link<input value={patchLink} onChange={e => setPatchLink(e.target.value)} /></label><label>Available since<input type="date" value={availableSince} onChange={e => setAvailableSince(e.target.value)} /></label></>}
          {modal === "pr" && <><label>PR number<input value={prNumber} onChange={e => setPrNumber(e.target.value)} placeholder="19015" /></label><label>PR URL (optional)<input value={prUrl} onChange={e => setPrUrl(e.target.value)} placeholder="https://github.com/…" /></label></>}
          <div className="modal-actions"><button className="btn secondary" onClick={() => setModal(null)}>Cancel</button><button className="btn primary" onClick={submitTriage} disabled={!canAdmin || ((modal === "comment" || modal === "dispute") && !formText.trim())}>Save changes</button></div>
        </section>
      </div>}
      {toast && <div className="toast" role="status"><CheckCircle2 size={16} />{toast}<button onClick={() => setToast("")} aria-label="Dismiss"><X size={14} /></button></div>}
    </div>
  );
}

export default App;
