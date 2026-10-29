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
type DeepView = { cve_id?: string; package_name?: string; package_version?: string; branch?: string; spec_path?: string; spec_url?: string; tarball?: { name?: string; url?: string; available?: boolean | null } | null; affected_files?: Array<string | { path?: string; file?: string; url?: string; name?: string }>; backport_patches?: Array<{ filename?: string; url?: string; present?: boolean | null }>; notes?: string[] };
type CveDetail = { cve_id?: string; findings?: Finding[]; enrichment?: { description?: string; published?: string; modified?: string; cvss_score?: number; severity?: string; references?: Array<{ url?: string; name?: string }> } | null; links?: Array<{ label: string; url: string }> };
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
  const [actionMenuKey, setActionMenuKey] = useState("");
  const [deepTarget, setDeepTarget] = useState<Finding | null>(null);
  const [deepData, setDeepData] = useState<DeepView | null>(null);
  const [deepBusy, setDeepBusy] = useState(false);
  const [deepError, setDeepError] = useState("");
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [detailBusy, setDetailBusy] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [patchFilter, setPatchFilter] = useState("all");
  const [triageFilter, setTriageFilter] = useState("all");
  const [resolutionFilter, setResolutionFilter] = useState("all");
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
      const params = new URLSearchParams({ search: query.trim(), branch, page: String(page), limit: "25" });
      if (severity !== "all") params.set("severity", severity);
      const [findings, packages] = await Promise.all([
        request<PageResult<Finding>>("/findings?" + params.toString(), {}, token),
        request<PageResult<{name: string; version?: string; branch?: string; spec_path?: string}>>("/packages?" + new URLSearchParams({
          search: query.trim(), branch, page: String(page), limit: "25",
        }).toString(), {}, token),
      ]);
      setStats(nextStats);
      let visible = findings.items;
      if (patchFilter !== "all") {
        visible = visible.filter(item => {
          const patch = item.patch_availability;
          const available = Boolean(patch?.available);
          return patchFilter === "available" ? available : patchFilter === "unavailable" ? patch?.applicable === true && !available : !patch?.applicable || patch?.ai_verdict === "Unknown";
        });
      }
      if (triageFilter !== "all") visible = visible.filter(item => String(item.triage?.triage_status || "open").toLowerCase() === triageFilter);
      if (resolutionFilter !== "all") visible = visible.filter(item => String(item.triage?.resolution_status || item.status || "").toLowerCase() === resolutionFilter);
      setRows(activeTab === "packages" ? [] : visible);
      setTotal(activeTab === "packages" ? packages.total : findings.total);
      setPackageRows(packages.items);
      setPackageTotal(packages.total);
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  }, [token, query, severity, branch, page, activeTab, patchFilter, triageFilter, resolutionFilter]);

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

  const openDeep = async (row: Finding) => {
    setDeepTarget(row); setDeepData(null); setDeepError(""); setDeepBusy(true);
    try {
      const params = new URLSearchParams({ branch: row.branch || "", spec: row.spec_path || "" });
      const data = await request<DeepView>(`/cves/${encodeURIComponent(row.cve_id)}/deep?${params.toString()}`, {}, token);
      setDeepData(data);
    } catch (e) { setDeepError(messageOf(e)); }
    finally { setDeepBusy(false); }
  };

  const openDetail = async (cveId: string) => {
    setDetail(null); setDetailError(""); setDetailBusy(true);
    try {
      const data = await request<CveDetail>(`/cves/${encodeURIComponent(cveId)}?enrich=false`, {}, token);
      setDetail(data);
    } catch (e) { setDetailError(messageOf(e)); }
    finally { setDetailBusy(false); }
  };

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
          <button className={activeTab === "triage" ? "active" : ""} onClick={() => { setActiveTab("triage"); setPage(1); }}><LayoutDashboard size={17} /> Dashboard</button>
          <button className={activeTab === "affected" ? "active" : ""} onClick={() => { setActiveTab("affected"); setPage(1); }}><ShieldAlert size={17} /> CVEs / affected</button>
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
          <label className="filter-select"><SlidersHorizontal size={15} /><span>Branch</span><select value={branch} onChange={e => { setBranch(e.target.value); setPage(1); }}><option value="3.0">3.0</option><option value="4.0">4.0</option></select></label>
          <label className="filter-select"><span>Patch</span><select value={patchFilter} onChange={e => { setPatchFilter(e.target.value); setPage(1); }}><option value="all">Any patch state</option><option value="available">Available</option><option value="unavailable">Not found</option><option value="unknown">Unknown</option></select></label>
          <label className="filter-select"><span>Triage</span><select value={triageFilter} onChange={e => { setTriageFilter(e.target.value); setPage(1); }}><option value="all">Any triage</option><option value="open">Open</option><option value="in_progress">In progress</option><option value="triaged">Triaged</option><option value="disputed">Disputed</option></select></label>
          <label className="filter-select"><span>Resolution</span><select value={resolutionFilter} onChange={e => { setResolutionFilter(e.target.value); setPage(1); }}><option value="all">Any resolution</option><option value="affected">Affected</option><option value="disputed">Disputed</option><option value="in_progress">In progress</option><option value="published">Published</option></select></label>
          <button className="btn secondary" onClick={() => { setQuery(""); setSeverity("all"); setBranch("3.0"); setPatchFilter("all"); setTriageFilter("all"); setResolutionFilter("all"); setPage(1); }}><X size={15} /> Clear filters</button>
          <button className="btn secondary" onClick={refresh}><RefreshCw size={15} /> Apply</button>
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
                  <td><button className="link-button" onClick={() => void openDetail(row.cve_id)}><strong>{row.cve_id}</strong><small>{row.package_name || "Unknown package"} · {row.package_version || "version unavailable"}</small></button></td>
                  <td><code>{row.branch}</code></td><td><StatusPill tone={severityClass(row.severity)}>{row.severity || "Unknown"}</StatusPill></td>
                  <td><StatusPill tone={row.patch_availability?.available ? "good" : row.patch_availability?.applicable === false ? "neutral" : "warning"}>{row.patch_availability?.available ? "Candidate found" : row.patch_availability?.applicable === false ? "Not applicable" : "Unknown"}</StatusPill>{row.patch_availability?.patch_link && <a className="sub-link" href={row.patch_availability.patch_link} target="_blank" rel="noopener noreferrer">Evidence link <ArrowUpRight size={12} /></a>}</td>
                  <td>{String(triage.triage_status || "Untriaged")}</td><td>{String(triage.resolution_status || row.status || "In progress")}</td><td>{String(triage.owner || "—")}</td>
                  <td><div className="action-wrap">
                    <button className="btn action-btn" onClick={() => void openDeep(row)}><FileSearch size={14} /> Deep</button>
                    <button className="btn action-btn" aria-expanded={actionMenuKey === key} onClick={() => setActionMenuKey(actionMenuKey === key ? "" : key)}>Actions <ChevronDown size={13} /></button>
                    {actionMenuKey === key && <div className="action-popover" role="menu">
                      <button role="menuitem" disabled={!canAdmin} onClick={() => { setActionMenuKey(""); openAction("pr", row); }}><GitPullRequest size={14} /> Set GitHub PR</button>
                      <button role="menuitem" disabled={!canAdmin} onClick={() => { setActionMenuKey(""); openAction("dispute", row); }}><AlertTriangle size={14} /> Dispute</button>
                    </div>}
                  </div></td>
                  <td><button className="icon-btn" onClick={() => setExpandedKey(expandedKey === key ? "" : key)} aria-label="Expand row">{expandedKey === key ? <ChevronDown size={16} /> : <ChevronRight size={16} />}</button></td>
                </tr>
                {expandedKey === key && <tr className="expanded"><td colSpan={9}>
                  <div className="expanded-grid">
                    <div><small>Patch evidence</small><strong>{row.patch_availability?.available ? "Candidate patch link found — not independently verified" : "Insufficient evidence to confirm a patch"}</strong><small>Source package specification</small>{row.spec_path ? <a href={`https://github.com/akhila-dev5/azurelinux-test/blob/${encodeURIComponent(row.branch)}/${row.spec_path}`} target="_blank" rel="noopener noreferrer">{row.spec_path}</a> : <span>Not available</span>}</div>
                    <div><small>Finding</small><strong>{row.cve_id}</strong><p>{row.description || "The approved source does not provide a description for this finding."}</p><small>Recorded patch result</small>{row.patch_availability?.patch_link ? <a href={row.patch_availability.patch_link} target="_blank" rel="noopener noreferrer">{row.patch_availability.patch_link}</a> : <span>Not recorded</span>}</div>
                  </div>
                </td></tr>}
              </React.Fragment>;
            })}</tbody>
          </table></div>}
          <div className="pagination"><span>Page {page} · {(activeTab === "packages" ? packageTotal : total).toLocaleString()} rows</span><div><button className="btn secondary" onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page <= 1 || busy}>Previous</button><button className="btn secondary" onClick={() => setPage(p => p + 1)} disabled={busy || (activeTab === "packages" ? packageRows.length < 25 : rows.length < 25)}>Next</button></div></div>
        </section>
      </main>

      {(deepTarget || detailBusy || detail || detailError) && <div className="modal-backdrop" role="presentation" onClick={e => { if (e.target === e.currentTarget) { setDeepTarget(null); setDetail(null); setDetailError(""); } }}>
        <section className="modal-card wide-modal" role="dialog" aria-modal="true" aria-labelledby="detail-modal-title">
          <button className="modal-close icon-btn" aria-label="Close" onClick={() => { setDeepTarget(null); setDeepData(null); setDetail(null); setDetailError(""); }}><X size={16} /></button>
          {deepTarget ? <>
            <small>DEEP INSPECTION · {deepTarget.branch}</small><h2 id="detail-modal-title">{deepTarget.cve_id} · {deepTarget.package_name}</h2>
            {deepBusy ? <div className="empty-state"><RefreshCw className="spin" /> Loading affected-file evidence…</div>
              : deepError ? <div className="alert error"><AlertCircle size={16} />{deepError}<button className="btn secondary" onClick={() => void openDeep(deepTarget)}>Retry</button></div>
              : <div className="detail-sections">
                <section><h3>Affected files</h3>{deepData?.affected_files?.length ? <div className="evidence-list">{deepData.affected_files.map((file, i) => { const path = typeof file === "string" ? file : (file.path || file.file || file.name || "Path not available"); const url = typeof file === "string" ? "" : file.url || ""; return <div key={path + i}><code>{path}</code>{url && <a href={url} target="_blank" rel="noopener noreferrer">Source evidence <ArrowUpRight size={12} /></a>}</div>; })}</div> : <p className="muted">No affected-file information available from the recorded source evidence.</p>}</section>
                <section><h3>Source artifact</h3>{deepData?.tarball?.name ? <div><strong>{deepData.tarball.name}</strong>{deepData.tarball.url && <p><a href={deepData.tarball.url} target="_blank" rel="noopener noreferrer">Open source tarball <ArrowUpRight size={12} /></a></p>}<small>Availability: {deepData.tarball.available == null ? "Unknown" : deepData.tarball.available ? "Available" : "Not available"}</small></div> : <p className="muted">No source tarball recorded.</p>}</section>
                <section><h3>Backport patches</h3>{deepData?.backport_patches?.length ? deepData.backport_patches.map((p, i) => <div className="evidence-row" key={p.filename || i}><span>{p.filename || "Patch file"}</span>{p.url ? <a href={p.url} target="_blank" rel="noopener noreferrer">View source <ArrowUpRight size={12} /></a> : <span>Link unavailable</span>}</div>) : <p className="muted">No backport patch file recorded.</p>}</section>
                {deepData?.notes?.length ? <section><h3>Evidence notes</h3><ul>{deepData.notes.map((note, i) => <li key={i}>{note}</li>)}</ul></section> : null}
              </div>}
          </> : <>
            <small>VULNEX CVE RECORD</small><h2 id="detail-modal-title">{detail?.cve_id || "CVE details"}</h2>
            {detailBusy ? <div className="empty-state"><RefreshCw className="spin" /> Loading CVE details…</div>
              : detailError ? <div className="alert error"><AlertCircle size={16} />{detailError}</div>
              : <div className="detail-sections">
                <section><h3>Severity and description</h3>{detail?.findings?.map((f, i) => <div className="evidence-row" key={f.spec_path || i}><span><StatusPill tone={severityClass(f.severity)}>{f.severity || "Unknown"}{f.cvss_score != null ? ` · ${f.cvss_score}` : ""}</StatusPill><strong>{f.package_name} {f.package_version || ""}</strong></span><code>{f.branch}</code></div>)}<p>{detail?.enrichment?.description || detail?.findings?.[0]?.description || "Description not available from the approved source."}</p></section>
                <section><h3>External references</h3><div className="evidence-list">{(detail?.links || []).map(link => <div key={link.label}><span>{link.label}</span><a href={link.url} target="_blank" rel="noopener noreferrer">Open reference <ArrowUpRight size={12} /></a></div>)}</div></section>
                <section><h3>Patch evidence</h3>{detail?.findings?.map((f, i) => <div key={f.spec_path || i} className="evidence-row"><span>{f.package_name} · {f.branch}</span>{f.patch_availability?.patch_link ? <a href={f.patch_availability.patch_link} target="_blank" rel="noopener noreferrer">Open recorded link <ArrowUpRight size={12} /></a> : <span className="muted">No link recorded</span>}</div>)}</section>
              </div>}
          </>}
        </section>
      </div>}
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
