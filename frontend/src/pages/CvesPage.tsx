import { useCallback, useEffect, useMemo, useState } from "react";
import { Activity, AlertCircle, AlertTriangle, CheckCircle2, Clock3, FileSearch, Package, RefreshCw, ShieldAlert } from "lucide-react";
import { isAbort, messageOf, request } from "../api/client";
import type { Finding, PageResult, Stats } from "../api/types";
import { useApp } from "../app-context";
import { CveLink } from "../components/CveLink";
import { FilterSidebar } from "../components/FilterSidebar";
import { Pagination } from "../components/Pagination";
import { PatchIcon } from "../components/PatchIcon";
import { StatusPill } from "../components/StatusPill";
import { useScan } from "../hooks/useScan";
import { addRecent, DEFAULT_FILTERS, loadRecent, PAGE_SIZE, removeRecent, saveRecent, toFindingParams, type Filters } from "../lib/filters";
import { findingKey, groupByCve, ownerOf, resolutionOf, triageStatusOf } from "../lib/findings";
import { formatDateTime, severityLabel, severityTone, statusLabel, statusTone } from "../lib/labels";

const COLUMNS = 7;

/**
 * The home page: every CVE found in the scan, grouped by CVE, with the search
 * filters on the left. It is a read-only overview. Investigation (Deep) and
 * triage (Actions) live on the CVE page, which each CVE links to.
 */
export function CvesPage() {
  const { token, canWrite, notify } = useApp();
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [page, setPage] = useState(1);
  const [recent, setRecent] = useState<Filters[]>(loadRecent);
  const [rows, setRows] = useState<Finding[]>([]);
  const [total, setTotal] = useState(0);
  const [stats, setStats] = useState<Stats | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    setBusy(true);
    setError("");
    Promise.all([
      request<Stats>("/stats?" + new URLSearchParams({ branch: filters.branch }), { signal }, token),
      request<PageResult<Finding>>("/findings?" + toFindingParams(filters, page), { signal }, token),
    ])
      .then(([nextStats, findings]) => {
        setStats(nextStats);
        setRows(findings.items);
        setTotal(findings.total);
      })
      .catch((e: unknown) => {
        if (!isAbort(e)) setError(messageOf(e));
      })
      .finally(() => {
        if (!signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [filters, page, token, tick]);

  const scan = useScan({ token, canWrite, branch: filters.branch, notify, onFinished: reload });

  const apply = (next: Filters) => {
    setFilters(next);
    setPage(1);
    const updated = addRecent(recent, next);
    setRecent(updated);
    saveRecent(updated);
  };
  const forget = (search: Filters) => {
    const updated = removeRecent(recent, search);
    setRecent(updated);
    saveRecent(updated);
  };

  const groups = useMemo(() => groupByCve(rows), [rows]);
  const scanRunning = scan.state !== "idle";
  const highSeverity = (stats?.severity?.critical ?? 0) + (stats?.severity?.high ?? 0);

  return (
    <div className="workspace">
      <FilterSidebar mode="cves" applied={filters} onApply={apply} recent={recent} onRemoveRecent={forget} />

      <main className="content">
        <div className="page-head">
          <div>
            <h1>Recent CVEs</h1>
            <p>
              Vulnerabilities found in the azurelinux-test packages on branch {filters.branch}. Select a CVE to see every
              affected package, its patch evidence and triage history.
            </p>
          </div>
          <button className="icon-btn" title="Refresh data" aria-label="Refresh data" onClick={reload} disabled={busy}>
            <RefreshCw size={17} className={busy ? "spin" : undefined} />
          </button>
        </div>

        {stats && !stats.last_scan?.finished_at && (
          <section className="alert warning">
            <div>
              <strong>No successful stable {filters.branch} scan found.</strong>
              <span>Run a scan to populate the findings for this branch.</span>
            </div>
            {canWrite && (
              <button className="btn primary" onClick={() => void scan.run()} disabled={scanRunning}>
                <Activity size={15} /> {scan.state === "running" ? "Scanning…" : "Scan branch " + filters.branch}
              </button>
            )}
          </section>
        )}

        <section className="summary-grid" aria-label="Summary">
          <article className="metric-card">
            <span className="metric-icon blue"><Package size={18} /></span>
            <small>Packages scanned</small>
            <strong>{(stats?.total_packages ?? 0).toLocaleString()}</strong>
            <span>Branch {filters.branch}</span>
          </article>
          <article className="metric-card">
            <span className="metric-icon red"><ShieldAlert size={18} /></span>
            <small>Open findings</small>
            <strong>{(stats?.total_findings ?? 0).toLocaleString()}</strong>
            <span>{(stats?.distinct_cves ?? 0).toLocaleString()} distinct CVEs</span>
          </article>
          <article className="metric-card">
            <span className="metric-icon amber"><AlertTriangle size={18} /></span>
            <small>Critical + high</small>
            <strong>{highSeverity.toLocaleString()}</strong>
            <span>Open findings only</span>
          </article>
          <article className="metric-card">
            <span className="metric-icon green"><CheckCircle2 size={18} /></span>
            <small>Last completed scan</small>
            <strong>{stats?.last_scan?.finished_at ? new Date(stats.last_scan.finished_at).toLocaleDateString() : "—"}</strong>
            <span>{stats?.last_scan?.branches ? `Branches ${stats.last_scan.branches}` : "No scan yet"}</span>
          </article>
        </section>

        {error && (
          <div className="alert error" role="alert">
            <AlertCircle size={17} />
            {error}
          </div>
        )}

        <section className="table-card" aria-busy={busy}>
          <div className="table-head">
            <div>
              <h2>Findings by CVE</h2>
              <p>
                {total.toLocaleString()} finding{total === 1 ? "" : "s"} · branch {filters.branch}
              </p>
            </div>
            <div className="head-meta">
              <span>
                <Clock3 size={14} /> {stats?.last_scan?.finished_at ? formatDateTime(stats.last_scan.finished_at) : "Waiting for first scan"}
              </span>
              <button
                className="icon-btn"
                onClick={() => void scan.run()}
                disabled={!canWrite || scanRunning}
                title={canWrite ? `Scan branch ${filters.branch} from azurelinux-test` : "Administrator sign-in required to scan"}
                aria-label={`Scan branch ${filters.branch}`}
              >
                <Activity size={16} />
              </button>
            </div>
          </div>

          {busy && rows.length === 0 ? (
            <div className="empty-state">
              <RefreshCw className="spin" /> Loading vulnerability records…
            </div>
          ) : rows.length === 0 ? (
            <div className="empty-state">
              <FileSearch size={26} />
              <strong>No findings match these filters</strong>
              <span>Change or clear the filters, or run a scan for branch {filters.branch}.</span>
            </div>
          ) : (
            <div className={`table-scroll${busy ? " dim" : ""}`}>
              <table className="findings-table">
                <thead>
                  <tr>
                    <th scope="col">Package</th>
                    <th scope="col">Branch</th>
                    <th scope="col">Patch</th>
                    <th scope="col">Triage status</th>
                    <th scope="col">Resolution status</th>
                    <th scope="col">Fixed version</th>
                    <th scope="col">Owner</th>
                  </tr>
                </thead>
                {groups.map((group) => (
                  <tbody key={group.cveId}>
                    <tr className="group-row">
                      <th scope="colgroup" colSpan={COLUMNS}>
                        <CveLink id={group.cveId}>{group.cveId} →</CveLink>
                        <StatusPill tone={severityTone(group.severity)}>
                          {severityLabel(group.severity)}
                          {group.cvssScore != null ? ` · ${group.cvssScore}` : ""}
                        </StatusPill>
                        <span className="group-count">
                          {group.rows.length} package{group.rows.length === 1 ? "" : "s"} on this page
                        </span>
                      </th>
                    </tr>
                    {group.rows.map((row) => (
                      <tr key={findingKey(row)}>
                        <td>
                          <strong>{row.package_name || "Unknown package"}</strong>
                          <small>{row.package_version || "version unavailable"}</small>
                        </td>
                        <td><code>{row.branch}</code></td>
                        <td><PatchIcon finding={row} /></td>
                        <td><StatusPill tone={statusTone(triageStatusOf(row))}>{statusLabel(triageStatusOf(row))}</StatusPill></td>
                        <td><StatusPill tone={statusTone(resolutionOf(row))}>{statusLabel(resolutionOf(row))}</StatusPill></td>
                        <td>{row.fixed_version || "—"}</td>
                        <td>{ownerOf(row) || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                ))}
              </table>
            </div>
          )}
          <Pagination page={page} total={total} pageSize={PAGE_SIZE} busy={busy} noun="findings" onPage={setPage} />
        </section>
      </main>
    </div>
  );
}
