import { useCallback, useEffect, useState } from "react";
import { AlertCircle, Lock, RefreshCw } from "lucide-react";
import { isAbort, messageOf, request } from "../api/client";
import type { Finding } from "../api/types";
import { useApp } from "../app-context";
import { ClaimButton } from "../components/ClaimButton";
import { StatusPill } from "../components/StatusPill";
import { findingKey, resolutionOf, triageStatusOf } from "../lib/findings";
import { formatDayMonth, statusLabel, statusTone } from "../lib/labels";
import { hrefFor } from "../lib/route";

type WorkflowItem = Finding & { held_via?: "assigned" | "claimed" };
type WorkflowGroup = { owner: string; total: number; items: WorkflowItem[] };
type WorkflowList = { me: string; total: number; groups: WorkflowGroup[] };

/**
 * Every developer's packages, claimed or assigned by the administrator: the signed-in
 * account first, then everyone else alphabetically. Visitors are told it is for developers; the server refuses them as well.
 */
export function WorkflowsPage() {
  const { token, canContribute } = useApp();
  const [data, setData] = useState<WorkflowList | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!canContribute) {
      setData(null);
      return;
    }
    const controller = new AbortController();
    setBusy(true);
    setError("");
    request<WorkflowList>("/workflows", { signal: controller.signal }, token)
      .then((result) => setData(result))
      .catch((e: unknown) => {
        if (!isAbort(e)) setError(messageOf(e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [canContribute, token, tick]);

  if (!canContribute) {
    return (
      <main className="cve-page">
        <div className="empty-state workflows-locked" role="status">
          <Lock size={26} aria-hidden="true" />
          <strong>Only developers can see Workflows</strong>
          <span>Sign in with a developer or administrator Google account to see the CVEs each developer holds.</span>
        </div>
      </main>
    );
  }

  const groups = data?.groups ?? [];
  return (
    <main className="cve-page">
      <div className="page-head">
        <div>
          <h1>Workflows</h1>
          <p>
            {data
              ? `${data.total} package${data.total === 1 ? "" : "s"} held across ${groups.length} developer${groups.length === 1 ? "" : "s"}, claimed or assigned. Claim a package from the CVEs page to track it here.`
              : "The packages each developer holds."}
          </p>
        </div>
        <button className="icon-btn" onClick={reload} aria-label="Refresh workflows" disabled={busy}>
          <RefreshCw size={16} className={busy ? "spin" : undefined} aria-hidden="true" />
        </button>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <AlertCircle size={16} /> {error}
        </div>
      )}

      {groups.map((group) => {
        const mine = group.owner === data?.me;
        return (
          <section className="table-card" key={group.owner} aria-label={`Packages held by ${group.owner}`}>
            <h2 className="workflow-owner">
              {group.owner}
              {mine && " (you)"}
              <small> · {group.total} package{group.total === 1 ? "" : "s"}</small>
            </h2>
            <div className={busy ? "table-scroll dim" : "table-scroll"}>
              {group.items.length > 0 ? (
                <table className="cve-table">
                  <thead>
                    <tr>
                      <th>CVE</th>
                      <th>Package</th>
                      <th>Scanned</th>
                      <th>Branch</th>
                      <th>Held</th>
                      <th>Triage status</th>
                      <th>Resolution status</th>
                      <th>Claim</th>
                    </tr>
                  </thead>
                  <tbody>
                    {group.items.map((row) => (
                      <tr key={findingKey(row)}>
                        <td>
                          <a className="cve-link" href={hrefFor({ name: "cve", id: row.cve_id })}>
                            {row.cve_id}
                          </a>
                        </td>
                        <td>
                          <strong>{row.package_name}</strong>
                          <small>{row.package_version}</small>
                        </td>
                        <td>{formatDayMonth(row.first_seen)}</td>
                        <td><code>{row.branch}</code></td>
                        <td>{row.held_via === "assigned" ? "Assigned" : "Claimed"}</td>
                        <td><StatusPill tone={statusTone(triageStatusOf(row))}>{statusLabel(triageStatusOf(row))}</StatusPill></td>
                        <td><StatusPill tone={statusTone(resolutionOf(row))}>{statusLabel(resolutionOf(row))}</StatusPill></td>
                        <td><ClaimButton finding={row} onChanged={reload} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                !busy && (
                  <div className="empty-state">
                    <strong>{mine ? "You have not claimed any packages yet" : "No packages held"}</strong>
                    {mine && <span>Use the Claim button next to a package on the CVEs page.</span>}
                  </div>
                )
              )}
            </div>
          </section>
        );
      })}
    </main>
  );
}
