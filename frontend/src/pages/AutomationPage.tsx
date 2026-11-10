import { useCallback, useEffect, useState } from "react";
import { AlertCircle, Bot, Lock, RefreshCw } from "lucide-react";
import { isAbort, messageOf, request } from "../api/client";
import { useApp } from "../app-context";
import { AutomateModal, type AutomationPackage } from "../components/AutomateModal";
import { StatusPill } from "../components/StatusPill";
import { formatDayMonth, severityLabel, severityTone } from "../lib/labels";
import { hrefFor } from "../lib/route";

type AutomationRequestRow = { id: number; cve_ids: string[]; mode: "new_pr" | "existing_pr"; pr_number: string; status: string; requested_by: string };
type Group = AutomationPackage & {
  requests: AutomationRequestRow[];
};
type AutomationList = { owner: string; total: number; packages: Group[] };

const keyOf = (g: Group) => `${g.package_name}|${g.branch}|${g.spec_path}`;

/**
 * The automation account's open CVEs that have a patch available, one card per package,
 * because the automation raises one pull request per package. Visitors are told it is for developers.
 */
export function AutomationPage() {
  const { token, canContribute } = useApp();
  const [data, setData] = useState<AutomationList | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  const [selected, setSelected] = useState<Group | null>(null);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!canContribute) {
      setData(null);
      return;
    }
    const controller = new AbortController();
    setBusy(true);
    setError("");
    request<AutomationList>("/automation", { signal: controller.signal }, token)
      .then(setData)
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
          <strong>Only developers can see Automation</strong>
          <span>Sign in with a developer or administrator Google account to automate fixes.</span>
        </div>
      </main>
    );
  }

  const packages = data?.packages ?? [];
  return (
    <main className="cve-page">
      <div className="page-head">
        <div>
          <h1>Automation</h1>
          <p>
            {data
              ? `${data.total} CVE${data.total === 1 ? "" : "s"} with a patch available across ${packages.length} package${packages.length === 1 ? "" : "s"}, held by ${data.owner}.`
              : "Packages with a patch available, ready to automate."}
          </p>
        </div>
        <button className="icon-btn" onClick={reload} aria-label="Refresh automation" disabled={busy}>
          <RefreshCw size={16} className={busy ? "spin" : undefined} aria-hidden="true" />
        </button>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <AlertCircle size={16} /> {error}
        </div>
      )}

      {packages.map((group) => (
        <section className="table-card automation-card" key={keyOf(group)} aria-label={`Package ${group.package_name}`}>
          <div className="automation-head">
            <div>
              <h2 className="workflow-owner-inline">{group.package_name}</h2>
              <small>
                {group.package_version} · branch <code>{group.branch}</code> · {group.items.length} CVE{group.items.length === 1 ? "" : "s"}
              </small>
            </div>
            <button className="btn primary" onClick={() => setSelected(group)} aria-label={`Automate ${group.package_name}`}>
              <Bot size={14} aria-hidden="true" /> Automate
            </button>
          </div>
          {group.requests[0] && (
            <p className="automation-last">
              Last request: {group.requests[0].cve_ids.length} CVE{group.requests[0].cve_ids.length === 1 ? "" : "s"},{" "}
              {group.requests[0].mode === "new_pr" ? "new PR" : `PR #${group.requests[0].pr_number}`} · {group.requests[0].status}
            </p>
          )}
          <details open>
            <summary>CVEs ({group.items.length})</summary>
            <ul className="automation-cves">
              {group.items.map((item) => (
                <li key={item.cve_id}>
                  <a className="cve-link" href={hrefFor({ name: "cve", id: item.cve_id })}>{item.cve_id}</a>
                  <StatusPill tone={severityTone(item.severity)}>{severityLabel(item.severity)}</StatusPill>
                  <span>{formatDayMonth(item.first_seen)}</span>
                </li>
              ))}
            </ul>
          </details>
        </section>
      ))}

      {data && packages.length === 0 && !busy && !error && (
        <div className="empty-state">
          <strong>Nothing to automate yet</strong>
          <span>CVEs show here when they are assigned to or claimed by {data.owner} and their patch verdict is Patch Available.</span>
        </div>
      )}

      {selected && <AutomateModal pkg={selected} onClose={() => setSelected(null)} onQueued={reload} />}
    </main>
  );
}
