import { useCallback, useEffect, useState } from "react";
import { AlertCircle, Check, RefreshCw, X } from "lucide-react";
import { isAbort, messageOf, request } from "../api/client";
import type { Dispute, DisputeList, DisputeStatus } from "../api/types";
import { useApp } from "../app-context";
import { Modal } from "../components/Modal";
import { Pagination } from "../components/Pagination";
import { StatusPill } from "../components/StatusPill";
import { formatDateTime } from "../lib/labels";
import { hrefFor } from "../lib/route";

const PAGE_SIZE = 25;

const TABS: ReadonlyArray<{ value: DisputeStatus | ""; label: string }> = [
  { value: "pending", label: "Pending" },
  { value: "approved", label: "Approved" },
  { value: "rejected", label: "Rejected" },
  { value: "", label: "All" },
];

const TONE: Record<DisputeStatus, string> = { pending: "warning", approved: "dispute", rejected: "neutral" };
const LABEL: Record<DisputeStatus, string> = { pending: "Pending", approved: "Approved", rejected: "Rejected" };

/**
 * Every dispute request. Anyone can raise one from a package's Actions menu; only the administrator
 * approves or rejects it here. An approved dispute marks the package's resolution status Disputed.
 */
export function DisputesPage() {
  const { token, roleInfo, notify } = useApp();
  const canDecide = Boolean(roleInfo.can_approve_dispute);
  const [tab, setTab] = useState<DisputeStatus | "">("pending");
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<DisputeList | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  const [deciding, setDeciding] = useState<number | null>(null);
  const [rejecting, setRejecting] = useState<Dispute | null>(null);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams({ limit: String(PAGE_SIZE), page: String(page) });
    if (tab) params.set("status", tab);
    if (query) params.set("search", query);
    setBusy(true);
    setError("");
    request<DisputeList>("/disputes?" + params, { signal: controller.signal }, token)
      .then(setData)
      .catch((e: unknown) => {
        if (!isAbort(e)) setError(messageOf(e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [tab, query, page, token, tick]);

  const decide = async (dispute: Dispute, verdict: "approve" | "reject", note = "") => {
    setDeciding(dispute.id);
    try {
      await request(`/disputes/${dispute.id}/${verdict}`, { method: "POST", body: JSON.stringify({ note }) }, token);
      notify(
        verdict === "approve"
          ? `Dispute approved: ${dispute.package_name} is now marked Disputed`
          : "Dispute rejected",
      );
      setRejecting(null);
      reload();
    } catch (e) {
      notify(messageOf(e));
    } finally {
      setDeciding(null);
    }
  };

  const counts = data?.counts;
  const rows = data?.items ?? [];

  return (
    <main className="cve-page">
      <div className="page-head">
        <div>
          <h1>Disputes</h1>
          <p>
            Dispute requests raised from a package's Actions menu. The administrator approves or rejects them here;
            an approved dispute marks the package's resolution status as Disputed.
          </p>
        </div>
        <button className="icon-btn" onClick={reload} aria-label="Refresh disputes" disabled={busy}>
          <RefreshCw size={16} className={busy ? "spin" : undefined} aria-hidden="true" />
        </button>
      </div>

      {error && (
        <div className="alert error" role="alert">
          <AlertCircle size={16} /> {error}
        </div>
      )}

      <section className="table-card">
        <div className="table-head">
          <div className="tabs" role="tablist" aria-label="Dispute status">
            {TABS.map(({ value, label }) => {
              const count = value ? counts?.[value] : counts ? counts.pending + counts.approved + counts.rejected : undefined;
              return (
                <button
                  key={label}
                  role="tab"
                  aria-selected={tab === value}
                  className={tab === value ? "tab active" : "tab"}
                  onClick={() => {
                    setTab(value);
                    setPage(1);
                  }}
                >
                  {label}
                  {count !== undefined && <span className="tab-count">{count}</span>}
                </button>
              );
            })}
          </div>
          <form
            className="inline-search"
            role="search"
            onSubmit={(event) => {
              event.preventDefault();
              setQuery(search.trim());
              setPage(1);
            }}
          >
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="CVE, package, requester…"
              aria-label="Search disputes"
            />
          </form>
        </div>

        <div className={busy ? "table-scroll dim" : "table-scroll"}>
          <table className="cve-table disputes-table">
            <thead>
              <tr>
                <th>CVE</th>
                <th>Package</th>
                <th>Reason</th>
                <th>Requested by</th>
                <th>Status</th>
                <th>Decision</th>
                {canDecide && <th>Review</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((d) => (
                <tr key={d.id}>
                  <td>
                    <a className="cve-link" href={hrefFor({ name: "cve", id: d.cve_id })}>
                      {d.cve_id}
                    </a>
                  </td>
                  <td>
                    <strong>{d.package_name || "—"}</strong>
                    <small>
                      {d.package_version} · {d.branch}
                    </small>
                  </td>
                  <td className="reason-cell">{d.reason}</td>
                  <td>
                    {d.requested_by || "—"}
                    <small>{formatDateTime(d.requested_at)}</small>
                  </td>
                  <td>
                    <StatusPill tone={TONE[d.status]}>{LABEL[d.status]}</StatusPill>
                  </td>
                  <td>
                    {d.status === "pending" ? (
                      "—"
                    ) : (
                      <>
                        {d.decided_by || "—"}
                        <small>{formatDateTime(d.decided_at)}</small>
                        {d.decision_note && <small className="reason-cell">{d.decision_note}</small>}
                      </>
                    )}
                  </td>
                  {canDecide && (
                    <td>
                      {d.status === "pending" ? (
                        <div className="review-actions">
                          <button
                            className="btn primary small"
                            disabled={deciding === d.id}
                            onClick={() => void decide(d, "approve")}
                            aria-label={`Approve dispute for ${d.package_name} ${d.cve_id}`}
                          >
                            <Check size={13} aria-hidden="true" /> Approve
                          </button>
                          <button
                            className="btn secondary small"
                            disabled={deciding === d.id}
                            onClick={() => setRejecting(d)}
                            aria-label={`Reject dispute for ${d.package_name} ${d.cve_id}`}
                          >
                            <X size={13} aria-hidden="true" /> Reject
                          </button>
                        </div>
                      ) : (
                        "—"
                      )}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
          {!busy && rows.length === 0 && !error && (
            <div className="empty-state">
              <strong>{tab === "pending" ? "No disputes are waiting" : "No disputes here"}</strong>
              <span>Raise one from a package's Actions menu on a CVE page.</span>
            </div>
          )}
        </div>

        <Pagination page={page} total={data?.total ?? 0} pageSize={PAGE_SIZE} busy={busy} noun="disputes" onPage={setPage} />
      </section>

      {rejecting && <RejectModal dispute={rejecting} onClose={() => setRejecting(null)} onReject={(note) => void decide(rejecting, "reject", note)} />}
    </main>
  );
}

function RejectModal({ dispute, onClose, onReject }: { dispute: Dispute; onClose: () => void; onReject: (note: string) => void }) {
  const [note, setNote] = useState("");
  return (
    <Modal eyebrow={`DISPUTE · ${dispute.cve_id}`} title="Reject dispute" onClose={onClose}>
      <p className="modal-context">
        <strong>{dispute.package_name}</strong> {dispute.package_version} · requested by {dispute.requested_by || "unknown"}
      </p>
      <label>
        Note for the requester (optional)
        <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} placeholder="Why is this dispute not accepted?" />
      </label>
      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>
          Cancel
        </button>
        <button className="btn primary" onClick={() => onReject(note.trim())}>
          Reject dispute
        </button>
      </div>
    </Modal>
  );
}
