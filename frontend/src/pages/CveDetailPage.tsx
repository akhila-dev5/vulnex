import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { AlertCircle, ArrowLeft, ArrowUpRight, ChevronDown, ChevronRight, ExternalLink, FileSearch, RefreshCw } from "lucide-react";
import { isAbort, messageOf, request } from "../api/client";
import type { CveDetail, Finding, FindingComment } from "../api/types";
import { useApp } from "../app-context";
import { ActionsMenu } from "../components/ActionsMenu";
import { DeepModal } from "../components/DeepModal";
import { FindingPanel, type CommentsState } from "../components/FindingPanel";
import { PatchIcon } from "../components/PatchIcon";
import { StatusPill } from "../components/StatusPill";
import { TriageModal } from "../components/TriageModal";
import { findingKey, ownerOf, resolutionOf, sortForCvePage, specUrl, triageStatusOf } from "../lib/findings";
import { formatDate, severityLabel, severityTone, statusLabel, statusTone } from "../lib/labels";
import { hrefFor } from "../lib/route";
import { ACTION_DONE, type TriageAction } from "../lib/triage";

const SOURCE_REPO = { owner: "akhila-dev5", repo: "azurelinux-test" };
const COLUMNS = 11;

/**
 * One CVE: its description and source links, then every package it affects.
 * Each package has Deep (evidence), Actions (triage) and a dropdown with the
 * GitHub PR, patch availability, triage information, dispute reason and comments.
 */
export function CveDetailPage({ id }: { id: string }) {
  const { token, notify } = useApp();
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [tick, setTick] = useState(0);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [comments, setComments] = useState<Record<string, CommentsState>>({});
  const [deepTarget, setDeepTarget] = useState<Finding | null>(null);
  const [activeAction, setActiveAction] = useState<{ type: TriageAction; finding: Finding } | null>(null);

  useEffect(() => {
    document.title = `${id} · Vulnex`;
    return () => {
      document.title = "Vulnex — Azure Linux CVE dashboard";
    };
  }, [id]);

  // A different CVE starts from a clean slate.
  useEffect(() => {
    setDetail(null);
    setExpanded({});
    setComments({});
  }, [id]);

  useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError("");
    request<CveDetail>(`/cves/${encodeURIComponent(id)}?enrich=false`, { signal: controller.signal }, token)
      .then(setDetail)
      .catch((e: unknown) => {
        if (!isAbort(e)) setError(messageOf(e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [id, token, tick]);

  const loadComments = useCallback(
    async (finding: Finding) => {
      const key = findingKey(finding);
      setComments((current) => ({ ...current, [key]: { status: "loading" } }));
      try {
        const params = new URLSearchParams({ cve_id: finding.cve_id, branch: finding.branch || "", spec_path: finding.spec_path || "" });
        const result = await request<{ items: FindingComment[] }>("/triage/comments?" + params.toString(), {}, token);
        setComments((current) => ({ ...current, [key]: { status: "ready", items: result.items ?? [] } }));
      } catch (e) {
        setComments((current) => ({ ...current, [key]: { status: "error", message: messageOf(e) } }));
      }
    },
    [token],
  );

  const toggle = (finding: Finding) => {
    const key = findingKey(finding);
    const opening = !expanded[key];
    setExpanded((current) => ({ ...current, [key]: opening }));
    if (opening && !comments[key]) void loadComments(finding);
  };

  const saved = (type: TriageAction, finding: Finding) => {
    setActiveAction(null);
    notify(ACTION_DONE[type]);
    setTick((t) => t + 1);
    // Comments and disputes show in the dropdown, so refresh them for this package.
    if (expanded[findingKey(finding)] || comments[findingKey(finding)]) void loadComments(finding);
  };

  const findings = useMemo(() => sortForCvePage(detail?.findings ?? []), [detail]);
  const openCount = findings.filter((f) => f.status === "affected").length;
  const vector = findings.find((f) => f.cvss_vector)?.cvss_vector;
  const score = findings.find((f) => f.cvss_score != null)?.cvss_score ?? detail?.enrichment?.cvss_score;
  const severity = findings.find((f) => f.severity)?.severity ?? detail?.enrichment?.severity;
  const description = detail?.enrichment?.description || findings.find((f) => f.description)?.description;
  const published = detail?.enrichment?.published;

  return (
    <main className="cve-page">
      <a className="back-link" href={hrefFor({ name: "cves" })}>
        <ArrowLeft size={15} aria-hidden="true" /> All CVEs
      </a>

      {error && (
        <div className="alert error" role="alert">
          <AlertCircle size={17} />
          <span>{error}</span>
          <button className="btn secondary" onClick={() => setTick((t) => t + 1)}>
            Retry
          </button>
        </div>
      )}

      {busy && !detail ? (
        <div className="empty-state">
          <RefreshCw className="spin" /> Loading {id}…
        </div>
      ) : detail ? (
        <>
          <section className="cve-head" aria-labelledby="cve-title">
            <div className="cve-head-main">
              <h1 id="cve-title">{detail.cve_id || id}</h1>
              <p className="meta">
                <span>Original vector:</span> <code>{vector || "not recorded"}</code>
              </p>
              {published && (
                <p className="meta">
                  <span>NVD published:</span> {formatDate(published)}
                </p>
              )}
              {detail.links?.length ? (
                <nav className="tracker-links" aria-label="External trackers">
                  {detail.links.map((link) => (
                    <a key={link.label} href={link.url} target="_blank" rel="noopener noreferrer">
                      {link.label} <ArrowUpRight size={12} aria-hidden="true" />
                    </a>
                  ))}
                </nav>
              ) : null}
              <p className="description">{description || "The approved source does not provide a description for this vulnerability."}</p>
            </div>
            <aside className="severity-panel" aria-label="Severity">
              <small>Severity</small>
              <strong className={`sev-${severityTone(severity)}`}>{severityLabel(severity)}</strong>
              <dl>
                <div>
                  <dt>CVSS score</dt>
                  <dd>{score != null ? score : "—"}</dd>
                </div>
                <div>
                  <dt>Open packages</dt>
                  <dd>
                    {openCount} of {findings.length}
                  </dd>
                </div>
              </dl>
              <p>Severity comes from the scanned vulnerability data; it is not adjusted by triage.</p>
            </aside>
          </section>

          <section className="table-card" aria-labelledby="affected-title">
            <div className="table-head">
              <div>
                <h2 id="affected-title">Affected packages</h2>
                <p>
                  {findings.length} package{findings.length === 1 ? "" : "s"} listed for {detail.cve_id || id}
                </p>
              </div>
            </div>
            {findings.length === 0 ? (
              <div className="empty-state">
                <FileSearch size={26} />
                <strong>No packages recorded</strong>
              </div>
            ) : (
              <div className="table-scroll">
                <table className="findings-table cve-table">
                  <thead>
                    <tr>
                      <th scope="col">Package</th>
                      <th scope="col">Finding</th>
                      <th scope="col">Branch</th>
                      <th scope="col">Patch</th>
                      <th scope="col">Triage status</th>
                      <th scope="col">Resolution status</th>
                      <th scope="col">Fixed version</th>
                      <th scope="col">Owner</th>
                      <th scope="col">Evidence</th>
                      <th scope="col">Actions</th>
                      <th scope="col"><span className="sr-only">Show details</span></th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((finding) => {
                      const key = findingKey(finding);
                      const panelId = `panel-${findings.indexOf(finding)}`;
                      const isOpen = Boolean(expanded[key]);
                      const label = `${finding.package_name} ${finding.package_version ?? ""}`.trim();
                      const spec = specUrl(SOURCE_REPO.owner, SOURCE_REPO.repo, finding);
                      return (
                        <Fragment key={key}>
                          <tr className={isOpen ? "row-open" : undefined}>
                            <td>
                              <strong>{finding.package_name || "Unknown package"}</strong>
                              {spec && (
                                <a className="spec-link" href={spec} target="_blank" rel="noopener noreferrer" title="Open the spec in azurelinux-test">
                                  <ExternalLink size={12} aria-hidden="true" />
                                  <span className="sr-only">Open {finding.package_name} spec on GitHub</span>
                                </a>
                              )}
                              <small>{finding.package_version || "version unavailable"}</small>
                            </td>
                            <td><StatusPill tone={statusTone(finding.status)}>{statusLabel(finding.status)}</StatusPill></td>
                            <td><code>{finding.branch}</code></td>
                            <td><PatchIcon finding={finding} /></td>
                            <td><StatusPill tone={statusTone(triageStatusOf(finding))}>{statusLabel(triageStatusOf(finding))}</StatusPill></td>
                            <td><StatusPill tone={statusTone(resolutionOf(finding))}>{statusLabel(resolutionOf(finding))}</StatusPill></td>
                            <td>{finding.fixed_version || "—"}</td>
                            <td>{ownerOf(finding) || "—"}</td>
                            <td>
                              <button className="btn deep-btn" onClick={() => setDeepTarget(finding)} aria-label={`Deep inspection of ${label}`}>
                                <FileSearch size={14} aria-hidden="true" /> Deep
                              </button>
                            </td>
                            <td>
                              <ActionsMenu label={label} onAction={(type) => setActiveAction({ type, finding })} />
                            </td>
                            <td>
                              <button
                                className="icon-btn"
                                onClick={() => toggle(finding)}
                                aria-expanded={isOpen}
                                aria-controls={panelId}
                                aria-label={`${isOpen ? "Hide" : "Show"} triage details for ${label}`}
                              >
                                {isOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                              </button>
                            </td>
                          </tr>
                          {isOpen && (
                            <tr className="expanded">
                              <td colSpan={COLUMNS}>
                                <FindingPanel
                                  id={panelId}
                                  finding={finding}
                                  comments={comments[key]}
                                  onAddComment={() => setActiveAction({ type: "comment", finding })}
                                />
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </>
      ) : null}

      {deepTarget && <DeepModal finding={deepTarget} onClose={() => setDeepTarget(null)} />}
      {activeAction && (
        <TriageModal
          action={activeAction.type}
          finding={activeAction.finding}
          onClose={() => setActiveAction(null)}
          onSaved={saved}
        />
      )}
    </main>
  );
}
