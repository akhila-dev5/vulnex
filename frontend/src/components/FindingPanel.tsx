import { ArrowUpRight, MessageSquarePlus, RefreshCw } from "lucide-react";
import type { Finding, FindingComment } from "../api/types";
import { useApp } from "../app-context";
import { latestDispute, ownerOf, resolutionOf, triageStatusOf } from "../lib/findings";
import { formatDate, formatDateTime, severityLabel, severityTone, statusLabel, statusTone } from "../lib/labels";
import { StatusPill } from "./StatusPill";

export type CommentsState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "ready"; items: FindingComment[] };

function ExternalLinkText({ href, children }: { href: string; children: string }) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="break">
      {children} <ArrowUpRight size={12} aria-hidden="true" />
    </a>
  );
}

const initialOf = (name?: string): string => (name?.trim().charAt(0) || "?").toUpperCase();

/** The dropdown under a package row: GitHub PR, patch availability, triage info, dispute reason and comments. */
export function FindingPanel({
  id,
  finding,
  comments,
  onAddComment,
}: {
  id: string;
  finding: Finding;
  comments: CommentsState | undefined;
  onAddComment: () => void;
}) {
  const { canAdmin } = useApp();
  const triage = finding.triage ?? {};
  const patch = finding.patch_availability ?? {};
  const items = comments?.status === "ready" ? comments.items : [];
  const dispute = latestDispute(items);
  const newestFirst = [...items].sort((a, b) => (b.created_at ?? "").localeCompare(a.created_at ?? ""));
  const patchLink = patch.patch_link || triage.patch_link;
  const since = patch.available_since || triage.available_since;

  return (
    <div className="finding-panel" id={id}>
      <section className="panel-block" aria-labelledby={`${id}-pr`}>
        <h3 id={`${id}-pr`}>GitHub PR</h3>
        {triage.github_pr_number ? (
          <dl className="kv">
            <div>
              <dt>PR number</dt>
              <dd>
                {triage.github_pr_url ? (
                  <ExternalLinkText href={triage.github_pr_url}>{`#${triage.github_pr_number}`}</ExternalLinkText>
                ) : (
                  `#${triage.github_pr_number}`
                )}
              </dd>
            </div>
            <div>
              <dt>Set by</dt>
              <dd>
                {triage.github_pr_set_by || "—"}
                {triage.github_pr_set_at ? ` · ${formatDateTime(triage.github_pr_set_at)}` : ""}
              </dd>
            </div>
          </dl>
        ) : (
          <p className="muted">No PR information recorded.</p>
        )}
      </section>

      <section className="panel-block" aria-labelledby={`${id}-triage`}>
        <h3 id={`${id}-triage`}>Triage information</h3>
        <dl className="kv">
          <div>
            <dt>Triage status</dt>
            <dd><StatusPill tone={statusTone(triageStatusOf(finding))}>{statusLabel(triageStatusOf(finding))}</StatusPill></dd>
          </div>
          <div>
            <dt>Resolution</dt>
            <dd><StatusPill tone={statusTone(resolutionOf(finding))}>{statusLabel(resolutionOf(finding))}</StatusPill></dd>
          </div>
          <div>
            <dt>Severity</dt>
            <dd>
              <StatusPill tone={severityTone(finding.severity)}>{severityLabel(finding.severity)}</StatusPill>
              {finding.cvss_score != null && <span className="score"> {finding.cvss_score}</span>}
            </dd>
          </div>
          <div>
            <dt>Owner</dt>
            <dd>{ownerOf(finding) || "—"}</dd>
          </div>
          <div className="wide">
            <dt>Vector</dt>
            <dd className="mono break">{finding.cvss_vector || "—"}</dd>
          </div>
        </dl>
      </section>

      <section className="panel-block wide" aria-labelledby={`${id}-patch`}>
        <h3 id={`${id}-patch`}>Patch availability</h3>
        <div className="verdict-grid">
          <div className="verdict-card">
            <small>Evidence verdict</small>
            <StatusPill tone={patch.available ? "good" : patch.applicable === false ? "neutral" : "warning"}>
              {patch.ai_verdict || "Unknown"}
            </StatusPill>
            <small>Possible patch links</small>
            {patch.possible_links?.length ? (
              <ul className="link-list">
                {patch.possible_links.map((link) => (
                  <li key={link}><ExternalLinkText href={link}>{link}</ExternalLinkText></li>
                ))}
              </ul>
            ) : (
              <p className="muted">No patch links found.</p>
            )}
            {patch.analysis?.length ? (
              <details>
                <summary>View analysis</summary>
                <ul>
                  {patch.analysis.map((line, i) => (
                    <li key={i} className="break">{line}</li>
                  ))}
                </ul>
              </details>
            ) : null}
          </div>
          <div className="verdict-card">
            <small>Final verdict</small>
            <StatusPill tone={(patch.final_verdict || "").toLowerCase().includes("no patch") ? "bad" : patch.available ? "good" : "neutral"}>
              {patch.final_verdict || "Not set"}
            </StatusPill>
            <dl className="kv">
              <div>
                <dt>Patch link</dt>
                <dd>{patchLink ? <ExternalLinkText href={patchLink}>{patchLink}</ExternalLinkText> : "—"}</dd>
              </div>
              <div>
                <dt>Available since</dt>
                <dd>{since ? formatDate(since) : "—"}</dd>
              </div>
            </dl>
          </div>
        </div>
      </section>

      <section className="panel-block" aria-labelledby={`${id}-dispute`}>
        <h3 id={`${id}-dispute`}>Dispute reason</h3>
        {comments?.status === "loading" || !comments ? (
          <p className="muted"><RefreshCw size={12} className="spin" /> Loading…</p>
        ) : dispute ? (
          <article className="comment dispute">
            <small>
              {dispute.author || "Recorded user"} · {formatDateTime(dispute.created_at)}
            </small>
            <p>{dispute.body}</p>
          </article>
        ) : (
          <p className="muted">No dispute has been raised for this package.</p>
        )}
      </section>

      <section className="panel-block" aria-labelledby={`${id}-comments`}>
        <div className="panel-title">
          <h3 id={`${id}-comments`}>Triage comments</h3>
          <button
            className="btn secondary small"
            onClick={onAddComment}
            disabled={!canAdmin}
            title={canAdmin ? undefined : "Administrator sign-in required"}
          >
            <MessageSquarePlus size={13} aria-hidden="true" /> Add comment
          </button>
        </div>
        {comments?.status === "error" ? (
          <p className="error-text" role="alert">Could not load comments: {comments.message}</p>
        ) : !comments || comments.status === "loading" ? (
          <p className="muted"><RefreshCw size={12} className="spin" /> Loading recorded comments…</p>
        ) : newestFirst.length === 0 ? (
          <p className="muted">No triage comments recorded for this package.</p>
        ) : (
          <ul className="comments">
            {newestFirst.map((comment, index) => (
              <li key={comment.id ?? index} className="comment">
                <span className="avatar" aria-hidden="true">{initialOf(comment.author)}</span>
                <div>
                  <small>
                    <strong>{comment.author || "Recorded user"}</strong>
                    {comment.kind === "dispute" ? " · Dispute" : ""} · {formatDateTime(comment.created_at)}
                  </small>
                  <p>{comment.body || "No comment text."}</p>
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
