import { useEffect, useState } from "react";
import { AlertCircle, ArrowUpRight, RefreshCw } from "lucide-react";
import { isAbort, messageOf, request } from "../api/client";
import type { DeepView, Finding } from "../api/types";
import { useApp } from "../app-context";
import { Modal } from "./Modal";

/** "Deep" inspection of one finding: affected files, source tarball and backport patches. */
export function DeepModal({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  const { token } = useApp();
  const [data, setData] = useState<DeepView | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    setBusy(true);
    setError("");
    const params = new URLSearchParams({ branch: finding.branch || "", spec: finding.spec_path || "" });
    request<DeepView>(
      `/cves/${encodeURIComponent(finding.cve_id)}/deep?${params.toString()}`,
      { signal: controller.signal },
      token,
    )
      .then(setData)
      .catch((e: unknown) => {
        if (!isAbort(e)) setError(messageOf(e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [finding, token, attempt]);

  return (
    <Modal
      wide
      eyebrow={`DEEP INSPECTION · ${finding.branch}`}
      title={`${finding.cve_id} · ${finding.package_name}`}
      onClose={onClose}
    >
      {busy ? (
        <div className="empty-state">
          <RefreshCw className="spin" /> Loading affected-file evidence…
        </div>
      ) : error ? (
        <div className="alert error" role="alert">
          <AlertCircle size={16} />
          {error}
          <button className="btn secondary" onClick={() => setAttempt((n) => n + 1)}>
            Retry
          </button>
        </div>
      ) : (
        <div className="detail-sections">
          <section>
            <h3>Affected files</h3>
            {data?.affected_files?.length ? (
              <div className="evidence-list">
                {data.affected_files.map((file, i) => {
                  const path = typeof file === "string" ? file : file.path || file.file || file.name || "Path not available";
                  const url = typeof file === "string" ? "" : file.url || "";
                  return (
                    <div key={path + i}>
                      <code>{path}</code>
                      {url && (
                        <a href={url} target="_blank" rel="noopener noreferrer">
                          Source evidence <ArrowUpRight size={12} />
                        </a>
                      )}
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="muted">No affected-file information available from the recorded source evidence.</p>
            )}
          </section>
          <section>
            <h3>Source artifact</h3>
            {data?.tarball?.name ? (
              <div>
                <strong>{data.tarball.name}</strong>
                {data.tarball.url && (
                  <p>
                    <a href={data.tarball.url} target="_blank" rel="noopener noreferrer">
                      Open source tarball <ArrowUpRight size={12} />
                    </a>
                  </p>
                )}
                <small>
                  Availability: {data.tarball.available == null ? "Unknown" : data.tarball.available ? "Available" : "Not available"}
                </small>
              </div>
            ) : (
              <p className="muted">No source tarball recorded.</p>
            )}
          </section>
          <section>
            <h3>Backport patches</h3>
            {data?.backport_patches?.length ? (
              data.backport_patches.map((patch, i) => (
                <div className="evidence-row" key={patch.filename || i}>
                  <span>{patch.filename || "Patch file"}</span>
                  {patch.url ? (
                    <a href={patch.url} target="_blank" rel="noopener noreferrer">
                      View source <ArrowUpRight size={12} />
                    </a>
                  ) : (
                    <span>Link unavailable</span>
                  )}
                </div>
              ))
            ) : (
              <p className="muted">No backport patch file recorded.</p>
            )}
          </section>
          {data?.notes?.length ? (
            <section>
              <h3>Evidence notes</h3>
              <ul>
                {data.notes.map((note, i) => (
                  <li key={i}>{note}</li>
                ))}
              </ul>
            </section>
          ) : null}
        </div>
      )}
    </Modal>
  );
}
