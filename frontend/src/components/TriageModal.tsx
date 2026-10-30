import { useState } from "react";
import { AlertCircle } from "lucide-react";
import { messageOf, request } from "../api/client";
import type { Finding } from "../api/types";
import { useApp } from "../app-context";
import {
  ACTION_TITLE,
  ASSIGNEES,
  DISPUTE_REASONS,
  buildTriageRequest,
  initialValues,
  isSubmittable,
  type TriageAction,
  type TriageValues,
} from "../lib/triage";
import { Modal } from "./Modal";

/** One form for every triage action (assign, dispute, comment, patch verdict, GitHub PR). */
export function TriageModal({
  action,
  finding,
  onClose,
  onSaved,
}: {
  action: TriageAction;
  finding: Finding;
  onClose: () => void;
  onSaved: (action: TriageAction, finding: Finding) => void;
}) {
  const { token, canAdmin } = useApp();
  const [values, setValues] = useState<TriageValues>(() => initialValues(finding));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const set = <K extends keyof TriageValues>(key: K, value: TriageValues[K]) =>
    setValues((current) => ({ ...current, [key]: value }));

  const save = async () => {
    const { path, body } = buildTriageRequest(action, finding, values);
    setSaving(true);
    setError("");
    try {
      await request(path, { method: "POST", body: JSON.stringify(body) }, token);
      onSaved(action, finding);
    } catch (e) {
      setError(messageOf(e));
      setSaving(false);
    }
  };

  return (
    <Modal eyebrow={`TRIAGE ACTION · ${finding.cve_id}`} title={ACTION_TITLE[action]} onClose={onClose}>
      <p className="modal-context">
        <strong>{finding.package_name}</strong> {finding.package_version} · branch {finding.branch}
      </p>

      {action === "assign" && (
        <>
          <label>
            Assignee email
            <select value={values.assigneeEmail} onChange={(e) => set("assigneeEmail", e.target.value)}>
              {ASSIGNEES.map((a) => (
                <option key={a.email} value={a.email}>
                  {a.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Assignment notes
            <textarea
              value={values.assignmentNotes}
              onChange={(e) => set("assignmentNotes", e.target.value)}
              rows={3}
              placeholder="Optional context for the assigned reviewer…"
            />
          </label>
        </>
      )}

      {action === "dispute" && (
        <>
          <label>
            Dispute reason
            <select value={values.disputeTag} onChange={(e) => set("disputeTag", e.target.value)}>
              {DISPUTE_REASONS.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label>
            Supporting details
            <textarea
              value={values.text}
              onChange={(e) => set("text", e.target.value)}
              rows={4}
              placeholder="Explain the evidence supporting this dispute…"
            />
          </label>
          <label>
            First unaffected version
            <input
              value={values.disputeVersion}
              disabled={values.neverApplicable}
              onChange={(e) => set("disputeVersion", e.target.value)}
              placeholder="e.g. 3.13.15-1"
            />
          </label>
          <label className="checkbox-line">
            <input
              type="checkbox"
              checked={values.neverApplicable}
              onChange={(e) => {
                set("neverApplicable", e.target.checked);
                if (e.target.checked) set("disputeVersion", "");
              }}
            />
            Never applicable (use only when supported by evidence)
          </label>
        </>
      )}

      {action === "comment" && (
        <label>
          Comment
          <textarea
            value={values.text}
            onChange={(e) => set("text", e.target.value)}
            rows={5}
            placeholder="Add a comment to the triage history…"
          />
        </label>
      )}

      {action === "patch" && (
        <>
          <label>
            Final verdict
            <select value={values.patchVerdict} onChange={(e) => set("patchVerdict", e.target.value)}>
              <option value="">No override</option>
              <option>Patch Available</option>
              <option>No Patch Found</option>
            </select>
          </label>
          <label>
            Patch link
            <input value={values.patchLink} onChange={(e) => set("patchLink", e.target.value)} />
          </label>
          <label>
            Available since
            <input type="date" value={values.availableSince} onChange={(e) => set("availableSince", e.target.value)} />
          </label>
        </>
      )}

      {action === "pr" && (
        <>
          <label>
            PR number
            <input value={values.prNumber} onChange={(e) => set("prNumber", e.target.value)} placeholder="19015" inputMode="numeric" />
          </label>
          <label>
            PR URL (optional)
            <input value={values.prUrl} onChange={(e) => set("prUrl", e.target.value)} placeholder="https://github.com/…/pull/19015" />
          </label>
        </>
      )}

      {error && (
        <div className="alert error" role="alert">
          <AlertCircle size={16} />
          {error}
        </div>
      )}

      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>
          Cancel
        </button>
        <button
          className="btn primary"
          onClick={() => void save()}
          disabled={!canAdmin || saving || !isSubmittable(action, values)}
          title={canAdmin ? undefined : "Administrator sign-in required"}
        >
          {saving ? "Saving…" : action === "assign" ? "Assign CVE" : "Save changes"}
        </button>
      </div>
    </Modal>
  );
}
