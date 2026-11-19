import { useState } from "react";
import { AlertCircle } from "lucide-react";
import { messageOf, request } from "../api/client";
import type { Finding } from "../api/types";
import { useApp } from "../app-context";
import { ASSIGNEES } from "../lib/triage";
import { Modal } from "./Modal";

const NOBODY = "n/a";

/**
 * Release a package you hold. The package never ends up with no owner by accident: either it goes to a
 * developer from the list, or "N/A" is chosen and a reason for waiving it is recorded.
 */
export function ReleaseModal({
  finding,
  me,
  onClose,
  onReleased,
}: {
  finding: Finding;
  me: string;
  onClose: () => void;
  onReleased: () => void;
}) {
  const { token, notify } = useApp();
  const [target, setTarget] = useState(NOBODY);
  const [reason, setReason] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const nobody = target === NOBODY;
  const ready = !nobody || reason.trim().length > 0;
  const people = ASSIGNEES.filter((a) => a.email.toLowerCase() !== me);

  const save = async () => {
    setSaving(true);
    setError("");
    try {
      await request(
        "/triage/release",
        {
          method: "POST",
          body: JSON.stringify({
            cve_id: finding.cve_id,
            branch: finding.branch ?? "",
            spec_path: finding.spec_path ?? "",
            assign_to: target,
            reason: nobody ? reason.trim() : "",
          }),
        },
        token,
      );
      notify(nobody ? "Released as N/A. The reason is saved in the comments." : `Released. It now belongs to ${target}.`);
      onReleased();
    } catch (e) {
      setError(messageOf(e));
      setSaving(false);
    }
  };

  return (
    <Modal eyebrow={`RELEASE · ${finding.cve_id}`} title="Release this package" onClose={onClose}>
      <p className="modal-context">
        <strong>{finding.package_name}</strong> {finding.package_version} · branch {finding.branch}
      </p>
      <label>
        Who gets it?
        <select value={target} onChange={(e) => setTarget(e.target.value)}>
          <option value={NOBODY}>N/A (nobody)</option>
          {people.map((a) => (
            <option key={a.email} value={a.email}>
              {a.label}
            </option>
          ))}
        </select>
      </label>
      {nobody && (
        <label>
          Reason for waiving
          <textarea
            value={reason}
            rows={3}
            maxLength={2000}
            placeholder="Why does this CVE not need an owner?"
            onChange={(e) => setReason(e.target.value)}
          />
        </label>
      )}
      {error && (
        <div className="alert error" role="alert">
          <AlertCircle size={16} /> {error}
        </div>
      )}
      <div className="modal-actions">
        <button className="btn" onClick={onClose} disabled={saving}>
          Cancel
        </button>
        <button className="btn primary" onClick={() => void save()} disabled={saving || !ready}>
          Release
        </button>
      </div>
    </Modal>
  );
}
