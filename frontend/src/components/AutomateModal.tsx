import { useState } from "react";
import { messageOf, request } from "../api/client";
import { useApp } from "../app-context";
import { Modal } from "./Modal";

export type AutomationItem = { cve_id: string; severity?: string; first_seen?: string };
export type AutomationPackage = {
  package_name: string;
  package_version?: string;
  branch: string;
  spec_path: string;
  items: AutomationItem[];
};

/** Tick the CVEs to fix, then choose a new pull request or an existing one (which needs its number). */
export function AutomateModal({
  pkg,
  onClose,
  onQueued,
}: {
  pkg: AutomationPackage;
  onClose: () => void;
  onQueued: () => void;
}) {
  const { token, notify } = useApp();
  const [ticked, setTicked] = useState<Set<string>>(() => new Set(pkg.items.map((i) => i.cve_id)));
  const [mode, setMode] = useState<"new_pr" | "existing_pr">("new_pr");
  const [prNumber, setPrNumber] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const toggle = (id: string) =>
    setTicked((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  const number = prNumber.trim().replace(/^#/, "");
  const valid = ticked.size > 0 && (mode === "new_pr" || /^\d+$/.test(number));

  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      await request(
        "/automation/requests",
        {
          method: "POST",
          body: JSON.stringify({
            package_name: pkg.package_name,
            branch: pkg.branch,
            spec_path: pkg.spec_path,
            cve_ids: [...ticked],
            mode,
            pr_number: mode === "existing_pr" ? number : "",
          }),
        },
        token,
      );
      notify(`Queued ${ticked.size} CVE${ticked.size === 1 ? "" : "s"} for ${pkg.package_name}.`);
      onQueued();
      onClose();
    } catch (e) {
      setError(messageOf(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal eyebrow="AUTOMATION" title={`Automate ${pkg.package_name}`} onClose={onClose}>
      <p className="modal-context">
        <strong>{pkg.package_name}</strong> {pkg.package_version} · branch {pkg.branch}. The ticked CVEs are fixed in one pull request.
      </p>

      <fieldset className="automate-group">
        <legend>CVEs to fix ({ticked.size} of {pkg.items.length})</legend>
        {pkg.items.map((item) => (
          <label className="checkbox-line" key={item.cve_id}>
            <input type="checkbox" checked={ticked.has(item.cve_id)} onChange={() => toggle(item.cve_id)} />
            {item.cve_id}
          </label>
        ))}
      </fieldset>

      <fieldset className="automate-group">
        <legend>Pull request</legend>
        <label className="checkbox-line">
          <input type="radio" name="pr-mode" checked={mode === "new_pr"} onChange={() => setMode("new_pr")} />
          Create a new PR
        </label>
        <label className="checkbox-line">
          <input type="radio" name="pr-mode" checked={mode === "existing_pr"} onChange={() => setMode("existing_pr")} />
          Commit to an existing PR
        </label>
        {mode === "existing_pr" && (
          <label>
            PR number
            <input value={prNumber} onChange={(e) => setPrNumber(e.target.value)} inputMode="numeric" placeholder="e.g. 1234" />
          </label>
        )}
      </fieldset>

      {error && <p className="alert error" role="alert">{error}</p>}
      <div className="modal-actions">
        <button className="btn secondary" onClick={onClose}>Cancel</button>
        <button className="btn primary" disabled={!valid || busy} onClick={() => void submit()}>
          {busy ? "Queuing…" : "Queue automation"}
        </button>
      </div>
    </Modal>
  );
}
