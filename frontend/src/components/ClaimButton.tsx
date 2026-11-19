import { useState } from "react";
import { HandHelping, Undo2 } from "lucide-react";
import { messageOf, request } from "../api/client";
import type { Finding } from "../api/types";
import { useApp } from "../app-context";
import { ReleaseModal } from "./ReleaseModal";

/** Who holds a package: the administrator's assignment if there is one, otherwise whoever claimed it. */
export function holderOf(finding: Finding): string {
  return (finding.assignment?.assignee_email || finding.triage?.owner || "").trim().toLowerCase();
}

/**
 * The only three actions on a package's owner, shown as one button:
 *  - Claim: nobody holds it.
 *  - Reclaim: someone else holds it and you take it.
 *  - Release: you hold it; a dialog asks who gets it, or "N/A" with a reason.
 *
 * Everyone sees the button, but only developers and the administrator can use it; for visitors it stays
 * disabled. The server checks the sign-in too, so hiding it is not the protection.
 */
export function ClaimButton({ finding, onChanged }: { finding: Finding; onChanged: () => void }) {
  const { token, roleInfo, canContribute, notify } = useApp();
  const [busy, setBusy] = useState(false);
  const [releasing, setReleasing] = useState(false);
  const holder = holderOf(finding);
  const me = (roleInfo.identity?.email ?? roleInfo.identity?.identity ?? "").trim().toLowerCase();
  const label = `${finding.package_name} ${finding.package_version ?? ""}`.trim();

  const claim = async (done: string) => {
    setBusy(true);
    try {
      await request(
        "/triage/claim",
        { method: "POST", body: JSON.stringify({ cve_id: finding.cve_id, branch: finding.branch ?? "", spec_path: finding.spec_path ?? "" }) },
        token,
      );
      notify(done);
      onChanged();
    } catch (error) {
      notify(messageOf(error));
    } finally {
      setBusy(false);
    }
  };

  if (!canContribute) {
    return (
      <button className="btn claim-btn" disabled title="Only developers can claim a package. Sign in as a developer." aria-label={`Claim ${label} (developers only)`}>
        <HandHelping size={14} aria-hidden="true" /> Claim
      </button>
    );
  }
  if (holder !== "" && holder === me) {
    return (
      <>
        <button className="btn claim-btn" disabled={busy} onClick={() => setReleasing(true)} aria-label={`Release ${label}`} title="You hold this package. Give it to someone else, or mark it N/A.">
          <Undo2 size={14} aria-hidden="true" /> Release
        </button>
        {releasing && (
          <ReleaseModal
            finding={finding}
            me={me}
            onClose={() => setReleasing(false)}
            onReleased={() => {
              setReleasing(false);
              onChanged();
            }}
          />
        )}
      </>
    );
  }
  if (holder !== "") {
    return (
      <button
        className="btn claim-btn primary"
        disabled={busy}
        onClick={() => void claim(`Reclaimed from ${holder}. It now appears under Workflows.`)}
        aria-label={`Reclaim ${label} from ${holder}`}
        title={`Held by ${holder}. Click to take it.`}
      >
        <HandHelping size={14} aria-hidden="true" /> Reclaim
      </button>
    );
  }
  return (
    <button className="btn claim-btn primary" disabled={busy} onClick={() => void claim("Claimed. It now appears under Workflows.")} aria-label={`Claim ${label}`}>
      <HandHelping size={14} aria-hidden="true" /> Claim
    </button>
  );
}
