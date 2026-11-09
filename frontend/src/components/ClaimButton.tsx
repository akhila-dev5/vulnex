import { useState } from "react";
import { HandHelping, Undo2 } from "lucide-react";
import { messageOf, request } from "../api/client";
import type { Finding } from "../api/types";
import { useApp } from "../app-context";

/**
 * "Claim" a package: its CVE is assigned to the signed-in Google account.
 *
 * Everyone sees the button, but only developers and the administrator can use it; for
 * visitors it stays disabled. The server checks the sign-in too, so hiding it is not the protection.
 */
export function ClaimButton({ finding, onChanged }: { finding: Finding; onChanged: () => void }) {
  const { token, roleInfo, canAdmin, canContribute, notify } = useApp();
  const [busy, setBusy] = useState(false);
  const owner = (finding.triage?.owner ?? "").trim();
  const me = (roleInfo.identity?.email ?? roleInfo.identity?.identity ?? "").trim().toLowerCase();
  const mine = owner !== "" && owner.toLowerCase() === me;
  const label = `${finding.package_name} ${finding.package_version ?? ""}`.trim();

  const send = async (path: "/triage/claim" | "/triage/release", done: string) => {
    setBusy(true);
    try {
      await request(
        path,
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
  if (mine) {
    return (
      <button className="btn claim-btn" disabled={busy} onClick={() => void send("/triage/release", "Released")} aria-label={`Release ${label}`} title="You claimed this package. Click to give it back.">
        <Undo2 size={14} aria-hidden="true" /> Release
      </button>
    );
  }
  if (owner && !canAdmin) {
    return (
      <button className="btn claim-btn" disabled title={`Already claimed by ${owner}`} aria-label={`${label} is claimed by ${owner}`}>
        Claimed
      </button>
    );
  }
  return (
    <button className="btn claim-btn primary" disabled={busy} onClick={() => void send("/triage/claim", "Claimed. It now appears under Workflows.")} aria-label={`Claim ${label}`}>
      <HandHelping size={14} aria-hidden="true" /> {owner ? "Take over" : "Claim"}
    </button>
  );
}
