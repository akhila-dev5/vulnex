import { useState } from "react";
import { Undo2 } from "lucide-react";
import { messageOf, request } from "../api/client";
import type { Finding } from "../api/types";
import { useApp } from "../app-context";

/**
 * The one action on a Workflows row: give the package back.
 *
 * Every row is already held by someone (claimed or assigned), so there is nothing to claim.
 * Only the holder or the administrator can release it; for anyone else the button is
 * disabled and says who holds it. The server enforces the same rule.
 */
export function ReleaseButton({ finding, holder, onChanged }: { finding: Finding; holder: string; onChanged: () => void }) {
  const { token, roleInfo, canAdmin, notify } = useApp();
  const [busy, setBusy] = useState(false);
  const me = (roleInfo.identity?.email ?? roleInfo.identity?.identity ?? "").trim().toLowerCase();
  const allowed = canAdmin || holder.trim().toLowerCase() === me;
  const label = `${finding.package_name} ${finding.package_version ?? ""}`.trim();

  const release = async () => {
    setBusy(true);
    try {
      await request(
        "/triage/release",
        {
          method: "POST",
          body: JSON.stringify({
            cve_id: finding.cve_id,
            branch: finding.branch ?? "",
            spec_path: finding.spec_path ?? "",
            package_name: finding.package_name,
          }),
        },
        token,
      );
      notify("Released");
      onChanged();
    } catch (error) {
      notify(messageOf(error));
    } finally {
      setBusy(false);
    }
  };

  return (
    <button
      className="btn claim-btn"
      disabled={busy || !allowed}
      onClick={() => void release()}
      aria-label={`Release ${label}`}
      title={allowed ? "Give this package back" : `Held by ${holder}. Only they or an admin can release it.`}
    >
      <Undo2 size={14} aria-hidden="true" /> Release
    </button>
  );
}
