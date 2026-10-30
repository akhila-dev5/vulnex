import { CheckCircle2, HelpCircle, MinusCircle, XCircle } from "lucide-react";
import type { Finding } from "../api/types";

/** Patch availability as an icon. The icon shape and the hidden text both carry the meaning, not colour alone. */
export function PatchIcon({ finding }: { finding: Finding }) {
  const patch = finding.patch_availability;
  let kind: "yes" | "no" | "na" | "unknown";
  let label: string;
  if (patch?.available) {
    kind = "yes";
    label = "Candidate patch found";
  } else if (patch?.applicable === false) {
    kind = "na";
    label = "Patch not applicable";
  } else if (patch?.applicable === true) {
    kind = "no";
    label = "No candidate patch found";
  } else {
    kind = "unknown";
    label = "Patch availability unknown";
  }
  const Icon = { yes: CheckCircle2, no: XCircle, na: MinusCircle, unknown: HelpCircle }[kind];
  return (
    <span className={`patch-icon ${kind}`} title={label}>
      <Icon size={17} aria-hidden="true" />
      <span className="sr-only">{label}</span>
    </span>
  );
}
