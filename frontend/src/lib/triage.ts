import type { Finding } from "../api/types";

export type TriageAction = "assign" | "dispute" | "comment" | "patch" | "pr" | "rescore";

export type TriageValues = {
  text: string;
  disputeTag: string;
  disputeVersion: string;
  neverApplicable: boolean;
  patchVerdict: string;
  patchLink: string;
  availableSince: string;
  prNumber: string;
  prUrl: string;
  assigneeEmail: string;
  assignmentNotes: string;
  rescoreSeverity: string;
  rescoreScore: string;
  rescoreReason: string;
};

export const RESCORE_SEVERITIES = ["critical", "high", "medium", "low", "none"] as const;

/** The standard CVSS band for a score, used to suggest a severity as the score is typed. */
export function severityForScore(score: number): string {
  if (score <= 0) return "none";
  if (score < 4) return "low";
  if (score < 7) return "medium";
  if (score < 9) return "high";
  return "critical";
}

export const DEFAULT_ASSIGNEE = "gurujuakhila.dev@gmail.com";

export const ASSIGNEES = [
  { email: DEFAULT_ASSIGNEE, label: `${DEFAULT_ASSIGNEE} (Admin / Dev)` },
  { email: "dev1.vulnex@gmail.com", label: "dev1.vulnex@gmail.com" },
  { email: "dev2.vulnex@gmail.com", label: "dev2.vulnex@gmail.com" },
  { email: "dev3.vulnex@gmail.com", label: "dev3.vulnex@gmail.com" },
] as const;

export const DISPUTE_REASONS = [
  ["UPSTREAM", "Upstream says not affected"],
  ["VERSION", "Version not affected"],
  ["BACKPORT", "Fix already backported"],
  ["CONFIGURATION", "Vulnerable feature/configuration not used"],
  ["OTHER", "Other evidence"],
] as const;

export const ACTION_TITLE: Record<TriageAction, string> = {
  assign: "Assign CVE to a reviewer",
  dispute: "Dispute finding",
  comment: "Add triage comment",
  patch: "Patch availability",
  pr: "Set GitHub pull request",
  rescore: "Rescore CVE",
};

/** Assigning, setting a patch verdict and rescoring stay with the administrator; the rest is open to developers too. */
export const ADMIN_ONLY_ACTIONS: readonly TriageAction[] = ["assign", "patch", "rescore"];

export function canUseAction(
  action: TriageAction,
  who: { canAdmin: boolean; canContribute: boolean },
): boolean {
  return ADMIN_ONLY_ACTIONS.includes(action) ? who.canAdmin : who.canContribute;
}

export const ACTION_DONE: Record<TriageAction, string> = {
  assign: "CVE assigned",
  dispute: "Dispute sent to the administrator for approval",
  comment: "Comment saved",
  patch: "Patch verdict updated",
  pr: "GitHub PR recorded",
  rescore: "CVE rescored",
};

/** Form values for an action, pre-filled from what is already recorded on the finding. */
export function initialValues(f: Finding): TriageValues {
  return {
    text: "",
    disputeTag: "UPSTREAM",
    disputeVersion: "",
    neverApplicable: false,
    patchVerdict: f.triage?.final_verdict ?? "",
    patchLink: f.patch_availability?.patch_link ?? "",
    availableSince: f.patch_availability?.available_since ?? "",
    prNumber: f.triage?.github_pr_number ?? "",
    prUrl: f.triage?.github_pr_url ?? "",
    assigneeEmail: DEFAULT_ASSIGNEE,
    assignmentNotes: "",
    rescoreSeverity: RESCORE_SEVERITIES.find((s) => s === f.severity) ?? "medium",
    rescoreScore: f.cvss_score != null ? String(f.cvss_score) : "",
    rescoreReason: "",
  };
}

/** The API call that saves an action. Pure, so the exact payloads are unit-tested. */
export function buildTriageRequest(
  action: TriageAction,
  f: Finding,
  v: TriageValues,
): { path: string; body: Record<string, unknown> } {
  const ref = { cve_id: f.cve_id, branch: f.branch, spec_path: f.spec_path };
  switch (action) {
    case "assign":
      return {
        path: "/assignments",
        body: { ...ref, package_name: f.package_name, assignee_email: v.assigneeEmail, notes: v.assignmentNotes.trim() },
      };
    case "dispute":
      return {
        path: "/triage/dispute",
        body: {
          ...ref,
          reason: `${v.disputeTag}: ${v.text.trim()}`,
          first_unaffected_version: v.neverApplicable ? "" : v.disputeVersion.trim(),
          never_applicable: v.neverApplicable,
        },
      };
    case "comment":
      return { path: "/triage/comment", body: { ...ref, body: v.text.trim() } };
    case "patch":
      return {
        path: "/triage/patch",
        body: {
          ...ref,
          final_verdict: v.patchVerdict,
          patch_link: v.patchLink.trim(),
          available_since: v.availableSince.trim(),
        },
      };
    case "rescore":
      return {
        path: `/cves/${encodeURIComponent(f.cve_id)}/rescore`,
        body: {
          severity: v.rescoreSeverity,
          cvss_score: v.rescoreScore.trim() === "" ? null : Number(v.rescoreScore),
          reason: v.rescoreReason.trim(),
        },
      };
    case "pr":
      return { path: "/triage/github-pr", body: { ...ref, number: v.prNumber.trim(), url: v.prUrl.trim() } };
  }
}

/** Whether the form has what the action needs before it can be submitted. */
export function isSubmittable(action: TriageAction, v: TriageValues): boolean {
  if (action === "comment" || action === "dispute") return v.text.trim() !== "";
  if (action === "pr") return v.prNumber.trim() !== "";
  if (action === "rescore") {
    const score = v.rescoreScore.trim();
    const validScore = score === "" || (Number.isFinite(Number(score)) && Number(score) >= 0 && Number(score) <= 10);
    return v.rescoreReason.trim() !== "" && validScore;
  }
  return true;
}
