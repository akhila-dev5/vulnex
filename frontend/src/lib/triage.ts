import type { Finding } from "../api/types";

export type TriageAction = "assign" | "dispute" | "comment" | "patch" | "pr";

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
};

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
};

export const ACTION_DONE: Record<TriageAction, string> = {
  assign: "CVE assigned",
  dispute: "Dispute recorded",
  comment: "Comment saved",
  patch: "Patch verdict updated",
  pr: "GitHub PR recorded",
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
    case "pr":
      return { path: "/triage/github-pr", body: { ...ref, number: v.prNumber.trim(), url: v.prUrl.trim() } };
  }
}

/** Whether the form has what the action needs before it can be submitted. */
export function isSubmittable(action: TriageAction, v: TriageValues): boolean {
  if (action === "comment" || action === "dispute") return v.text.trim() !== "";
  if (action === "pr") return v.prNumber.trim() !== "";
  return true;
}
