import type { Finding, FindingComment } from "../api/types";

/** Identifies one CVE on one package spec on one branch. */
export const findingKey = (f: Pick<Finding, "cve_id" | "branch" | "spec_path">): string =>
  [f.cve_id, f.branch, f.spec_path].join("::");

export const triageStatusOf = (f: Finding): string => f.triage?.triage_status || "open";
export const resolutionOf = (f: Finding): string => f.triage?.resolution_status || f.status || "";
export const ownerOf = (f: Finding): string => f.assignment?.assignee_email || f.triage?.owner || "";

export type CveGroup = { cveId: string; severity?: string; cvssScore?: number | null; rows: Finding[] };

/**
 * Put the rows of one CVE together, keeping the order in which each CVE first
 * appears (the API already orders by severity).
 */
export function groupByCve(rows: readonly Finding[]): CveGroup[] {
  const groups = new Map<string, CveGroup>();
  for (const row of rows) {
    const existing = groups.get(row.cve_id);
    if (existing) existing.rows.push(row);
    else groups.set(row.cve_id, { cveId: row.cve_id, severity: row.severity, cvssScore: row.cvss_score, rows: [row] });
  }
  return [...groups.values()];
}

const STATUS_ORDER: Record<string, number> = { affected: 0, unconfirmed: 1, patched: 2, false_positive: 3 };

/** Open exposures first, then by package name, for the packages table of one CVE. */
export function sortForCvePage(rows: readonly Finding[]): Finding[] {
  return [...rows].sort((a, b) => {
    const byStatus = (STATUS_ORDER[a.status ?? ""] ?? 9) - (STATUS_ORDER[b.status ?? ""] ?? 9);
    return byStatus !== 0 ? byStatus : a.package_name.localeCompare(b.package_name);
  });
}

/** The most recent dispute among a finding's comments (the API returns newest first or last; compare dates). */
export function latestDispute(comments: readonly FindingComment[]): FindingComment | undefined {
  const disputes = comments.filter((c) => c.kind === "dispute");
  return disputes.reduce<FindingComment | undefined>((best, c) => {
    if (!best) return c;
    return (c.created_at ?? "") >= (best.created_at ?? "") ? c : best;
  }, undefined);
}

export const specUrl = (owner: string, repo: string, f: Pick<Finding, "branch" | "spec_path">): string =>
  f.spec_path
    ? `https://github.com/${owner}/${repo}/blob/${encodeURIComponent(f.branch)}/${f.spec_path
        .split("/")
        .map(encodeURIComponent)
        .join("/")}`
    : "";
