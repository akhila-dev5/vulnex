const LABELS: Record<string, string> = {
  open: "Open",
  in_progress: "In progress",
  completed: "Completed",
  disputed: "Disputed",
  pending_dispute: "Pending dispute",
  affected: "Affected",
  published: "Published",
  fixed: "Fixed",
  patched: "Patched",
  false_positive: "False positive",
  unconfirmed: "Unconfirmed",
};

/** Human label for a backend status string; unknown values are tidied, not hidden. */
export function statusLabel(value?: string | null): string {
  const v = (value ?? "").trim();
  if (!v) return "—";
  const known = LABELS[v.toLowerCase()];
  if (known) return known;
  const spaced = v.replace(/_/g, " ");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

/** Colour family for a status pill. The label always carries the meaning too. */
export function statusTone(value?: string | null): string {
  switch ((value ?? "").toLowerCase()) {
    case "completed":
    case "published":
    case "fixed":
    case "patched":
      return "good";
    case "affected":
    case "unconfirmed":
      return "warning";
    case "in_progress":
      return "info";
    case "disputed":
    case "pending_dispute":
      return "dispute";
    default:
      return "neutral";
  }
}

export function severityTone(value?: string | null): string {
  const v = (value ?? "unknown").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(v) ? v : "unknown";
}

export function severityLabel(value?: string | null): string {
  const v = (value ?? "").trim();
  return v ? v.charAt(0).toUpperCase() + v.slice(1).toLowerCase() : "Unknown";
}

export function formatDateTime(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : date.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
}
