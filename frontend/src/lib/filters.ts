// The left-hand filter form. Every field maps to a query parameter the backend
// already understands (see GET /api/findings), so filtering and paging happen
// on the server, not in the browser.

export type Option = readonly [value: string, label: string];

export const BRANCH_OPTIONS: readonly Option[] = [
  ["3.0", "3.0"],
  ["4.0", "4.0"],
];
export const SEVERITY_OPTIONS: readonly Option[] = [
  ["critical", "Critical"],
  ["high", "High"],
  ["medium", "Medium"],
  ["low", "Low"],
  ["unknown", "Unknown"],
];
export const PATCH_OPTIONS: readonly Option[] = [
  ["available", "Patch available"],
  ["unavailable", "Patch not available"],
];
export const TRIAGE_OPTIONS: readonly Option[] = [
  ["open", "Open"],
  ["in_progress", "In progress"],
  ["completed", "Completed"],
  ["disputed", "Disputed"],
];
export const RESOLUTION_OPTIONS: readonly Option[] = [
  ["affected", "Affected"],
  ["disputed", "Disputed"],
  ["in_progress", "In progress"],
  ["published", "Published"],
];

export type Filters = {
  /** CVE or advisory id, or any text from the description (backend `search`). */
  cve: string;
  /** Exact package name (backend `package`). */
  pkg: string;
  branch: string;
  severity: string;
  patch: string;
  triage: string;
  resolution: string;
  owner: string;
  fixed: string;
};

export const DEFAULT_BRANCH = "3.0";

export const DEFAULT_FILTERS: Filters = {
  cve: "",
  pkg: "",
  branch: DEFAULT_BRANCH,
  severity: "",
  patch: "",
  triage: "",
  resolution: "",
  owner: "",
  fixed: "",
};

export const PAGE_SIZE = 25;
const MAX_TEXT = 100;

export function toFindingParams(f: Filters, page: number, limit = PAGE_SIZE): URLSearchParams {
  const p = new URLSearchParams({ branch: f.branch, page: String(page), limit: String(limit) });
  const set = (key: string, value: string) => {
    if (value.trim() !== "") p.set(key, value.trim());
  };
  set("search", f.cve);
  set("package", f.pkg);
  set("severity", f.severity);
  set("patch_state", f.patch);
  set("triage_status", f.triage);
  set("resolution_status", f.resolution);
  set("owner", f.owner);
  set("fixed_version", f.fixed);
  return p;
}

export function toPackageParams(f: Filters, page: number, limit = PAGE_SIZE): URLSearchParams {
  const p = new URLSearchParams({ branch: f.branch, page: String(page), limit: String(limit) });
  if (f.pkg.trim() !== "") p.set("search", f.pkg.trim());
  return p;
}

/** True when the form differs from its defaults, i.e. it is worth remembering. */
export function isActive(f: Filters): boolean {
  return (Object.keys(DEFAULT_FILTERS) as Array<keyof Filters>).some(
    (key) => f[key].trim() !== DEFAULT_FILTERS[key],
  );
}

const labelOf = (options: readonly Option[], value: string): string =>
  options.find(([v]) => v === value)?.[1] ?? value;

/** One readable line per active field, used for the "Recent searches" list. */
export function describeFilters(f: Filters): string[] {
  const lines: string[] = [];
  if (f.cve.trim()) lines.push(`CVE / text: ${f.cve.trim()}`);
  if (f.pkg.trim()) lines.push(`Package: ${f.pkg.trim()}`);
  lines.push(`Branch: ${f.branch}`);
  if (f.severity) lines.push(`Severity: ${labelOf(SEVERITY_OPTIONS, f.severity)}`);
  if (f.patch) lines.push(`Patch: ${labelOf(PATCH_OPTIONS, f.patch)}`);
  if (f.triage) lines.push(`Triage: ${labelOf(TRIAGE_OPTIONS, f.triage)}`);
  if (f.resolution) lines.push(`Resolution: ${labelOf(RESOLUTION_OPTIONS, f.resolution)}`);
  if (f.owner.trim()) lines.push(`Owner: ${f.owner.trim()}`);
  if (f.fixed.trim()) lines.push(`Fixed in: ${f.fixed.trim()}`);
  return lines;
}

export const filtersKey = (f: Filters): string => JSON.stringify(f);

const text = (v: unknown): string => (typeof v === "string" ? v.trim().slice(0, MAX_TEXT) : "");
const choice = (v: unknown, options: readonly Option[], fallback: string): string =>
  typeof v === "string" && options.some(([o]) => o === v) ? v : fallback;

/**
 * Rebuild a Filters object from untrusted data (browser storage can be edited by
 * anyone with the page open). Unknown values fall back to the defaults.
 */
export function sanitizeFilters(raw: unknown): Filters {
  const o = (typeof raw === "object" && raw !== null ? raw : {}) as Record<string, unknown>;
  return {
    cve: text(o.cve),
    pkg: text(o.pkg),
    branch: choice(o.branch, BRANCH_OPTIONS, DEFAULT_BRANCH),
    severity: choice(o.severity, SEVERITY_OPTIONS, ""),
    patch: choice(o.patch, PATCH_OPTIONS, ""),
    triage: choice(o.triage, TRIAGE_OPTIONS, ""),
    resolution: choice(o.resolution, RESOLUTION_OPTIONS, ""),
    owner: text(o.owner),
    fixed: text(o.fixed),
  };
}

// -- recent searches ---------------------------------------------------------
export const RECENT_KEY = "vulnex.recentSearches";
export const MAX_RECENT = 8;

export function addRecent(list: readonly Filters[], f: Filters): Filters[] {
  if (!isActive(f)) return [...list];
  const key = filtersKey(f);
  return [f, ...list.filter((x) => filtersKey(x) !== key)].slice(0, MAX_RECENT);
}

export function removeRecent(list: readonly Filters[], f: Filters): Filters[] {
  const key = filtersKey(f);
  return list.filter((x) => filtersKey(x) !== key);
}

export function loadRecent(): Filters[] {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(RECENT_KEY) ?? "[]");
    return Array.isArray(parsed) ? parsed.slice(0, MAX_RECENT).map(sanitizeFilters) : [];
  } catch {
    return [];
  }
}

export function saveRecent(list: readonly Filters[]): void {
  try {
    window.localStorage.setItem(RECENT_KEY, JSON.stringify(list));
  } catch {
    /* Recent searches are a convenience; losing them is fine. */
  }
}
