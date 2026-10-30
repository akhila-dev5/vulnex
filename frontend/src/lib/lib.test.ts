import { describe, expect, it } from "vitest";
import {
  DEFAULT_FILTERS,
  MAX_RECENT,
  RECENT_KEY,
  addRecent,
  describeFilters,
  isActive,
  loadRecent,
  removeRecent,
  sanitizeFilters,
  toFindingParams,
  toPackageParams,
  type Filters,
} from "./filters";
import { groupByCve, latestDispute, sortForCvePage, specUrl } from "./findings";
import { hrefFor, parseRoute } from "./route";
import { SESSION_KEY, clearToken, consumeTokenHandoff, loadToken, saveToken } from "./session";
import { buildTriageRequest, initialValues, isSubmittable } from "./triage";
import { finding } from "../test/fixtures";

describe("route", () => {
  it("parses the three pages", () => {
    expect(parseRoute("")).toEqual({ name: "cves" });
    expect(parseRoute("#/")).toEqual({ name: "cves" });
    expect(parseRoute("#/packages")).toEqual({ name: "packages" });
    expect(parseRoute("#/cve/cve-2026-1234")).toEqual({ name: "cve", id: "CVE-2026-1234" });
  });
  it("rejects malformed ids and unknown paths", () => {
    expect(parseRoute("#/cve/")).toEqual({ name: "notfound" });
    expect(parseRoute("#/cve/../../etc")).toEqual({ name: "notfound" });
    expect(parseRoute("#/cve/%E0%A4%A")).toEqual({ name: "notfound" });
    expect(parseRoute("#/nope")).toEqual({ name: "notfound" });
  });
  it("round-trips a CVE link", () => {
    expect(hrefFor({ name: "cve", id: "CVE-2026-1234" })).toBe("#/cve/CVE-2026-1234");
    expect(parseRoute(hrefFor({ name: "cve", id: "AZL-77" }))).toEqual({ name: "cve", id: "AZL-77" });
  });
});

describe("filters", () => {
  const active: Filters = { ...DEFAULT_FILTERS, cve: " CVE-1 ", severity: "high", patch: "available" };

  it("sends only filled fields to the API, trimmed", () => {
    const p = toFindingParams(active, 2);
    expect(p.get("search")).toBe("CVE-1");
    expect(p.get("severity")).toBe("high");
    expect(p.get("patch_state")).toBe("available");
    expect(p.get("page")).toBe("2");
    expect(p.get("branch")).toBe("3.0");
    expect(p.has("owner")).toBe(false);
  });
  it("builds package params from the package field only", () => {
    expect(toPackageParams({ ...DEFAULT_FILTERS, pkg: "curl" }, 1).get("search")).toBe("curl");
  });
  it("knows when the form is worth remembering", () => {
    expect(isActive(DEFAULT_FILTERS)).toBe(false);
    expect(isActive(active)).toBe(true);
    expect(isActive({ ...DEFAULT_FILTERS, branch: "4.0" })).toBe(true);
  });
  it("describes active fields readably", () => {
    expect(describeFilters(active)).toEqual(["CVE / text: CVE-1", "Branch: 3.0", "Severity: High", "Patch: Patch available"]);
  });
  it("sanitizes tampered storage", () => {
    const clean = sanitizeFilters({ cve: "x".repeat(500), severity: "<script>", branch: "9.9", owner: 7 });
    expect(clean.cve).toHaveLength(100);
    expect(clean.severity).toBe("");
    expect(clean.branch).toBe("3.0");
    expect(clean.owner).toBe("");
  });
  it("keeps recent searches unique, newest first, capped, and skips empty forms", () => {
    expect(addRecent([], DEFAULT_FILTERS)).toEqual([]);
    const a = { ...DEFAULT_FILTERS, cve: "a" };
    const b = { ...DEFAULT_FILTERS, cve: "b" };
    expect(addRecent(addRecent([], a), b)).toEqual([b, a]);
    expect(addRecent([b, a], a)).toEqual([a, b]);
    expect(removeRecent([b, a], b)).toEqual([a]);
    let list: Filters[] = [];
    for (let i = 0; i < MAX_RECENT + 4; i++) list = addRecent(list, { ...DEFAULT_FILTERS, cve: String(i) });
    expect(list).toHaveLength(MAX_RECENT);
  });
  it("survives corrupt recent-search storage", () => {
    window.localStorage.setItem(RECENT_KEY, "{not json");
    expect(loadRecent()).toEqual([]);
    window.localStorage.setItem(RECENT_KEY, JSON.stringify([{ cve: "ok", severity: "bogus" }, "junk"]));
    const loaded = loadRecent();
    expect(loaded[0]?.cve).toBe("ok");
    expect(loaded[0]?.severity).toBe("");
  });
});

describe("session", () => {
  it("stores and clears the token", () => {
    expect(loadToken()).toBe("");
    saveToken("abc");
    expect(window.localStorage.getItem(SESSION_KEY)).toBe("abc");
    expect(loadToken()).toBe("abc");
    clearToken();
    expect(loadToken()).toBe("");
  });
  it("takes the Google hand-off token out of the URL", () => {
    window.location.hash = "#vulnex_token=tok_123-AB";
    expect(consumeTokenHandoff()).toBe(true);
    expect(loadToken()).toBe("tok_123-AB");
    expect(window.location.hash).toBe("#/");
  });
  it("ignores a URL without a token", () => {
    window.location.hash = "#/packages";
    expect(consumeTokenHandoff()).toBe(false);
    expect(loadToken()).toBe("");
  });
});

describe("findings helpers", () => {
  const a1 = finding({ cve_id: "CVE-1", package_name: "b" });
  const b1 = finding({ cve_id: "CVE-2", package_name: "z" });
  const a2 = finding({ cve_id: "CVE-1", package_name: "a", spec_path: "x" });

  it("groups rows by CVE in order of first appearance", () => {
    const groups = groupByCve([a1, b1, a2]);
    expect(groups.map((g) => g.cveId)).toEqual(["CVE-1", "CVE-2"]);
    expect(groups[0]?.rows).toHaveLength(2);
  });
  it("lists open exposures first on the CVE page", () => {
    const patched = finding({ status: "patched", package_name: "a" });
    const open = finding({ status: "affected", package_name: "z" });
    expect(sortForCvePage([patched, open]).map((f) => f.status)).toEqual(["affected", "patched"]);
  });
  it("finds the newest dispute", () => {
    const d = latestDispute([
      { kind: "dispute", body: "old", created_at: "2026-01-01" },
      { kind: "comment", body: "c", created_at: "2026-03-01" },
      { kind: "dispute", body: "new", created_at: "2026-02-01" },
    ]);
    expect(d?.body).toBe("new");
    expect(latestDispute([])).toBeUndefined();
  });
  it("builds an encoded spec URL", () => {
    expect(specUrl("o", "r", { branch: "3.0", spec_path: "SPECS/a b/a.spec" })).toBe("https://github.com/o/r/blob/3.0/SPECS/a%20b/a.spec");
    expect(specUrl("o", "r", { branch: "3.0", spec_path: "" })).toBe("");
  });
});

describe("triage requests", () => {
  const f = finding();
  const v = { ...initialValues(f), text: "  evidence  " };

  it("builds the dispute payload with the reason tag and trimmed text", () => {
    const { path, body } = buildTriageRequest("dispute", f, { ...v, disputeVersion: " 3.13.15-1 " });
    expect(path).toBe("/triage/dispute");
    expect(body).toMatchObject({ reason: "UPSTREAM: evidence", first_unaffected_version: "3.13.15-1", never_applicable: false, cve_id: f.cve_id, branch: "3.0" });
  });
  it("drops the version when never applicable", () => {
    const { body } = buildTriageRequest("dispute", f, { ...v, disputeVersion: "1.0", neverApplicable: true });
    expect(body).toMatchObject({ first_unaffected_version: "", never_applicable: true });
  });
  it("builds comment, PR, patch and assignment payloads", () => {
    expect(buildTriageRequest("comment", f, v)).toMatchObject({ path: "/triage/comment", body: { body: "evidence" } });
    expect(buildTriageRequest("pr", f, { ...v, prNumber: " 19015 " })).toMatchObject({ path: "/triage/github-pr", body: { number: "19015" } });
    expect(buildTriageRequest("patch", f, { ...v, patchVerdict: "Patch Available" })).toMatchObject({ path: "/triage/patch", body: { final_verdict: "Patch Available" } });
    expect(buildTriageRequest("assign", f, v)).toMatchObject({ path: "/assignments", body: { package_name: "rabbitmq-server", assignee_email: "gurujuakhila.dev@gmail.com" } });
  });
  it("requires the fields each action needs", () => {
    expect(isSubmittable("comment", initialValues(f))).toBe(false);
    expect(isSubmittable("comment", v)).toBe(true);
    expect(isSubmittable("pr", initialValues(finding({ triage: null })))).toBe(false);
    expect(isSubmittable("patch", initialValues(f))).toBe(true);
  });
  it("pre-fills the PR form from what is recorded", () => {
    const withPr = finding({ triage: { github_pr_number: "7", github_pr_url: "https://github.com/a/b/pull/7" } });
    expect(initialValues(withPr)).toMatchObject({ prNumber: "7", prUrl: "https://github.com/a/b/pull/7" });
  });
});
