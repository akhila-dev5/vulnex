import type { AppContextValue } from "../app-context";
import type { CveDetail, Finding, RoleInfo } from "../api/types";

export function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    cve_id: "CVE-2026-1000",
    package_name: "rabbitmq-server",
    package_version: "3.13.7-9",
    branch: "3.0",
    spec_path: "SPECS/rabbitmq-server/rabbitmq-server.spec",
    status: "affected",
    severity: "medium",
    cvss_score: 6.3,
    cvss_vector: "CVSS:4.0/AV:N/AC:L",
    description: "A test vulnerability.",
    fixed_version: "3.13.15",
    triage: null,
    patch_availability: { applicable: true, available: true, ai_verdict: "Patch Available", final_verdict: "Patch Available", possible_links: ["https://github.com/rabbitmq/rabbitmq-server/commit/0b4080f"], analysis: ["Upstream fix commit: abc"] },
    assignment: null,
    ...overrides,
  };
}

export const SECOND = finding({
  package_name: "zchunk",
  package_version: "1.3.2-1",
  spec_path: "SPECS/zchunk/zchunk.spec",
  status: "patched",
  patch_availability: { applicable: false, available: false, ai_verdict: "Not applicable" },
});

export const OTHER_CVE = finding({ cve_id: "CVE-2026-2000", severity: "high", package_name: "kernel", spec_path: "SPECS/kernel/kernel.spec" });

export const DETAIL: CveDetail = {
  cve_id: "CVE-2026-1000",
  findings: [SECOND, finding({ triage: { triage_status: "completed", resolution_status: "in_progress", github_pr_number: "19015", github_pr_url: "https://github.com/akhila-dev5/azurelinux-test/pull/19015", github_pr_set_by: "admin@example.org" } })],
  enrichment: { description: "RabbitMQ is a messaging broker.", published: "2026-09-25T00:00:00Z" },
  links: [
    { label: "Ubuntu", url: "https://ubuntu.com/security/CVE-2026-1000" },
    { label: "Debian", url: "https://security-tracker.debian.org/tracker/CVE-2026-1000" },
    { label: "Red Hat", url: "https://access.redhat.com/security/cve/CVE-2026-1000" },
    { label: "Mitre", url: "https://www.cve.org/CVERecord?id=CVE-2026-1000" },
    { label: "OSV", url: "https://osv.dev/vulnerability/CVE-2026-1000" },
  ],
};

export const ADMIN_ROLE: RoleInfo = { role: "admin", write_enabled: true };

export const adminContext: AppContextValue = {
  token: "tok",
  roleInfo: ADMIN_ROLE,
  canAdmin: true,
  canWrite: true,
  notify: () => undefined,
  signOut: () => undefined,
};

export const guestContext: AppContextValue = {
  token: "",
  roleInfo: { role: "viewer" },
  canAdmin: false,
  canWrite: false,
  notify: () => undefined,
  signOut: () => undefined,
};

/** A fetch stub that answers by URL path; unknown paths fail the test loudly. */
export function stubFetch(routes: Record<string, unknown | ((url: URL, init?: RequestInit) => unknown)>) {
  const calls: Array<{ url: URL; init?: RequestInit }> = [];
  const fn = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), "http://localhost");
    calls.push({ url, init });
    const key = url.pathname.replace(/^\/api/, "");
    const handler = routes[key];
    if (handler === undefined) throw new Error(`Unexpected request: ${url.pathname}`);
    const body = typeof handler === "function" ? (handler as (u: URL, i?: RequestInit) => unknown)(url, init) : handler;
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  };
  return { fn, calls };
}
