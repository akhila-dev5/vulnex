import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppContext, type AppContextValue } from "../app-context";
import { TopNav } from "../components/TopNav";
import { ADMIN_ROLE, DETAIL, OTHER_CVE, SECOND, adminContext, developerContext, finding, guestContext, stubFetch } from "../test/fixtures";
import { DisputesPage } from "./DisputesPage";
import { CveDetailPage } from "./CveDetailPage";
import { CvesPage } from "./CvesPage";

const STATS = { total_packages: 1549, total_findings: 4189, distinct_cves: 1900, severity: { critical: 3, high: 10 }, last_scan: { finished_at: "2026-10-29T13:10:50+00:00", branches: "3.0" } };
const COMMENTS = {
  items: [
    { id: 1, kind: "comment", author: "admin@example.org", body: "Fixed in v3.13.15", created_at: "2026-10-01T12:26:08Z" },
    { id: 2, kind: "dispute", author: "admin@example.org", body: "UPSTREAM: maintainers say not affected", created_at: "2026-10-02T09:00:00Z" },
  ],
};

function renderWith(ctx: AppContextValue, ui: React.ReactElement) {
  return render(<AppContext.Provider value={ctx}>{ui}</AppContext.Provider>);
}

beforeEach(() => vi.unstubAllGlobals());
afterEach(() => vi.unstubAllGlobals());

describe("top navigation", () => {
  it("offers CVEs, Packages and Disputes, in that order", () => {
    renderWith(guestContext, <TopNav route={{ name: "cves" }} />);
    const nav = screen.getByRole("navigation", { name: /main navigation/i });
    expect(within(nav).getAllByRole("link").map((a) => a.textContent)).toEqual(["CVEs", "Packages", "Disputes"]);
    expect(within(nav).getByRole("link", { name: "CVEs" })).toHaveAttribute("aria-current", "page");
  });
  it("keeps CVEs highlighted on a CVE page", () => {
    renderWith(guestContext, <TopNav route={{ name: "cve", id: "CVE-2026-1" }} />);
    expect(screen.getByRole("link", { name: "CVEs" })).toHaveAttribute("aria-current", "page");
  });
  it("labels the signed-in role", () => {
    const { unmount } = renderWith(developerContext, <TopNav route={{ name: "cves" }} />);
    expect(screen.getByText("Developer")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
    unmount();
    vi.stubGlobal("fetch", stubFetch({ "/disputes": { items: [], total: 0, counts: { pending: 3, approved: 0, rejected: 0 } } }).fn);
    renderWith(adminContext, <TopNav route={{ name: "cves" }} />);
    expect(screen.getByText("Administrator")).toBeInTheDocument();
  });
  it("shows the administrator how many disputes are waiting", async () => {
    vi.stubGlobal("fetch", stubFetch({ "/disputes": { items: [], total: 0, counts: { pending: 3, approved: 1, rejected: 0 } } }).fn);
    renderWith(adminContext, <TopNav route={{ name: "cves" }} />);
    expect(await screen.findByLabelText("3 waiting for approval")).toBeInTheDocument();
  });
  it("shows sign-in to guests and sign-out to the administrator", () => {
    const { unmount } = renderWith(guestContext, <TopNav route={{ name: "cves" }} />);
    expect(screen.getByRole("link", { name: /sign in with google/i })).toBeInTheDocument();
    unmount();
    renderWith(adminContext, <TopNav route={{ name: "cves" }} />);
    expect(screen.getByRole("button", { name: /sign out/i })).toBeInTheDocument();
  });
});

describe("CVEs page (home)", () => {
  const routes = { "/stats": STATS, "/findings": { items: [finding(), SECOND, OTHER_CVE], total: 3 } };

  it("lists findings grouped by CVE with the filters on the left", async () => {
    vi.stubGlobal("fetch", stubFetch(routes).fn);
    renderWith(guestContext, <CvesPage />);
    expect(await screen.findByText("rabbitmq-server")).toBeInTheDocument();
    expect(screen.getByRole("complementary", { name: /search filters/i })).toBeInTheDocument();
    expect(screen.getAllByRole("rowgroup").length).toBeGreaterThan(2); // header + one body per CVE
    expect(screen.getByText("zchunk")).toBeInTheDocument();
    expect(screen.getByText("kernel")).toBeInTheDocument();
  });

  it("has no Deep, Actions or Assign buttons", async () => {
    vi.stubGlobal("fetch", stubFetch(routes).fn);
    renderWith(adminContext, <CvesPage />);
    await screen.findByText("rabbitmq-server");
    expect(screen.queryByRole("button", { name: /deep/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /^actions/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /assign/i })).toBeNull();
    expect(screen.queryByRole("menuitem")).toBeNull();
  });

  it("opens each CVE in a new tab", async () => {
    vi.stubGlobal("fetch", stubFetch(routes).fn);
    renderWith(guestContext, <CvesPage />);
    await screen.findByText("rabbitmq-server");
    const link = screen.getByRole("link", { name: /CVE-2026-1000/ });
    expect(link).toHaveAttribute("href", "#/cve/CVE-2026-1000");
    expect(link).toHaveAttribute("target", "_blank");
    expect(link.getAttribute("rel")).toContain("noopener");
  });

  it("sends the filters to the server and remembers the search", async () => {
    const { fn, calls } = stubFetch(routes);
    vi.stubGlobal("fetch", fn);
    const user = userEvent.setup();
    renderWith(guestContext, <CvesPage />);
    await screen.findByText("rabbitmq-server");

    await user.type(screen.getByLabelText(/package \(exact name\)/i), "rabbitmq-server");
    await user.selectOptions(screen.getByLabelText(/severity/i), "high");
    await user.click(screen.getByRole("button", { name: /search cves/i }));

    await vi.waitFor(() => {
      const last = calls.filter((c) => c.url.pathname === "/api/findings").at(-1);
      expect(last?.url.searchParams.get("package")).toBe("rabbitmq-server");
      expect(last?.url.searchParams.get("severity")).toBe("high");
      expect(last?.url.searchParams.get("page")).toBe("1");
    });
    const recent = screen.getByRole("region", { name: /recent searches/i });
    expect(within(recent).getByText("Package: rabbitmq-server")).toBeInTheDocument();

    await user.click(within(recent).getByRole("button", { name: /remove recent search/i }));
    expect(within(recent).getByText(/searches you run appear here/i)).toBeInTheDocument();
  });

  it("shows an empty state and an error without crashing", async () => {
    vi.stubGlobal("fetch", stubFetch({ "/stats": STATS, "/findings": { items: [], total: 0 } }).fn);
    const { unmount } = renderWith(guestContext, <CvesPage />);
    expect(await screen.findByText(/no findings match these filters/i)).toBeInTheDocument();
    unmount();
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ detail: "Database unavailable" }), { status: 500 }));
    renderWith(guestContext, <CvesPage />);
    expect(await screen.findByRole("alert")).toHaveTextContent("Database unavailable");
  });
});

describe("CVE page", () => {
  const routes = (extra: Record<string, unknown> = {}) => ({ "/cves/CVE-2026-1000": DETAIL, "/triage/comments": COMMENTS, ...extra });

  it("shows the header, tracker links and every affected package", async () => {
    vi.stubGlobal("fetch", stubFetch(routes()).fn);
    renderWith(guestContext, <CveDetailPage id="CVE-2026-1000" />);
    expect(await screen.findByRole("heading", { level: 1, name: "CVE-2026-1000" })).toBeInTheDocument();
    const trackers = screen.getByRole("navigation", { name: /external trackers/i });
    expect(within(trackers).getAllByRole("link").map((a) => a.textContent?.trim())).toEqual(["Ubuntu", "Debian", "Red Hat", "Mitre", "OSV"]);
    expect(screen.getByText("RabbitMQ is a messaging broker.")).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("rabbitmq-server")).toBeInTheDocument();
    expect(within(table).getByText("zchunk")).toBeInTheDocument();
  });

  it("gives every package a Deep button and an Actions menu", async () => {
    vi.stubGlobal("fetch", stubFetch(routes()).fn);
    renderWith(guestContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    expect(screen.getAllByRole("button", { name: /deep inspection of/i })).toHaveLength(2);
    expect(screen.getAllByRole("button", { name: /^actions for/i })).toHaveLength(2);
  });

  it("opens the Deep view for one package", async () => {
    const deep = { upstream_fixed_version: "9.9.9-upstream", affected_files: ["lib/x.c"], backport_patches: [], tarball: { name: "rabbitmq.tar.gz", available: true }, notes: [] };
    const { fn, calls } = stubFetch(routes({ "/cves/CVE-2026-1000/deep": deep }));
    vi.stubGlobal("fetch", fn);
    const user = userEvent.setup();
    renderWith(guestContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getByRole("button", { name: /deep inspection of rabbitmq-server/i }));
    expect(await screen.findByText("lib/x.c")).toBeInTheDocument();
    const upstream = screen.getByRole("heading", { name: "Upstream fixed version" }).closest("section")!;
    expect(within(upstream).getByText("9.9.9-upstream")).toBeInTheDocument();
    expect(calls.at(-1)?.url.searchParams.get("spec")).toBe("SPECS/rabbitmq-server/rabbitmq-server.spec");
  });

  it("disables the actions for guests and explains why", async () => {
    vi.stubGlobal("fetch", stubFetch(routes()).fn);
    const user = userEvent.setup();
    renderWith(guestContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getAllByRole("button", { name: /^actions for/i })[0]!);
    const items = screen.getAllByRole("menuitem");
    expect(items.map((i) => i.textContent?.trim())).toEqual(["Set GitHub PR", "Dispute", "Add comment", "Patch verdict", "Assign reviewer"]);
    items.forEach((item) => expect(item).toBeDisabled());
    expect(screen.getByText(/sign in with google to use these actions/i)).toBeInTheDocument();
  });

  it("draws the Actions menu outside the table so the table's scroll box cannot clip it", async () => {
    vi.stubGlobal("fetch", stubFetch(routes()).fn);
    const user = userEvent.setup();
    renderWith(guestContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getAllByRole("button", { name: /^actions for/i })[0]!);
    const menu = screen.getByRole("menu");
    // Inside the table it sits under `.table-scroll { overflow-x: auto }` and
    // `.table-card { overflow: hidden }`, which cut it off.
    expect(menu.closest(".table-card, .table-scroll, table")).toBeNull();
    expect(menu.parentElement).toBe(document.body);
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("menu")).toBeNull();
  });

  it("expands to the GitHub PR, patch availability, triage info, dispute reason and comments", async () => {
    const { fn, calls } = stubFetch(routes());
    vi.stubGlobal("fetch", fn);
    const user = userEvent.setup();
    renderWith(guestContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getByRole("button", { name: /show triage details for rabbitmq-server/i }));

    expect(await screen.findByRole("heading", { name: "GitHub PR" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /#19015/ })).toHaveAttribute("href", "https://github.com/akhila-dev5/azurelinux-test/pull/19015");
    expect(screen.getByRole("heading", { name: "Patch availability" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Triage information" })).toBeInTheDocument();
    const disputeBlock = (await screen.findByRole("heading", { name: "Approved dispute" })).closest("section")!;
    expect(within(disputeBlock).getByText("UPSTREAM: maintainers say not affected")).toBeInTheDocument();
    expect(screen.getByText("Fixed in v3.13.15")).toBeInTheDocument();
    const commentCall = calls.find((c) => c.url.pathname === "/api/triage/comments");
    expect(commentCall?.url.searchParams.get("cve_id")).toBe("CVE-2026-1000");
    expect(screen.getByRole("button", { name: /add comment/i })).toBeDisabled();
  });

  it("lets the administrator set a GitHub PR and refreshes afterwards", async () => {
    let posted: unknown;
    const notify = vi.fn();
    const { fn, calls } = stubFetch(
      routes({ "/triage/github-pr": (_u: URL, init?: RequestInit) => ((posted = JSON.parse(String(init?.body))), { ok: true }) }),
    );
    vi.stubGlobal("fetch", fn);
    const user = userEvent.setup();
    renderWith({ ...adminContext, notify, roleInfo: ADMIN_ROLE }, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getAllByRole("button", { name: /^actions for rabbitmq-server/i })[0]!);
    await user.click(screen.getByRole("menuitem", { name: /set github pr/i }));

    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByRole("heading", { name: /set github pull request/i })).toBeInTheDocument();
    const number = within(dialog).getByLabelText(/pr number/i);
    await user.clear(number);
    await user.type(number, "19016");
    await user.click(within(dialog).getByRole("button", { name: /save changes/i }));

    await vi.waitFor(() => expect(notify).toHaveBeenCalledWith("GitHub PR recorded"));
    expect(posted).toMatchObject({ cve_id: "CVE-2026-1000", number: "19016", branch: "3.0" });
    expect(calls.filter((c) => c.url.pathname === "/api/cves/CVE-2026-1000").length).toBeGreaterThan(1);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(calls.find((c) => c.url.pathname === "/api/triage/github-pr")?.init?.headers).toBeDefined();
  });

  it("shows the server's message when a triage action is refused", async () => {
    vi.stubGlobal("fetch", async (input: RequestInfo | URL) => {
      const path = new URL(String(input), "http://localhost").pathname;
      if (path === "/api/triage/comment") return new Response(JSON.stringify({ detail: "Read-only access: this action needs an admin sign-in." }), { status: 401 });
      return new Response(JSON.stringify(path.includes("/cves/") ? DETAIL : COMMENTS), { status: 200 });
    });
    const user = userEvent.setup();
    renderWith(adminContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getAllByRole("button", { name: /^actions for rabbitmq-server/i })[0]!);
    await user.click(screen.getByRole("menuitem", { name: /add comment/i }));
    await user.type(screen.getByLabelText(/^comment$/i), "hello");
    await user.click(screen.getByRole("button", { name: /save changes/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/needs an admin sign-in/i);
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("reports an unknown CVE", async () => {
    vi.stubGlobal("fetch", async () => new Response(JSON.stringify({ detail: "CVE not found in the current scan" }), { status: 404 }));
    renderWith(guestContext, <CveDetailPage id="CVE-2000-0001" />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/CVE not found in the current scan/);
    expect(screen.getByRole("link", { name: /all cves/i })).toHaveAttribute("href", "#/");
  });
});


describe("Fixed version column (azurelinux-test release, never the upstream version)", () => {
  const fixedCell = (name: string) => {
    const row = screen.getByText(name).closest("tr")!;
    const header = screen.getAllByRole("columnheader").findIndex((h) => h.textContent === "Fixed version");
    return within(row).getAllByRole("cell")[header]!;
  };

  it("on the CVE page: an unfixed package is blank even though upstream has a fix", async () => {
    vi.stubGlobal("fetch", stubFetch({ "/cves/CVE-2026-1000": DETAIL, "/triage/comments": COMMENTS }).fn);
    renderWith(guestContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    // rabbitmq-server is affected and its upstream fixed version is 3.13.15.
    expect(fixedCell("rabbitmq-server")).toHaveTextContent("—");
    expect(screen.queryByText("3.13.15")).toBeNull();
    // zchunk is patched: show the release that patched it.
    expect(fixedCell("zchunk")).toHaveTextContent("1.3.1-4");
  });

  it("on the CVEs list: same rule", async () => {
    vi.stubGlobal("fetch", stubFetch({ "/stats": STATS, "/findings": { items: [finding(), SECOND], total: 2 } }).fn);
    renderWith(guestContext, <CvesPage />);
    await screen.findByText("rabbitmq-server");
    expect(fixedCell("rabbitmq-server")).toHaveTextContent("—");
    expect(fixedCell("zchunk")).toHaveTextContent("1.3.1-4");
    expect(screen.queryByText("3.13.15")).toBeNull();
  });

  it("marks a release that is only bounded by the scanned version", async () => {
    const bounded = finding({ status: "patched", package_name: "demo", azl_fixed_version: "2.0-5", azl_fixed_basis: "spec-evr" });
    vi.stubGlobal("fetch", stubFetch({ "/stats": STATS, "/findings": { items: [bounded], total: 1 } }).fn);
    renderWith(guestContext, <CvesPage />);
    await screen.findByText("demo");
    const cell = fixedCell("demo");
    expect(cell).toHaveTextContent("2.0-5");
    expect(within(cell).getByTitle(/No changelog entry names this CVE/)).toBeInTheDocument();
  });

  it("labels the sidebar filter as the Azure Linux fix", async () => {
    vi.stubGlobal("fetch", stubFetch({ "/stats": STATS, "/findings": { items: [], total: 0 } }).fn);
    renderWith(guestContext, <CvesPage />);
    expect(await screen.findByLabelText(/fixed version \(azure linux\)/i)).toBeInTheDocument();
  });
});

describe("Actions by role", () => {
  const routes = { "/cves/CVE-2026-1000": DETAIL, "/triage/comments": COMMENTS };
  const states = async (ctx: AppContextValue) => {
    vi.stubGlobal("fetch", stubFetch(routes).fn);
    const user = userEvent.setup();
    renderWith(ctx, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getAllByRole("button", { name: /^actions for/i })[0]!);
    return Object.fromEntries(screen.getAllByRole("menuitem").map((i) => [i.textContent!.trim(), !(i as HTMLButtonElement).disabled]));
  };

  it("lets a developer set a PR, dispute and comment, but not assign or set a patch verdict", async () => {
    expect(await states(developerContext)).toEqual({
      "Set GitHub PR": true, Dispute: true, "Add comment": true, "Patch verdict": false, "Assign reviewer": false,
    });
    expect(screen.getByText(/administrator-only/i)).toBeInTheDocument();
  });
  it("lets the administrator use every action", async () => {
    expect(Object.values(await states(adminContext)).every(Boolean)).toBe(true);
  });
  it("lets nobody act as a guest", async () => {
    expect(Object.values(await states(guestContext)).some(Boolean)).toBe(false);
  });
  it("tells a developer a dispute goes to the administrator for approval", async () => {
    vi.stubGlobal("fetch", stubFetch(routes).fn);
    const user = userEvent.setup();
    renderWith(developerContext, <CveDetailPage id="CVE-2026-1000" />);
    await screen.findByRole("heading", { level: 1 });
    await user.click(screen.getAllByRole("button", { name: /^actions for/i })[0]!);
    await user.click(screen.getByRole("menuitem", { name: /dispute/i }));
    expect(screen.getByText(/reviews disputes in the disputes section/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /raise dispute/i })).toBeDisabled(); // needs details first
  });
});

describe("Disputes page", () => {
  const pending = { id: 7, cve_id: "CVE-2026-1000", branch: "3.0", spec_path: "SPECS/x/x.spec", package_name: "rabbitmq-server", package_version: "3.13.7-1", reason: "UPSTREAM: not affected", status: "pending", requested_by: "dev@example.org", requested_at: "2026-11-04T08:00:00Z" };
  const list = (items: unknown[]) => ({ items, total: items.length, counts: { pending: 1, approved: 0, rejected: 0 } });

  it("lists pending requests with Approve and Reject for the administrator", async () => {
    const { fn, calls } = stubFetch({ "/disputes": list([pending]), "/disputes/7/approve": { dispute: { ...pending, status: "approved" } } });
    vi.stubGlobal("fetch", fn);
    const user = userEvent.setup();
    renderWith(adminContext, <DisputesPage />);
    expect(await screen.findByText("rabbitmq-server")).toBeInTheDocument();
    expect(screen.getByText("UPSTREAM: not affected")).toBeInTheDocument();
    expect(calls[0]!.url.searchParams.get("status")).toBe("pending");
    await user.click(screen.getByRole("button", { name: /approve dispute for rabbitmq-server/i }));
    expect(calls.some((c) => c.url.pathname.endsWith("/disputes/7/approve") && c.init?.method === "POST")).toBe(true);
  });
  it("rejects with an optional note", async () => {
    const { fn, calls } = stubFetch({ "/disputes": list([pending]), "/disputes/7/reject": {} });
    vi.stubGlobal("fetch", fn);
    const user = userEvent.setup();
    renderWith(adminContext, <DisputesPage />);
    await user.click(await screen.findByRole("button", { name: /reject dispute for rabbitmq-server/i }));
    await user.type(screen.getByLabelText(/note for the requester/i), "Needs evidence");
    await user.click(screen.getByRole("button", { name: "Reject dispute" }));
    const call = calls.find((c) => c.url.pathname.endsWith("/disputes/7/reject"))!;
    expect(JSON.parse(String(call.init?.body))).toEqual({ note: "Needs evidence" });
  });
  it("shows requests read-only to developers and guests, with no decision buttons", async () => {
    vi.stubGlobal("fetch", stubFetch({ "/disputes": list([pending]) }).fn);
    renderWith(developerContext, <DisputesPage />);
    expect(await screen.findByText("rabbitmq-server")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /approve dispute/i })).toBeNull();
    expect(screen.queryByRole("columnheader", { name: "Review" })).toBeNull();
  });
  it("switches tabs and shows an empty state", async () => {
    const { fn, calls } = stubFetch({ "/disputes": (url: URL) => (url.searchParams.get("status") === "approved" ? list([]) : list([pending])) });
    vi.stubGlobal("fetch", fn);
    const user = userEvent.setup();
    renderWith(adminContext, <DisputesPage />);
    await screen.findByText("rabbitmq-server");
    await user.click(screen.getByRole("tab", { name: /approved/i }));
    expect(await screen.findByText(/no disputes here/i)).toBeInTheDocument();
    expect(calls.at(-1)!.url.searchParams.get("status")).toBe("approved");
  });
});
