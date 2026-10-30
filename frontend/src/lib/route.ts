// Tiny hash router. Three pages: the CVE list, the package list and one CVE.
// Hash routes keep the site a plain static bundle (no server rewrite rules needed)
// and make every CVE page a shareable, bookmarkable URL.

export type Route =
  | { name: "cves" }
  | { name: "packages" }
  | { name: "cve"; id: string }
  | { name: "notfound" };

// Vulnerability ids are normally CVE-YYYY-NNNN, but the scanner can also key a
// finding by an advisory id, so accept any plain identifier and let the API 404.
const ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/;

export function parseRoute(hash: string): Route {
  const path = hash.replace(/^#/, "").split("?")[0] ?? "";
  if (path === "" || path === "/" || path === "/cves") return { name: "cves" };
  if (path === "/packages") return { name: "packages" };
  const match = path.match(/^\/cve\/([^/]+)$/);
  if (match?.[1]) {
    let id = match[1];
    try {
      id = decodeURIComponent(id);
    } catch {
      return { name: "notfound" };
    }
    if (ID_RE.test(id)) return { name: "cve", id: id.toUpperCase() };
  }
  return { name: "notfound" };
}

export function hrefFor(route: Route): string {
  switch (route.name) {
    case "cves":
      return "#/";
    case "packages":
      return "#/packages";
    case "cve":
      return `#/cve/${encodeURIComponent(route.id)}`;
    default:
      return "#/";
  }
}
