import { useEffect, useState } from "react";
import { LogIn, LogOut, ShieldCheck } from "lucide-react";
import { request } from "../api/client";
import type { DisputeList } from "../api/types";
import { useApp } from "../app-context";
import { hrefFor, type Route } from "../lib/route";
import { StatusPill } from "./StatusPill";

const LINKS = [
  { label: "CVEs", route: { name: "cves" } as Route },
  { label: "Packages", route: { name: "packages" } as Route },
  { label: "Disputes", route: { name: "disputes" } as Route },
  { label: "Workflows", route: { name: "workflows" } as Route },
];

export function TopNav({ route }: { route: Route }) {
  const { token, canAdmin, canContribute, roleInfo, signOut } = useApp();
  const [pending, setPending] = useState(0);

  // The administrator decides disputes, so show how many are waiting. Nobody else needs the number.
  useEffect(() => {
    if (!canAdmin) {
      setPending(0);
      return;
    }
    const controller = new AbortController();
    request<DisputeList>("/disputes?status=pending&limit=1", { signal: controller.signal }, token)
      .then((result) => setPending(result.counts?.pending ?? 0))
      .catch(() => undefined);
    return () => controller.abort();
  }, [canAdmin, token, route.name]);

  // A single CVE page belongs to the CVEs section.
  const section = route.name === "cve" ? "cves" : route.name;

  return (
    <header className="topnav">
      <a className="brand" href={hrefFor({ name: "cves" })}>
        <span className="brand-mark">
          <ShieldCheck size={20} />
        </span>
        <span className="brand-text">Vulnex</span>
        <span className="brand-sub">Azure Linux</span>
      </a>

      <nav className="topnav-links" aria-label="Main navigation">
        {LINKS.map((link) => (
          <a
            key={link.label}
            href={hrefFor(link.route)}
            aria-current={section === link.route.name ? "page" : undefined}
            className={section === link.route.name ? "active" : ""}
          >
            {link.label}
            {link.route.name === "disputes" && pending > 0 && (
              <span className="nav-badge" aria-label={`${pending} waiting for approval`}>{pending}</span>
            )}
          </a>
        ))}
      </nav>

      <div className="topnav-right">
        <StatusPill tone={canContribute ? "good" : "neutral"}>
          {canAdmin ? "Administrator" : canContribute ? "Developer" : "Guest · read-only"}
        </StatusPill>
        {canContribute ? (
          <button className="btn nav-btn" onClick={signOut}>
            <LogOut size={15} /> Sign out
          </button>
        ) : (
          roleInfo.role !== "automation" && (
            <a className="btn nav-btn primary" href="/api/auth/google">
              <LogIn size={15} /> Sign in with Google
            </a>
          )
        )}
      </div>
    </header>
  );
}
