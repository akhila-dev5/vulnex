import { LogIn, LogOut, ShieldCheck } from "lucide-react";
import { useApp } from "../app-context";
import { hrefFor, type Route } from "../lib/route";
import { StatusPill } from "./StatusPill";

const LINKS = [
  { label: "CVEs", route: { name: "cves" } as Route },
  { label: "Packages", route: { name: "packages" } as Route },
];

export function TopNav({ route }: { route: Route }) {
  const { canWrite, roleInfo, signOut } = useApp();
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
          </a>
        ))}
      </nav>

      <div className="topnav-right">
        <StatusPill tone={canWrite ? "good" : "neutral"}>{canWrite ? "Administrator" : "Guest · read-only"}</StatusPill>
        {canWrite ? (
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
