import type { ReactNode } from "react";
import { hrefFor } from "../lib/route";

/**
 * A link to the CVE page. It opens in a new browser tab so the list, its filters
 * and the reader's place in it stay where they were. The admin session is shared
 * between tabs (see lib/session.ts), so the new tab is signed in too.
 */
export function CveLink({ id, children, className = "cve-link" }: { id: string; children?: ReactNode; className?: string }) {
  return (
    <a className={className} href={hrefFor({ name: "cve", id })} target="_blank" rel="noopener noreferrer">
      {children ?? id}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  );
}
