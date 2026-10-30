import type { ReactNode } from "react";

export function StatusPill({ children, tone = "neutral" }: { children: ReactNode; tone?: string }) {
  return <span className={`status-pill ${tone}`}>{children}</span>;
}
