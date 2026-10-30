import { useEffect, useId, useRef, useState } from "react";
import { AlertTriangle, ChevronDown, GitPullRequest, MessageSquarePlus, ShieldCheck, UserPlus, type LucideIcon } from "lucide-react";
import { useApp } from "../app-context";
import type { TriageAction } from "../lib/triage";

const ITEMS: Array<{ action: TriageAction; label: string; Icon: LucideIcon }> = [
  { action: "pr", label: "Set GitHub PR", Icon: GitPullRequest },
  { action: "dispute", label: "Dispute", Icon: AlertTriangle },
  { action: "comment", label: "Add comment", Icon: MessageSquarePlus },
  { action: "patch", label: "Patch verdict", Icon: ShieldCheck },
  { action: "assign", label: "Assign reviewer", Icon: UserPlus },
];

/** Per-package triage actions. Everyone can open the menu; only the administrator can use the items. */
export function ActionsMenu({ label, onAction }: { label: string; onAction: (action: TriageAction) => void }) {
  const { canAdmin } = useApp();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const menuId = useId();

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      if (wrapRef.current && !wrapRef.current.contains(event.target as Node)) setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="actions-menu" ref={wrapRef}>
      <button
        ref={buttonRef}
        className="btn action-btn"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-label={`Actions for ${label}`}
        onClick={() => setOpen((o) => !o)}
      >
        Actions <ChevronDown size={13} aria-hidden="true" />
      </button>
      {open && (
        <div className="action-popover" id={menuId} role="menu">
          {ITEMS.map(({ action, label: itemLabel, Icon }) => (
            <button
              key={action}
              role="menuitem"
              disabled={!canAdmin}
              onClick={() => {
                setOpen(false);
                onAction(action);
              }}
            >
              <Icon size={14} aria-hidden="true" /> {itemLabel}
            </button>
          ))}
          {!canAdmin && <p className="menu-note">Sign in as the administrator to use these actions.</p>}
        </div>
      )}
    </div>
  );
}
