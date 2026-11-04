import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
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

const GAP = 6; // space between the button and the menu
const EDGE = 8; // keep the menu this far from the window edge

/**
 * Per-package triage actions. Everyone can open the menu; only the administrator can use the items.
 *
 * The menu is drawn in a portal on <body> with fixed positioning. Rendered inside the table it
 * would be clipped: the table sits in a scroll box (`overflow-x: auto`, which also makes the
 * vertical axis clip) inside a card with `overflow: hidden`.
 */
export function ActionsMenu({ label, onAction }: { label: string; onAction: (action: TriageAction) => void }) {
  const { canAdmin } = useApp();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const popRef = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; right: number } | null>(null);
  const menuId = useId();

  // Place the menu under the button, or above it when there is no room below.
  useLayoutEffect(() => {
    if (!open || !buttonRef.current || !popRef.current) {
      setPos(null);
      return;
    }
    const button = buttonRef.current.getBoundingClientRect();
    const height = popRef.current.offsetHeight;
    let top = button.bottom + GAP;
    if (top + height > window.innerHeight - EDGE && button.top - GAP - height >= EDGE) {
      top = button.top - GAP - height;
    }
    setPos({ top: Math.max(EDGE, top), right: Math.max(EDGE, window.innerWidth - button.right) });
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: MouseEvent) => {
      const target = event.target as Node;
      if (wrapRef.current?.contains(target) || popRef.current?.contains(target)) return;
      setOpen(false);
    };
    // The menu is fixed to the window, so it would drift away from its button: close it instead.
    const close = (event?: Event) => {
      if (event?.target instanceof Node && popRef.current?.contains(event.target)) return; // the menu's own scrolling
      setOpen(false);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    document.addEventListener("mousedown", onPointer);
    document.addEventListener("keydown", onKey);
    window.addEventListener("scroll", close, true);
    const onResize = () => close();
    window.addEventListener("resize", onResize);
    return () => {
      document.removeEventListener("mousedown", onPointer);
      document.removeEventListener("keydown", onKey);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("resize", onResize);
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
      {open &&
        createPortal(
          <div
            className="action-popover"
            id={menuId}
            role="menu"
            ref={popRef}
            style={pos ? { top: pos.top, right: pos.right } : { top: 0, right: 0, visibility: "hidden" }}
          >
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
          </div>,
          document.body,
        )}
    </div>
  );
}
