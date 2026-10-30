import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

/** Accessible dialog: Escape and backdrop click close it, focus moves in and returns on close. */
export function Modal({
  eyebrow,
  title,
  wide = false,
  onClose,
  children,
}: {
  eyebrow?: string;
  title: string;
  wide?: boolean;
  onClose: () => void;
  children: ReactNode;
}) {
  const dialogRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    dialogRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      previouslyFocused?.focus?.();
    };
  }, [onClose]);

  return (
    <div
      className="modal-backdrop"
      role="presentation"
      onClick={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <section
        ref={dialogRef}
        tabIndex={-1}
        className={`modal-card${wide ? " wide-modal" : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby="modal-title"
      >
        <button className="modal-close icon-btn" aria-label="Close" onClick={onClose}>
          <X size={16} />
        </button>
        {eyebrow && <small>{eyebrow}</small>}
        <h2 id="modal-title">{title}</h2>
        {children}
      </section>
    </div>
  );
}
