import { useEffect, useId, useState, type FormEvent, type ReactNode } from "react";
import { Search, SlidersHorizontal, X } from "lucide-react";
import {
  BRANCH_OPTIONS,
  DEFAULT_FILTERS,
  PATCH_OPTIONS,
  RESOLUTION_OPTIONS,
  SEVERITY_OPTIONS,
  TRIAGE_OPTIONS,
  describeFilters,
  filtersKey,
  type Filters,
  type Option,
} from "../lib/filters";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
    </label>
  );
}

function Select({
  value,
  onChange,
  options,
  anyLabel,
}: {
  value: string;
  onChange: (value: string) => void;
  options: readonly Option[];
  anyLabel?: string;
}) {
  return (
    <select value={value} onChange={(event) => onChange(event.target.value)}>
      {anyLabel !== undefined && <option value="">{anyLabel}</option>}
      {options.map(([v, label]) => (
        <option key={v} value={v}>
          {label}
        </option>
      ))}
    </select>
  );
}

/**
 * The search filters, on the left of the page. Typing only edits a draft; the
 * results change when the form is submitted, so a half-typed filter never
 * triggers a request.
 */
export function FilterSidebar({
  mode,
  applied,
  onApply,
  recent = [],
  onRemoveRecent,
}: {
  mode: "cves" | "packages";
  applied: Filters;
  onApply: (filters: Filters) => void;
  recent?: Filters[];
  onRemoveRecent?: (filters: Filters) => void;
}) {
  const [draft, setDraft] = useState<Filters>(applied);
  const [open, setOpen] = useState(false);
  const panelId = useId();

  // A recent search (or Clear) changes the applied filters from outside the form.
  useEffect(() => setDraft(applied), [applied]);

  const set = (key: keyof Filters) => (value: string) => setDraft((d) => ({ ...d, [key]: value }));
  const text = (key: keyof Filters) => ({
    value: draft[key],
    onChange: (event: { target: { value: string } }) => set(key)(event.target.value),
    maxLength: 100,
  });

  const submit = (event: FormEvent) => {
    event.preventDefault();
    onApply(draft);
    setOpen(false);
  };
  const clear = () => {
    setDraft(DEFAULT_FILTERS);
    onApply(DEFAULT_FILTERS);
  };

  return (
    <aside className="filters" aria-label="Search filters">
      <button
        type="button"
        className="btn secondary filters-toggle"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((o) => !o)}
      >
        <SlidersHorizontal size={15} /> {open ? "Hide filters" : "Show filters"}
      </button>

      <div id={panelId} className={`filters-panel${open ? " open" : ""}`}>
        <form onSubmit={submit}>
          {mode === "cves" ? (
            <>
              <Field label="CVE or advisory id">
                <input type="search" placeholder="e.g. CVE-2026-1234" {...text("cve")} />
              </Field>
              <Field label="Package (exact name)">
                <input type="search" placeholder="e.g. rabbitmq-server" {...text("pkg")} />
              </Field>
              <div className="field-row">
                <Field label="Branch">
                  <Select value={draft.branch} onChange={set("branch")} options={BRANCH_OPTIONS} />
                </Field>
                <Field label="Patch">
                  <Select value={draft.patch} onChange={set("patch")} options={PATCH_OPTIONS} anyLabel="Any" />
                </Field>
              </div>
              <Field label="Severity">
                <Select value={draft.severity} onChange={set("severity")} options={SEVERITY_OPTIONS} anyLabel="Any severity" />
              </Field>
              <Field label="Triage status">
                <Select value={draft.triage} onChange={set("triage")} options={TRIAGE_OPTIONS} anyLabel="Any triage status" />
              </Field>
              <Field label="Resolution status">
                <Select value={draft.resolution} onChange={set("resolution")} options={RESOLUTION_OPTIONS} anyLabel="Any resolution" />
              </Field>
              <Field label="Fixed version">
                <input type="search" placeholder="e.g. 3.13.15" {...text("fixed")} />
              </Field>
              <Field label="Owner">
                <input type="search" placeholder="Owner email" {...text("owner")} />
              </Field>
            </>
          ) : (
            <>
              <Field label="Package name">
                <input type="search" placeholder="Search packages" {...text("pkg")} />
              </Field>
              <Field label="Branch">
                <Select value={draft.branch} onChange={set("branch")} options={BRANCH_OPTIONS} />
              </Field>
            </>
          )}

          <div className="filter-actions">
            <button type="submit" className="btn primary">
              <Search size={15} /> {mode === "cves" ? "Search CVEs" : "Search packages"}
            </button>
            <button type="button" className="btn secondary" onClick={clear}>
              Clear form
            </button>
          </div>
        </form>

        {mode === "cves" && (
          <section className="recent" aria-labelledby={`${panelId}-recent`}>
            <h2 id={`${panelId}-recent`}>Recent searches</h2>
            {recent.length === 0 ? (
              <p className="muted">Searches you run appear here.</p>
            ) : (
              <ul>
                {recent.map((search) => (
                  <li key={filtersKey(search)}>
                    <button type="button" className="recent-apply" onClick={() => onApply(search)}>
                      {describeFilters(search).map((line) => (
                        <span key={line}>{line}</span>
                      ))}
                    </button>
                    <button
                      type="button"
                      className="recent-remove"
                      aria-label={`Remove recent search: ${describeFilters(search).join(", ")}`}
                      onClick={() => onRemoveRecent?.(search)}
                    >
                      <X size={13} />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      </div>
    </aside>
  );
}
