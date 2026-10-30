import { useEffect, useState } from "react";
import { AlertCircle, FileSearch, RefreshCw } from "lucide-react";
import { isAbort, messageOf, request } from "../api/client";
import type { PackageRow, PageResult } from "../api/types";
import { useApp } from "../app-context";
import { FilterSidebar } from "../components/FilterSidebar";
import { Pagination } from "../components/Pagination";
import { DEFAULT_FILTERS, PAGE_SIZE, toPackageParams, type Filters } from "../lib/filters";

export function PackagesPage() {
  const { token } = useApp();
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [page, setPage] = useState(1);
  const [rows, setRows] = useState<PackageRow[]>([]);
  const [total, setTotal] = useState(0);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    const { signal } = controller;
    setBusy(true);
    setError("");
    request<PageResult<PackageRow>>("/packages?" + toPackageParams(filters, page), { signal }, token)
      .then((result) => {
        setRows(result.items);
        setTotal(result.total);
      })
      .catch((e: unknown) => {
        if (!isAbort(e)) setError(messageOf(e));
      })
      .finally(() => {
        if (!signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [filters, page, token]);

  const apply = (next: Filters) => {
    setFilters(next);
    setPage(1);
  };

  return (
    <div className="workspace">
      <FilterSidebar mode="packages" applied={filters} onApply={apply} />
      <main className="content">
        <div className="page-head">
          <div>
            <h1>Packages</h1>
            <p>Every package spec scanned from azurelinux-test on branch {filters.branch}.</p>
          </div>
        </div>

        {error && (
          <div className="alert error" role="alert">
            <AlertCircle size={17} />
            {error}
          </div>
        )}

        <section className="table-card" aria-busy={busy}>
          <div className="table-head">
            <div>
              <h2>Package inventory</h2>
              <p>
                {total.toLocaleString()} package{total === 1 ? "" : "s"} · branch {filters.branch}
              </p>
            </div>
          </div>
          {busy && rows.length === 0 ? (
            <div className="empty-state">
              <RefreshCw className="spin" /> Loading packages…
            </div>
          ) : rows.length === 0 ? (
            <div className="empty-state">
              <FileSearch size={26} />
              <strong>No packages found</strong>
              <span>Try a different name or branch.</span>
            </div>
          ) : (
            <div className={`table-scroll${busy ? " dim" : ""}`}>
              <table className="packages-table">
                <thead>
                  <tr>
                    <th scope="col">Package</th>
                    <th scope="col">Version</th>
                    <th scope="col">Branch</th>
                    <th scope="col">Spec path</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((pkg, index) => (
                    <tr key={pkg.spec_path || pkg.name + index}>
                      <td><strong>{pkg.name}</strong></td>
                      <td>{pkg.version || "—"}</td>
                      <td><code>{pkg.branch || filters.branch}</code></td>
                      <td className="spec-path">{pkg.spec_path || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <Pagination page={page} total={total} pageSize={PAGE_SIZE} busy={busy} noun="packages" onPage={setPage} />
        </section>
      </main>
    </div>
  );
}
