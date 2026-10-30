export function Pagination({
  page,
  total,
  pageSize,
  busy,
  noun = "rows",
  onPage,
}: {
  page: number;
  total: number;
  pageSize: number;
  busy: boolean;
  noun?: string;
  onPage: (page: number) => void;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  return (
    <nav className="pagination" aria-label="Pagination">
      <span>
        Page {page} of {pages} · {total.toLocaleString()} {noun}
      </span>
      <div>
        <button className="btn secondary" onClick={() => onPage(page - 1)} disabled={page <= 1 || busy}>
          Previous
        </button>
        <button className="btn secondary" onClick={() => onPage(page + 1)} disabled={page >= pages || busy}>
          Next
        </button>
      </div>
    </nav>
  );
}
