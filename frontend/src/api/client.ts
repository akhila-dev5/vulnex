const API = "/api";

export class ApiError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

/** What to show when the server sent no usable message (e.g. a gateway timeout page). */
export function fallbackMessage(status: number): string {
  if (status === 502 || status === 503 || status === 504) {
    return `The server took too long to respond or is unavailable (HTTP ${status}). Try again in a moment.`;
  }
  return `Request failed (HTTP ${status})`;
}

export const messageOf = (error: unknown): string =>
  error instanceof Error ? error.message : "Unexpected request error";

/** True when a request was cancelled on purpose (component unmounted, newer request started). */
export const isAbort = (error: unknown): boolean =>
  error instanceof DOMException && error.name === "AbortError";

/**
 * Call the Vulnex API. The admin session token, when there is one, travels in the
 * X-VULNEX-Key header; the backend decides what it is allowed to do with it.
 */
export async function request<T>(
  path: string,
  init: RequestInit = {},
  token = "",
): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Accept", "application/json");
  if (init.body) headers.set("Content-Type", "application/json");
  if (token) headers.set("X-VULNEX-Key", token);
  const response = await fetch(API + path, { ...init, headers, credentials: "same-origin" });
  if (!response.ok) {
    // HTTP/2 carries no status text, and proxies reply with HTML, so name the status.
    let detail = fallbackMessage(response.status);
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string" && body.detail) detail = body.detail;
    } catch {
      /* Non-JSON error body. */
    }
    throw new ApiError(detail, response.status);
  }
  return response.json() as Promise<T>;
}
