// The admin session token is kept in localStorage so that a CVE opened in a new
// browser tab is still signed in, and so that signing out in one tab signs out all.
//
// The token is opaque and short-lived (the server expires it, and a server restart
// invalidates every token). Storage can be unavailable (private mode, blocked
// cookies), so every access is guarded and the app simply works as a guest.

export const SESSION_KEY = "vulnex.session";

export function loadToken(): string {
  try {
    return window.localStorage.getItem(SESSION_KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveToken(token: string): void {
  try {
    window.localStorage.setItem(SESSION_KEY, token);
  } catch {
    /* Storage unavailable: the session lasts only until the page closes. */
  }
}

export function clearToken(): void {
  try {
    window.localStorage.removeItem(SESSION_KEY);
  } catch {
    /* Nothing to clear. */
  }
}

const HANDOFF_RE = /vulnex_token=([A-Za-z0-9_-]+)/;

/**
 * Google sign-in finishes by redirecting to `/#vulnex_token=…`. Store that token and
 * remove it from the address bar straight away so it never ends up in history,
 * bookmarks or a copied link. Returns true when a token was picked up.
 */
export function consumeTokenHandoff(): boolean {
  const match = window.location.hash.match(HANDOFF_RE);
  if (!match?.[1]) return false;
  saveToken(match[1]);
  window.history.replaceState(null, "", window.location.pathname + window.location.search + "#/");
  return true;
}
