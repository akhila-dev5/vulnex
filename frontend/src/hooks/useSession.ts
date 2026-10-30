import { useCallback, useEffect, useState } from "react";
import { isAbort, request } from "../api/client";
import type { RoleInfo } from "../api/types";
import { clearToken, loadToken, SESSION_KEY } from "../lib/session";

const VIEWER: RoleInfo = { role: "viewer" };

/**
 * Who is using the site. The server is the authority: the stored token only
 * asks to be treated as the admin, and the role comes back from GET /api/role.
 */
export function useSession() {
  const [token, setToken] = useState<string>(loadToken);
  const [roleInfo, setRoleInfo] = useState<RoleInfo>(VIEWER);

  // Sign in or out in another tab is picked up here.
  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (event.key === SESSION_KEY || event.key === null) setToken(loadToken());
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    request<RoleInfo>("/role", { signal: controller.signal }, token)
      .then((info) => {
        if (token && info.role === "viewer") {
          // The server no longer knows this token (expired, or the server restarted).
          clearToken();
          setToken("");
          return;
        }
        setRoleInfo(info);
      })
      .catch((error: unknown) => {
        // A network failure keeps the stored token; only the displayed role resets.
        if (!isAbort(error)) setRoleInfo(VIEWER);
      });
    return () => controller.abort();
  }, [token]);

  const signOut = useCallback(() => {
    const current = token;
    clearToken();
    setToken("");
    setRoleInfo(VIEWER);
    void request("/auth/logout", { method: "POST" }, current).catch(() => undefined);
  }, [token]);

  const canAdmin = roleInfo.role === "admin";
  const canWrite = Boolean(roleInfo.write_enabled && canAdmin);
  return { token, roleInfo, canAdmin, canWrite, signOut };
}
