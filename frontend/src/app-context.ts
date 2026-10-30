import { createContext, useContext } from "react";
import type { RoleInfo } from "./api/types";

export type AppContextValue = {
  /** Admin session token ("" for guests). */
  token: string;
  roleInfo: RoleInfo;
  /** Signed in as the administrator: triage actions are enabled. */
  canAdmin: boolean;
  /** Administrator and the server reports writes as enabled: scans are enabled. */
  canWrite: boolean;
  notify: (message: string) => void;
  signOut: () => void;
};

export const AppContext = createContext<AppContextValue>({
  token: "",
  roleInfo: { role: "viewer" },
  canAdmin: false,
  canWrite: false,
  notify: () => undefined,
  signOut: () => undefined,
});

export const useApp = (): AppContextValue => useContext(AppContext);
