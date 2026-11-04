import { createContext, useContext } from "react";
import type { RoleInfo } from "./api/types";

export type AppContextValue = {
  /** Admin session token ("" for guests). */
  token: string;
  roleInfo: RoleInfo;
  /** Signed in as the administrator: every action, including assign, patch verdict and dispute decisions. */
  canAdmin: boolean;
  /** Signed in as the administrator or a developer: GitHub PR, comments and disputes. */
  canContribute: boolean;
  /** Administrator and the server reports writes as enabled: scans are enabled. */
  canWrite: boolean;
  notify: (message: string) => void;
  signOut: () => void;
};

export const AppContext = createContext<AppContextValue>({
  token: "",
  roleInfo: { role: "viewer" },
  canAdmin: false,
  canContribute: false,
  canWrite: false,
  notify: () => undefined,
  signOut: () => undefined,
});

export const useApp = (): AppContextValue => useContext(AppContext);
