import { useCallback, useEffect, useState } from "react";
import { messageOf, request } from "../api/client";

export type ScanState = "idle" | "starting" | "running";

type ScanStatus = { manager?: { running?: boolean; error?: string } };

/** Start a background scan of one branch and reload the data when it finishes. */
export function useScan(options: {
  token: string;
  canWrite: boolean;
  branch: string;
  notify: (message: string) => void;
  onFinished: () => void;
}) {
  const { token, canWrite, branch, notify, onFinished } = options;
  const [state, setState] = useState<ScanState>("idle");

  const run = useCallback(async () => {
    if (!canWrite) return;
    setState("starting");
    try {
      await request("/scan", { method: "POST", body: JSON.stringify({ branches: [branch] }) }, token);
      setState("running");
      notify(`Azure Linux ${branch} scan started from azurelinux-test`);
    } catch (error) {
      setState("idle");
      notify(messageOf(error));
    }
  }, [canWrite, branch, token, notify]);

  useEffect(() => {
    if (state !== "running") return;
    const timer = window.setInterval(async () => {
      try {
        const status = await request<ScanStatus>("/scan/status", {}, token);
        if (status.manager?.running) return;
        setState("idle");
        notify(status.manager?.error ? "Scan failed: " + status.manager.error : "Scan completed; findings refreshed");
        onFinished();
      } catch (error) {
        notify("Could not check scan status: " + messageOf(error));
      }
    }, 5000);
    return () => window.clearInterval(timer);
  }, [state, token, notify, onFinished]);

  return { state, run };
}
