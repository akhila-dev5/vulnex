import { useCallback, useMemo, useState } from "react";
import { AppContext, type AppContextValue } from "./app-context";
import { TopNav } from "./components/TopNav";
import { Toast } from "./components/Toast";
import { useHashRoute } from "./hooks/useHashRoute";
import { useSession } from "./hooks/useSession";
import { CveDetailPage } from "./pages/CveDetailPage";
import { CvesPage } from "./pages/CvesPage";
import { PackagesPage } from "./pages/PackagesPage";
import { hrefFor } from "./lib/route";

function NotFound() {
  return (
    <main className="cve-page">
      <div className="empty-state">
        <strong>Page not found</strong>
        <a href={hrefFor({ name: "cves" })}>Go to the CVE list</a>
      </div>
    </main>
  );
}

function App() {
  const route = useHashRoute();
  const session = useSession();
  const [toast, setToast] = useState("");
  const notify = useCallback((message: string) => setToast(message), []);

  const value = useMemo<AppContextValue>(
    () => ({
      token: session.token,
      roleInfo: session.roleInfo,
      canAdmin: session.canAdmin,
      canWrite: session.canWrite,
      signOut: session.signOut,
      notify,
    }),
    [session.token, session.roleInfo, session.canAdmin, session.canWrite, session.signOut, notify],
  );

  return (
    <AppContext.Provider value={value}>
      <div className="site">
        <TopNav route={route} />
        {route.name === "cve" ? (
          <CveDetailPage key={route.id} id={route.id} />
        ) : route.name === "packages" ? (
          <PackagesPage />
        ) : route.name === "cves" ? (
          <CvesPage />
        ) : (
          <NotFound />
        )}
        <Toast message={toast} onDismiss={() => setToast("")} />
      </div>
    </AppContext.Provider>
  );
}

export default App;
