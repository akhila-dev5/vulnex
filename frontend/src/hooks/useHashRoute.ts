import { useEffect, useState } from "react";
import { parseRoute, type Route } from "../lib/route";

/** The current page, kept in sync with the address-bar hash (including back/forward). */
export function useHashRoute(): Route {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  useEffect(() => {
    const sync = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", sync);
    return () => window.removeEventListener("hashchange", sync);
  }, []);
  return route;
}
