import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { consumeTokenHandoff } from "./lib/session";
import "./styles.css";

// Finish a Google sign-in before anything renders: store the token and clean the URL.
consumeTokenHandoff();

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
