import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import "./styles.css";

import { createApiClient } from "./api/client";
import { App } from "./App";

const root = document.getElementById("root");
if (!root) {
  throw new Error("missing #root element");
}

createRoot(root).render(
  <StrictMode>
    <App client={createApiClient()} />
  </StrictMode>,
);
