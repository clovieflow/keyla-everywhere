import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import App from "../../App";
import "../../styles/base.css";
import "../../styles/console.css";
import "../../styles/editorial.css";

/** Mounts the authenticated console app into the shared dashboard document. */
export function mountConsole(root: HTMLElement): void {
  document.title = "Keyla Everywhere Console";
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
