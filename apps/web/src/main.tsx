import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { CaptureImportController } from "./features/capture-import/CaptureImportController";
import "./styles.css";

const root = document.querySelector("#root");
if (!(root instanceof HTMLElement)) throw new Error("WireLens root element is missing");

createRoot(root).render(
  <StrictMode>
    <CaptureImportController />
  </StrictMode>,
);
