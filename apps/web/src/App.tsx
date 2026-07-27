import { useEffect, useState } from "react";

import { CaptureImporter } from "./features/capture-import/CaptureImporter";
import type {
  CaptureImportModel,
  CaptureSelectionRejection,
} from "./features/capture-import/import-state";
import { PacketDetailWorkspace, type PacketDetailWorkspaceProps } from "./features/packet-detail";

type VisualTheme = "dark" | "light";

const BOOTING_MODEL: CaptureImportModel = { phase: "booting" };
const THEME_STORAGE_KEY = "wirelens:theme";
const NOOP = (): void => undefined;
const NOOP_FILE = (_file: File): void => undefined;
const NOOP_REJECTION = (_rejection: CaptureSelectionRejection): void => undefined;
const DEFAULT_THEME: VisualTheme = "light";

function normalizeTheme(value: string | null): VisualTheme | undefined {
  return value === "dark" || value === "light" ? value : undefined;
}

function detectDefaultTheme(): VisualTheme {
  if (typeof window === "undefined") return DEFAULT_THEME;
  if (typeof window.matchMedia !== "function") return DEFAULT_THEME;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export interface AppProps {
  readonly importModel?: CaptureImportModel;
  readonly onCancelImport?: () => void;
  readonly onFileSelected?: (file: File) => void;
  readonly onResetImport?: () => void;
  readonly onSelectionRejected?: (rejection: CaptureSelectionRejection) => void;
  readonly packetInspection?: Omit<PacketDetailWorkspaceProps, "datasetGeneration" | "packetCount">;
}

export function App({
  importModel = BOOTING_MODEL,
  onCancelImport = NOOP,
  onFileSelected = NOOP_FILE,
  onResetImport = NOOP,
  onSelectionRejected = NOOP_REJECTION,
  packetInspection,
}: AppProps) {
  const completedSummary = importModel.phase === "complete" ? importModel.summary : undefined;
  const inspectionReady =
    completedSummary !== undefined &&
    completedSummary.datasetGeneration !== undefined &&
    packetInspection !== undefined;
  const [theme, setTheme] = useState<VisualTheme>(() => {
    if (typeof window === "undefined") return DEFAULT_THEME;
    return normalizeTheme(window.localStorage.getItem(THEME_STORAGE_KEY)) ?? detectDefaultTheme();
  });

  useEffect(() => {
    if (theme === "dark") {
      document.documentElement.setAttribute("data-theme", "dark");
      document.documentElement.style.colorScheme = "dark";
    } else {
      document.documentElement.setAttribute("data-theme", "light");
      document.documentElement.style.colorScheme = "light";
    }
    window.localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  const toggleTheme = (): void => {
    setTheme((previousTheme) => (previousTheme === "dark" ? "light" : "dark"));
  };

  return (
    <div className="app-shell" data-theme={theme}>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>
      <header className="site-header">
        <div className="site-header__inner">
          <div className="wordmark">
            <span className="wordmark-mark" aria-hidden="true">
              <span />
            </span>
            <span>WireLens</span>
          </div>
          <span className="local-badge">
            <span aria-hidden="true" />
            Local analysis
          </span>
          <button
            className="theme-toggle button button--secondary"
            type="button"
            onClick={toggleTheme}
            aria-label="Toggle light and dark theme"
            aria-pressed={theme === "dark"}
          >
            {theme === "dark" ? "Use light theme" : "Use dark theme"}
          </button>
        </div>
        <nav aria-label="Primary" className="app-nav">
          <a href="#capture-import">Capture import</a>
          {inspectionReady ? <a href="#packet-detail-workspace">Packet detail</a> : null}
        </nav>
      </header>

      <main
        id="main-content"
        className={`import-page${inspectionReady ? " import-page--inspection" : ""}`}
      >
        <section className="import-introduction" aria-labelledby="page-title">
          <p className="page-kicker">Private packet analysis</p>
          <h1 id="page-title">
            {inspectionReady ? "Inspect packet evidence" : "Open a packet capture"}
          </h1>
          <p className="page-lede">
            {inspectionReady
              ? "Move between decoded fields and their exact captured bytes. Every query stays in this browser."
              : "Choose a PCAP or PCAPNG file to inspect locally, without sending capture data to a server."}
          </p>
          <aside className="privacy-notice" data-testid="privacy-notice" aria-label="Privacy">
            <span className="privacy-notice__icon" aria-hidden="true">
              <svg viewBox="0 0 24 24" focusable="false" aria-hidden="true">
                <path d="M12 3 5.5 5.5v5.8c0 4.2 2.7 7.9 6.5 9.7 3.8-1.8 6.5-5.5 6.5-9.7V5.5L12 3Z" />
                <path d="m9.2 12 1.8 1.8 3.9-4" />
              </svg>
            </span>
            <div>
              <strong>Your capture stays on this device</strong>
              <p>WireLens analyzes it in this browser and does not upload or save the file.</p>
            </div>
          </aside>
        </section>

        <section id="capture-import">
          <CaptureImporter
            model={importModel}
            onCancel={onCancelImport}
            onFileSelected={onFileSelected}
            onReset={onResetImport}
            onSelectionRejected={onSelectionRejected}
          />
        </section>
        {inspectionReady ? (
          <PacketDetailWorkspace
            {...packetInspection}
            datasetGeneration={completedSummary.datasetGeneration}
            packetCount={completedSummary.packetsRetained}
          />
        ) : null}
      </main>
    </div>
  );
}

export default App;
