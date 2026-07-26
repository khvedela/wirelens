import { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";

import "./styles.css";

import type { BuildVariant, ProbeResponse, ProbeSuccess } from "./worker-contract";

interface ProbeState {
  result?: ProbeSuccess;
  status: "starting" | "ready" | "error";
  statusText: string;
  transferState: "pending" | "detached" | "retained";
  variant: BuildVariant;
}

function requestedVariant(): BuildVariant {
  return new URLSearchParams(globalThis.location.search).get("variant") === "wasm-pack"
    ? "wasm-pack"
    : "direct";
}

function createProbeWorker(variant: BuildVariant): Worker {
  return variant === "direct"
    ? new Worker(new URL("./workers/direct.worker.ts", import.meta.url), {
        name: "wirelens-direct-wasm-probe",
        type: "module",
      })
    : new Worker(new URL("./workers/wasm-pack.worker.ts", import.meta.url), {
        name: "wirelens-wasm-pack-probe",
        type: "module",
      });
}

function ProbeApp() {
  const [state, setState] = useState<ProbeState>(() => ({
    status: "starting",
    statusText: "Starting worker…",
    transferState: "pending",
    variant: requestedVariant(),
  }));

  useEffect(() => {
    const worker = createProbeWorker(state.variant);
    const timeout = globalThis.setTimeout(() => {
      setState((current) => ({
        ...current,
        status: "error",
        statusText: "Worker timed out",
      }));
      worker.terminate();
    }, 10_000);

    worker.addEventListener("message", (event: MessageEvent<ProbeResponse>) => {
      globalThis.clearTimeout(timeout);
      const response = event.data;
      if (response.kind === "error") {
        setState((current) => ({
          ...current,
          status: "error",
          statusText: response.message,
        }));
      } else {
        setState((current) => ({
          ...current,
          result: response,
          status: "ready",
          statusText: "Ready",
        }));
      }
      worker.terminate();
    });

    worker.addEventListener("error", (event) => {
      globalThis.clearTimeout(timeout);
      setState((current) => ({
        ...current,
        status: "error",
        statusText: event.message || "Worker failed",
      }));
      worker.terminate();
    });

    const bytes = new Uint8Array([1, 2, 3, 4, 255]);
    worker.postMessage({ bytes, kind: "run" }, [bytes.buffer]);
    setState((current) => ({
      ...current,
      transferState: bytes.byteLength === 0 ? "detached" : "retained",
    }));

    return () => {
      globalThis.clearTimeout(timeout);
      worker.terminate();
    };
  }, [state.variant]);

  const result = state.result;
  return (
    <main
      id="app"
      data-duration-ms={result?.durationMs}
      data-state={state.status}
    >
      <p className="eyebrow">WireLens engineering probe</p>
      <h1>React + module worker + Wasm</h1>
      <dl>
        <div><dt>Status</dt><dd id="status">{state.statusText}</dd></div>
        <div><dt>Build path</dt><dd id="variant">{state.variant}</dd></div>
        <div><dt>Wasm result</dt><dd id="byte-sum">{result?.byteSum ?? "—"}</dd></div>
        <div><dt>Schema</dt><dd id="schema-version">{result?.schemaVersion ?? "—"}</dd></div>
        <div><dt>Execution context</dt><dd id="worker-context">{result?.workerContext ?? "—"}</dd></div>
        <div><dt>Main-thread transfer</dt><dd id="transfer-state">{state.transferState}</dd></div>
      </dl>
    </main>
  );
}

const root = document.querySelector("#root");
if (!(root instanceof HTMLElement)) {
  throw new Error("probe page is missing its React root");
}

createRoot(root).render(<ProbeApp />);
