import type {
  BuildVariant,
  ProbeFailure,
  ProbeRequest,
  ProbeSuccess,
} from "../worker-contract";

interface Bindings {
  byteSum(bytes: Uint8Array): number;
  init(): Promise<unknown>;
  schemaVersion(): number;
}

export function installProbeWorker(variant: BuildVariant, bindings: Bindings): void {
  let initialization: Promise<unknown> | undefined;

  globalThis.addEventListener("message", (event: MessageEvent<ProbeRequest>) => {
    void (async () => {
      try {
        if (event.data.kind !== "run" || !(event.data.bytes instanceof Uint8Array)) {
          throw new Error("invalid probe request");
        }

        initialization ??= bindings.init();
        await initialization;
        const startedAt = performance.now();
        const response: ProbeSuccess = {
          byteSum: bindings.byteSum(event.data.bytes),
          durationMs: performance.now() - startedAt,
          kind: "ready",
          schemaVersion: bindings.schemaVersion(),
          variant,
          workerContext: globalThis.constructor.name,
        };
        globalThis.postMessage(response);
      } catch (error) {
        const response: ProbeFailure = {
          kind: "error",
          message: error instanceof Error ? error.message : "unknown worker error",
          variant,
        };
        globalThis.postMessage(response);
      }
    })();
  });
}
