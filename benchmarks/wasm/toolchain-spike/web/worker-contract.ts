export type BuildVariant = "direct" | "wasm-pack";

export interface ProbeRequest {
  bytes: Uint8Array;
  kind: "run";
}

export interface ProbeSuccess {
  byteSum: number;
  durationMs: number;
  kind: "ready";
  schemaVersion: number;
  variant: BuildVariant;
  workerContext: string;
}

export interface ProbeFailure {
  kind: "error";
  message: string;
  variant: BuildVariant;
}

export type ProbeResponse = ProbeFailure | ProbeSuccess;
