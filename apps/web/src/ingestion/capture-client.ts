import type { BoundaryErrorCode, ResourceStats } from "../boundary/worker-contract";
import {
  CAPTURE_INGESTION_PROTOCOL_VERSION,
  type CaptureWorkerCommand,
  type CaptureWorkerEvent,
  type ImportError,
  type ImportSummary,
  type IngestionCapabilities,
  type ParseProgress,
  type ReadProgress,
  type TerminalProgress,
} from "./capture-contract";

export class CaptureImportClientError extends Error {
  constructor(
    readonly detail: ImportError,
    readonly terminalProgress: TerminalProgress = {},
  ) {
    super(detail.code);
    this.name = "CaptureImportClientError";
  }
}

export class CaptureImportCancelledError extends Error {
  constructor(readonly terminalProgress: TerminalProgress = {}) {
    super("capture import cancelled");
    this.name = "CaptureImportCancelledError";
  }
}

export type ImportProgressEvent = Extract<CaptureWorkerEvent, { type: "progress" }>;
export type CaptureWorkerFactory = () => Worker;

interface PendingImport {
  onProgress(event: ImportProgressEvent): void;
  reject(error: Error): void;
  resolve(summary: ImportSummary): void;
}

interface PendingCommand<T> {
  reject(error: CaptureImportClientError): void;
  resolve(value: T): void;
  type: "dispose_dataset" | "initialize" | "resource_stats" | "shutdown";
}

const ERROR_CODES = new Set<ImportError["code"]>([
  "empty_capture",
  "internal_failure",
  "invalid_selection",
  "malformed_capture",
  "read_failed",
  "resource_limit",
  "truncated_capture",
  "unsupported_format",
  "unsupported_version",
  "worker_failed",
]);
const BOUNDARY_ERROR_CODES = new Set<BoundaryErrorCode>([
  "cancelled",
  "internal_invariant",
  "invalid_argument",
  "invalid_handle",
  "invalid_state",
  "malformed_capture",
  "resource_limit",
  "stale_handle",
  "truncated_capture",
  "unsupported_format",
  "unsupported_version",
  "wrong_handle_kind",
]);
const RESOURCE_STAT_KEYS = [
  "currentOwnedCaptureBytesHi",
  "currentOwnedCaptureBytesLo",
  "cursors",
  "datasets",
  "imports",
  "peakOwnedCaptureBytesHi",
  "peakOwnedCaptureBytesLo",
  "peakTransientImportInputBytesHi",
  "peakTransientImportInputBytesLo",
  "retainedBatchBytesHi",
  "retainedBatchBytesLo",
  "retainedCaptureBytesHi",
  "retainedCaptureBytesLo",
  "retainedIndexBytesHi",
  "retainedIndexBytesLo",
  "retainedLogicalBytesHi",
  "retainedLogicalBytesLo",
  "retainedPacketIndexBytesHi",
  "retainedPacketIndexBytesLo",
  "totalLogicalBytesUpperBoundHi",
  "totalLogicalBytesUpperBoundLo",
  "transientAuxiliaryBytesUpperBoundHi",
  "transientAuxiliaryBytesUpperBoundLo",
  "transientImportInputBytesHi",
  "transientImportInputBytesLo",
  "transientPacketIndexBytesUpperBoundHi",
  "transientPacketIndexBytesUpperBoundLo",
  "transientParserBufferBytesUpperBoundHi",
  "transientParserBufferBytesUpperBoundLo",
] as const;

function internalFailure(): CaptureImportClientError {
  return new CaptureImportClientError({ code: "worker_failed" });
}

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : undefined;
}

function importError(value: unknown): ImportError | undefined {
  const candidate = record(value);
  if (
    candidate === undefined ||
    typeof candidate.code !== "string" ||
    !ERROR_CODES.has(candidate.code as ImportError["code"])
  ) {
    return undefined;
  }
  const detail: ImportError = { code: candidate.code as ImportError["code"] };
  if (typeof candidate.inputOffset === "string") detail.inputOffset = candidate.inputOffset;
  if (
    typeof candidate.limitBytes === "number" &&
    Number.isSafeInteger(candidate.limitBytes) &&
    candidate.limitBytes > 0
  ) {
    detail.limitBytes = candidate.limitBytes;
  }
  return detail;
}

function positiveId(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function safeCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function word(value: unknown): value is number {
  return safeCount(value) && value <= 0xffff_ffff;
}

function readProgress(value: unknown): value is ReadProgress {
  const candidate = record(value);
  return (
    candidate !== undefined &&
    safeCount(candidate.bytesRead) &&
    safeCount(candidate.totalBytes) &&
    candidate.bytesRead <= candidate.totalBytes
  );
}

function parseProgress(value: unknown, terminal: boolean): value is ParseProgress {
  const candidate = record(value);
  const phase = candidate?.phase;
  const phaseIsValid =
    phase === "complete" ||
    phase === "parsing" ||
    phase === "validating" ||
    (terminal && (phase === "cancelled" || phase === "failed"));
  return (
    candidate !== undefined &&
    phaseIsValid &&
    safeCount(candidate.bytesConsumed) &&
    word(candidate.diagnostics) &&
    safeCount(candidate.packetsRetained) &&
    safeCount(candidate.records) &&
    safeCount(candidate.totalBytes) &&
    candidate.bytesConsumed <= candidate.totalBytes &&
    candidate.packetsRetained <= candidate.records
  );
}

function terminalProgress(value: Record<string, unknown>): boolean {
  return (
    (value.lastReadProgress === undefined || readProgress(value.lastReadProgress)) &&
    (value.lastParseProgress === undefined || parseProgress(value.lastParseProgress, true))
  );
}

function summary(value: unknown): value is ImportSummary {
  const candidate = record(value);
  return (
    candidate !== undefined &&
    safeCount(candidate.byteLength) &&
    (candidate.byteOrder === "big-endian" || candidate.byteOrder === "little-endian") &&
    typeof candidate.filename === "string" &&
    typeof candidate.filenameHintMismatch === "boolean" &&
    (candidate.format === "pcap" || candidate.format === "pcapng") &&
    safeCount(candidate.packetsRetained) &&
    safeCount(candidate.records) &&
    candidate.packetsRetained <= candidate.records &&
    safeCount(candidate.warningCount)
  );
}

function ingestionCapabilities(value: unknown): value is IngestionCapabilities {
  const candidate = record(value);
  const wasm = record(candidate?.wasm);
  return (
    candidate !== undefined &&
    safeCount(candidate.maxCaptureBytes) &&
    candidate.maxCaptureBytes > 0 &&
    safeCount(candidate.readChunkBytes) &&
    candidate.readChunkBytes > 0 &&
    wasm !== undefined &&
    safeCount(wasm.apiVersion) &&
    wasm.apiVersion > 0 &&
    safeCount(wasm.maxImportStepBytes) &&
    wasm.maxImportStepBytes > 0 &&
    safeCount(wasm.maxImportStepRecords) &&
    wasm.maxImportStepRecords > 0 &&
    safeCount(wasm.maxPackets) &&
    wasm.maxPackets > 0
  );
}

function resourceStats(value: unknown): value is ResourceStats {
  const candidate = record(value);
  return candidate !== undefined && RESOURCE_STAT_KEYS.every((key) => word(candidate[key]));
}

export function validateCaptureWorkerEvent(value: unknown): CaptureWorkerEvent | undefined {
  const candidate = record(value);
  if (
    candidate === undefined ||
    candidate.protocolVersion !== CAPTURE_INGESTION_PROTOCOL_VERSION ||
    typeof candidate.type !== "string"
  ) {
    return undefined;
  }
  switch (candidate.type) {
    case "initialized":
      return positiveId(candidate.requestId) && ingestionCapabilities(candidate.capabilities)
        ? (value as CaptureWorkerEvent)
        : undefined;
    case "progress":
      if (!positiveId(candidate.jobId)) return undefined;
      if (candidate.phase === "validating" || candidate.phase === "cancelling") {
        return value as CaptureWorkerEvent;
      }
      if (candidate.phase === "reading" && readProgress(candidate.progress)) {
        return value as CaptureWorkerEvent;
      }
      if (candidate.phase === "parsing" && parseProgress(candidate.progress, false)) {
        return value as CaptureWorkerEvent;
      }
      return undefined;
    case "complete":
      return positiveId(candidate.jobId) && summary(candidate.summary)
        ? (value as CaptureWorkerEvent)
        : undefined;
    case "cancelled":
      return positiveId(candidate.jobId) && terminalProgress(candidate)
        ? (value as CaptureWorkerEvent)
        : undefined;
    case "import_error": {
      const boundaryCode = candidate.boundaryCode;
      return positiveId(candidate.jobId) &&
        importError(candidate.error) !== undefined &&
        terminalProgress(candidate) &&
        (boundaryCode === undefined ||
          (typeof boundaryCode === "string" &&
            BOUNDARY_ERROR_CODES.has(boundaryCode as BoundaryErrorCode)))
        ? (value as CaptureWorkerEvent)
        : undefined;
    }
    case "dataset_disposed":
    case "shutdown_complete":
      return positiveId(candidate.requestId) ? (value as CaptureWorkerEvent) : undefined;
    case "resource_stats":
      return positiveId(candidate.requestId) && resourceStats(candidate.stats)
        ? (value as CaptureWorkerEvent)
        : undefined;
    case "command_error":
      return positiveId(candidate.requestId) && importError(candidate.error) !== undefined
        ? (value as CaptureWorkerEvent)
        : undefined;
    default:
      return undefined;
  }
}

export class CaptureImportClient {
  readonly #worker: Worker;
  readonly #commands = new Map<number, PendingCommand<unknown>>();
  readonly #imports = new Map<number, PendingImport>();
  #activeJobId: number | undefined;
  #closed = false;
  #nextId = 1;
  #startingImport = false;
  readonly #initialization: Promise<IngestionCapabilities>;

  constructor(
    workerFactory: CaptureWorkerFactory = () =>
      new Worker(new URL("../workers/capture.worker.ts", import.meta.url), {
        name: "wirelens-capture-ingestion",
        type: "module",
      }),
  ) {
    this.#worker = workerFactory();
    this.#worker.addEventListener("message", (event: MessageEvent<unknown>) => {
      this.#receive(event.data);
    });
    this.#worker.addEventListener("error", () => {
      this.#abort(internalFailure());
    });
    this.#worker.addEventListener("messageerror", () => {
      this.#abort(internalFailure());
    });
    this.#initialization = this.#request<IngestionCapabilities>("initialize");
  }

  ready(): Promise<IngestionCapabilities> {
    return this.#initialization;
  }

  async importCapture(
    file: File,
    onProgress: (event: ImportProgressEvent) => void,
  ): Promise<ImportSummary> {
    if (this.#closed || this.#activeJobId !== undefined || this.#startingImport) {
      throw new CaptureImportClientError({ code: "invalid_selection" });
    }
    this.#startingImport = true;
    try {
      await this.#initialization;
      if (this.#closed || this.#activeJobId !== undefined) {
        throw new CaptureImportClientError({ code: "invalid_selection" });
      }
      const jobId = this.#takeId();
      this.#activeJobId = jobId;
      const result = new Promise<ImportSummary>((resolve, reject) => {
        this.#imports.set(jobId, { onProgress, reject, resolve });
      });
      this.#post({
        file,
        jobId,
        protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
        type: "start_import",
      });
      return await result;
    } finally {
      this.#startingImport = false;
    }
  }

  cancelImport(): void {
    if (this.#activeJobId === undefined || this.#closed) return;
    this.#post({
      jobId: this.#activeJobId,
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      type: "cancel_import",
    });
  }

  async disposeDataset(): Promise<void> {
    await this.#initialization;
    await this.#request("dispose_dataset");
  }

  async resourceStats(): Promise<ResourceStats> {
    await this.#initialization;
    return this.#request<ResourceStats>("resource_stats");
  }

  async shutdown(): Promise<void> {
    if (this.#closed) return;
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const graceful = this.#initialization.then(() => this.#request("shutdown"));
      const deadline = new Promise<never>((_resolve, reject) => {
        timeout = setTimeout(() => reject(internalFailure()), 1_000);
      });
      await Promise.race([graceful, deadline]);
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
      this.terminate();
    }
  }

  terminate(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#worker.terminate();
    this.#failAll(internalFailure());
  }

  #request<T>(type: PendingCommand<T>["type"]): Promise<T> {
    if (this.#closed) return Promise.reject(internalFailure());
    const requestId = this.#takeId();
    const result = new Promise<T>((resolve, reject) => {
      this.#commands.set(requestId, {
        reject,
        resolve: (value) => resolve(value as T),
        type,
      });
    });
    this.#post({
      protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
      requestId,
      type,
    } as CaptureWorkerCommand);
    return result;
  }

  #receive(raw: unknown): void {
    const event = validateCaptureWorkerEvent(raw);
    if (event === undefined) {
      this.#abort(internalFailure());
      return;
    }
    if (event.type === "progress") {
      this.#imports.get(event.jobId)?.onProgress(event);
      return;
    }
    if (event.type === "complete" || event.type === "cancelled" || event.type === "import_error") {
      const pending = this.#imports.get(event.jobId);
      if (pending === undefined) return;
      this.#imports.delete(event.jobId);
      if (this.#activeJobId === event.jobId) this.#activeJobId = undefined;
      const terminalProgress: TerminalProgress = {
        ...(event.type === "complete" || event.lastParseProgress === undefined
          ? {}
          : { lastParseProgress: event.lastParseProgress }),
        ...(event.type === "complete" || event.lastReadProgress === undefined
          ? {}
          : { lastReadProgress: event.lastReadProgress }),
      };
      if (event.type === "complete") pending.resolve(event.summary);
      else if (event.type === "cancelled") {
        pending.reject(new CaptureImportCancelledError(terminalProgress));
      } else {
        const detail = importError(event.error);
        pending.reject(
          detail === undefined
            ? internalFailure()
            : new CaptureImportClientError(detail, terminalProgress),
        );
      }
      return;
    }

    const pending = this.#commands.get(event.requestId);
    if (pending === undefined) return;
    this.#commands.delete(event.requestId);
    if (event.type === "command_error") {
      const detail = importError(event.error);
      pending.reject(
        detail === undefined ? internalFailure() : new CaptureImportClientError(detail),
      );
      return;
    }
    const matches =
      (pending.type === "initialize" && event.type === "initialized") ||
      (pending.type === "dispose_dataset" && event.type === "dataset_disposed") ||
      (pending.type === "resource_stats" && event.type === "resource_stats") ||
      (pending.type === "shutdown" && event.type === "shutdown_complete");
    if (!matches) {
      pending.reject(internalFailure());
      return;
    }
    pending.resolve(
      event.type === "initialized"
        ? event.capabilities
        : event.type === "resource_stats"
          ? event.stats
          : undefined,
    );
  }

  #post(command: CaptureWorkerCommand): void {
    if (this.#closed) throw internalFailure();
    this.#worker.postMessage(command);
  }

  #takeId(): number {
    const id = this.#nextId;
    this.#nextId += 1;
    if (!Number.isSafeInteger(this.#nextId)) this.#nextId = 1;
    return id;
  }

  #failAll(error: CaptureImportClientError): void {
    for (const pending of this.#commands.values()) pending.reject(error);
    for (const pending of this.#imports.values()) pending.reject(error);
    this.#commands.clear();
    this.#imports.clear();
    this.#activeJobId = undefined;
    this.#startingImport = false;
  }

  #abort(error: CaptureImportClientError): void {
    if (!this.#closed) {
      this.#closed = true;
      this.#worker.terminate();
    }
    this.#failAll(error);
  }
}
