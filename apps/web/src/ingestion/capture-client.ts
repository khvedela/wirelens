import {
  decodePacketDetail,
  MAX_PACKET_DETAIL_BYTES,
  MAX_PACKET_DETAIL_FIELDS,
  MAX_PACKET_DETAIL_LAYERS,
  PACKET_DETAIL_SCHEMA_VERSION,
  type PacketDetail,
} from "../boundary/packet-detail";
import type { BoundaryErrorCode, ResourceStats } from "../boundary/worker-contract";
import {
  CAPTURE_INGESTION_PROTOCOL_VERSION,
  type CaptureWorkerCommand,
  type CaptureWorkerEvent,
  type ImportError,
  type ImportSummary,
  type IngestionCapabilities,
  PACKET_EVIDENCE_PAGE_BYTES,
  type PacketEvidencePage,
  type PacketQueryError,
  type PacketQueryErrorCode,
  type PacketSelectionResolution,
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

export class CapturePacketQueryError extends Error {
  constructor(readonly detail: PacketQueryError) {
    super(detail.code);
    this.name = "CapturePacketQueryError";
  }
}

export class CapturePacketQueryCancelledError extends CapturePacketQueryError {
  constructor() {
    super({ code: "cancelled" });
    this.name = "CapturePacketQueryCancelledError";
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

type PacketQueryType =
  | "read_packet_detail"
  | "read_packet_evidence_page"
  | "resolve_packet_selection";

interface PendingPacketQuery {
  cleanup(): void;
  datasetGeneration: number;
  packetId: number;
  pageStart?: number;
  reject(error: CapturePacketQueryError): void;
  resolve(value: unknown): void;
  selectionLength?: number;
  selectionStart?: number;
  type: PacketQueryType;
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
const PACKET_QUERY_ERROR_CODES = new Set<PacketQueryErrorCode>([
  "cancelled",
  "dataset_unavailable",
  "invalid_packet",
  "invalid_range",
  "resource_limit",
  "stale_dataset",
  "unsupported_version",
  "worker_failed",
]);
const DECODED_PACKET_DETAILS = new WeakMap<Uint8Array, PacketDetail>();
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

function queryFailure(code: PacketQueryErrorCode): CapturePacketQueryError {
  return new CapturePacketQueryError({ code });
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

function exactUint8Array(value: unknown, maximumElements: number): value is Uint8Array {
  return (
    value instanceof Uint8Array &&
    value.buffer instanceof ArrayBuffer &&
    value.byteOffset === 0 &&
    value.byteLength === value.buffer.byteLength &&
    value.length <= maximumElements
  );
}

function exactUint32Array(value: unknown, maximumElements: number): value is Uint32Array {
  return (
    value instanceof Uint32Array &&
    value.buffer instanceof ArrayBuffer &&
    value.byteOffset === 0 &&
    value.byteLength === value.buffer.byteLength &&
    value.length <= maximumElements
  );
}

function packetQueryError(value: unknown): PacketQueryError | undefined {
  const candidate = record(value);
  return candidate !== undefined &&
    typeof candidate.code === "string" &&
    PACKET_QUERY_ERROR_CODES.has(candidate.code as PacketQueryErrorCode)
    ? { code: candidate.code as PacketQueryErrorCode }
    : undefined;
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
    safeCount(candidate.warningCount) &&
    (candidate.datasetGeneration === undefined || positiveId(candidate.datasetGeneration))
  );
}

function ingestionCapabilities(value: unknown): value is IngestionCapabilities {
  const candidate = record(value);
  const wasm = record(candidate?.wasm);
  const inspection = record(candidate?.packetInspection);
  const inspectionIsValid =
    inspection === undefined ||
    (inspection.detailSchemaVersion === PACKET_DETAIL_SCHEMA_VERSION &&
      inspection.evidencePageBytes === PACKET_EVIDENCE_PAGE_BYTES &&
      safeCount(inspection.maxCorrelationMatches) &&
      inspection.maxCorrelationMatches > 0 &&
      inspection.maxCorrelationMatches <= MAX_PACKET_DETAIL_FIELDS &&
      safeCount(inspection.maxDetailBytes) &&
      inspection.maxDetailBytes >= 80 + 20 * 24 &&
      inspection.maxDetailBytes <= MAX_PACKET_DETAIL_BYTES &&
      safeCount(inspection.maxFieldsPerPacket) &&
      inspection.maxFieldsPerPacket > 0 &&
      inspection.maxFieldsPerPacket <= MAX_PACKET_DETAIL_FIELDS &&
      safeCount(inspection.maxLayersPerPacket) &&
      inspection.maxLayersPerPacket > 0 &&
      inspection.maxLayersPerPacket <= MAX_PACKET_DETAIL_LAYERS);
  return (
    candidate !== undefined &&
    inspectionIsValid &&
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

function packetQueryIdentity(value: Record<string, unknown>): boolean {
  return positiveId(value.requestId) && positiveId(value.datasetGeneration) && word(value.packetId);
}

function packetDetailEvent(value: Record<string, unknown>): boolean {
  if (!packetQueryIdentity(value) || !exactUint8Array(value.bytes, MAX_PACKET_DETAIL_BYTES)) {
    return false;
  }
  try {
    DECODED_PACKET_DETAILS.set(
      value.bytes,
      decodePacketDetail(value.bytes, value.packetId as number),
    );
    return true;
  } catch {
    return false;
  }
}

function packetEvidenceEvent(value: Record<string, unknown>): boolean {
  return (
    packetQueryIdentity(value) &&
    word(value.pageStart) &&
    value.pageStart % PACKET_EVIDENCE_PAGE_BYTES === 0 &&
    exactUint8Array(value.bytes, PACKET_EVIDENCE_PAGE_BYTES)
  );
}

function packetSelectionEvent(value: Record<string, unknown>): boolean {
  if (
    !packetQueryIdentity(value) ||
    !word(value.selectionStart) ||
    !word(value.selectionLength) ||
    value.selectionStart + value.selectionLength > 0xffff_ffff ||
    !exactUint32Array(value.fieldIds, MAX_PACKET_DETAIL_FIELDS)
  ) {
    return false;
  }
  const expectedPrimary = value.fieldIds[0] ?? null;
  if (value.primaryFieldId !== expectedPrimary) return false;
  const seen = new Set<number>();
  for (const fieldId of value.fieldIds) {
    if (seen.has(fieldId)) return false;
    seen.add(fieldId);
  }
  return true;
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
    case "packet_detail":
      return packetDetailEvent(candidate) ? (value as CaptureWorkerEvent) : undefined;
    case "packet_evidence_page":
      return packetEvidenceEvent(candidate) ? (value as CaptureWorkerEvent) : undefined;
    case "packet_selection_resolved":
      return packetSelectionEvent(candidate) ? (value as CaptureWorkerEvent) : undefined;
    case "packet_query_error":
      return packetQueryIdentity(candidate) && packetQueryError(candidate.error) !== undefined
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
  readonly #packetQueries = new Map<number, PendingPacketQuery>();
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
    this.#invalidatePacketQueries({ code: "dataset_unavailable" });
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
    this.#invalidatePacketQueries({ code: "dataset_unavailable" });
    await this.#initialization;
    await this.#request("dispose_dataset");
  }

  async resourceStats(): Promise<ResourceStats> {
    await this.#initialization;
    return this.#request<ResourceStats>("resource_stats");
  }

  async readPacketDetail(
    datasetGeneration: number,
    packetId: number,
    signal?: AbortSignal,
  ): Promise<PacketDetail> {
    const inspection = (await this.#packetCapabilities(signal)).packetInspection;
    this.#validatePacketIdentity(datasetGeneration, packetId, inspection !== undefined, signal);
    if (inspection === undefined) throw queryFailure("unsupported_version");
    return this.#packetRequest<PacketDetail>(
      {
        datasetGeneration,
        packetId,
        type: "read_packet_detail",
      },
      signal,
      (requestId) => ({
        datasetGeneration,
        detailSchemaVersion: inspection.detailSchemaVersion,
        packetId,
        protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
        requestId,
        type: "read_packet_detail",
      }),
    );
  }

  async readPacketEvidencePage(
    datasetGeneration: number,
    packetId: number,
    pageStart: number,
    signal?: AbortSignal,
  ): Promise<PacketEvidencePage> {
    const inspection = (await this.#packetCapabilities(signal)).packetInspection;
    this.#validatePacketIdentity(datasetGeneration, packetId, inspection !== undefined, signal);
    if (
      inspection === undefined ||
      !word(pageStart) ||
      pageStart % inspection.evidencePageBytes !== 0
    ) {
      throw queryFailure(inspection === undefined ? "unsupported_version" : "invalid_range");
    }
    return this.#packetRequest<PacketEvidencePage>(
      { datasetGeneration, packetId, pageStart, type: "read_packet_evidence_page" },
      signal,
      (requestId) => ({
        datasetGeneration,
        packetId,
        pageStart,
        protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
        requestId,
        type: "read_packet_evidence_page",
      }),
    );
  }

  async resolvePacketSelection(
    datasetGeneration: number,
    packetId: number,
    selectionStart: number,
    selectionLength: number,
    signal?: AbortSignal,
  ): Promise<PacketSelectionResolution> {
    const inspection = (await this.#packetCapabilities(signal)).packetInspection;
    this.#validatePacketIdentity(datasetGeneration, packetId, inspection !== undefined, signal);
    if (inspection === undefined) throw queryFailure("unsupported_version");
    const selectionEnd = selectionStart + selectionLength;
    if (
      !word(selectionStart) ||
      !word(selectionLength) ||
      !Number.isSafeInteger(selectionEnd) ||
      selectionEnd > 0xffff_ffff
    ) {
      throw queryFailure("invalid_range");
    }
    return this.#packetRequest<PacketSelectionResolution>(
      {
        datasetGeneration,
        packetId,
        selectionLength,
        selectionStart,
        type: "resolve_packet_selection",
      },
      signal,
      (requestId) => ({
        datasetGeneration,
        packetId,
        protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION,
        requestId,
        selectionLength,
        selectionStart,
        type: "resolve_packet_selection",
      }),
    );
  }

  async shutdown(): Promise<void> {
    if (this.#closed) return;
    this.#invalidatePacketQueries({ code: "dataset_unavailable" });
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

  #validatePacketIdentity(
    datasetGeneration: number,
    packetId: number,
    supported: boolean,
    signal?: AbortSignal,
  ): void {
    if (this.#closed) throw queryFailure("worker_failed");
    if (signal?.aborted) throw new CapturePacketQueryCancelledError();
    if (!supported) throw queryFailure("unsupported_version");
    if (!positiveId(datasetGeneration)) throw queryFailure("stale_dataset");
    if (!word(packetId)) throw queryFailure("invalid_packet");
  }

  #packetCapabilities(signal?: AbortSignal): Promise<IngestionCapabilities> {
    if (this.#closed) return Promise.reject(queryFailure("worker_failed"));
    if (signal?.aborted) return Promise.reject(new CapturePacketQueryCancelledError());
    if (signal === undefined) {
      return this.#initialization.catch(() => {
        throw queryFailure("worker_failed");
      });
    }
    return new Promise<IngestionCapabilities>((resolve, reject) => {
      const abort = (): void => {
        cleanup();
        reject(new CapturePacketQueryCancelledError());
      };
      const cleanup = (): void => signal.removeEventListener("abort", abort);
      signal.addEventListener("abort", abort, { once: true });
      void this.#initialization.then(
        (value) => {
          cleanup();
          resolve(value);
        },
        () => {
          cleanup();
          reject(queryFailure("worker_failed"));
        },
      );
      if (signal.aborted) abort();
    });
  }

  #packetRequest<T>(
    metadata: Omit<PendingPacketQuery, "cleanup" | "reject" | "resolve">,
    signal: AbortSignal | undefined,
    command: (requestId: number) => CaptureWorkerCommand,
  ): Promise<T> {
    if (this.#closed) return Promise.reject(queryFailure("worker_failed"));
    if (signal?.aborted) return Promise.reject(new CapturePacketQueryCancelledError());
    const requestId = this.#takeId();
    return new Promise<T>((resolve, reject) => {
      const abort = (): void => {
        const pending = this.#packetQueries.get(requestId);
        if (pending === undefined) return;
        this.#packetQueries.delete(requestId);
        pending.cleanup();
        reject(new CapturePacketQueryCancelledError());
      };
      const cleanup = (): void => signal?.removeEventListener("abort", abort);
      const pending: PendingPacketQuery = {
        ...metadata,
        cleanup,
        reject,
        resolve: (value) => resolve(value as T),
      };
      this.#packetQueries.set(requestId, pending);
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) {
        abort();
        return;
      }
      try {
        this.#post(command(requestId));
      } catch {
        this.#packetQueries.delete(requestId);
        cleanup();
        reject(queryFailure("worker_failed"));
      }
    });
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

    if (
      event.type === "packet_detail" ||
      event.type === "packet_evidence_page" ||
      event.type === "packet_selection_resolved" ||
      event.type === "packet_query_error"
    ) {
      if (event.type === "packet_query_error" && event.error.code === "worker_failed") {
        this.#abort(internalFailure());
        return;
      }
      const pending = this.#packetQueries.get(event.requestId);
      if (pending === undefined) return;
      if (
        pending.datasetGeneration !== event.datasetGeneration ||
        pending.packetId !== event.packetId ||
        (event.type === "packet_detail" && pending.type !== "read_packet_detail") ||
        (event.type === "packet_evidence_page" &&
          (pending.type !== "read_packet_evidence_page" ||
            pending.pageStart !== event.pageStart)) ||
        (event.type === "packet_selection_resolved" &&
          (pending.type !== "resolve_packet_selection" ||
            pending.selectionStart !== event.selectionStart ||
            pending.selectionLength !== event.selectionLength))
      ) {
        this.#abort(internalFailure());
        return;
      }
      this.#packetQueries.delete(event.requestId);
      pending.cleanup();
      if (event.type === "packet_query_error") {
        const detail = packetQueryError(event.error) ?? { code: "worker_failed" as const };
        pending.reject(new CapturePacketQueryError(detail));
        if (detail.code === "worker_failed") this.#abort(internalFailure());
        return;
      }
      try {
        if (event.type === "packet_detail") {
          const detail = DECODED_PACKET_DETAILS.get(event.bytes);
          DECODED_PACKET_DETAILS.delete(event.bytes);
          if (detail === undefined) throw new Error("validated packet detail was not retained");
          pending.resolve(detail);
        } else if (event.type === "packet_evidence_page") {
          pending.resolve({
            bytes: event.bytes,
            datasetGeneration: event.datasetGeneration,
            packetId: event.packetId,
            pageStart: event.pageStart,
          } satisfies PacketEvidencePage);
        } else {
          pending.resolve({
            datasetGeneration: event.datasetGeneration,
            fieldIds: event.fieldIds,
            packetId: event.packetId,
            primaryFieldId: event.primaryFieldId,
            selectionLength: event.selectionLength,
            selectionStart: event.selectionStart,
          } satisfies PacketSelectionResolution);
        }
      } catch {
        pending.reject(queryFailure("worker_failed"));
        this.#abort(internalFailure());
      }
      return;
    }

    if (event.type === "command_error") {
      const packetQuery = this.#packetQueries.get(event.requestId);
      if (packetQuery !== undefined) {
        this.#packetQueries.delete(event.requestId);
        packetQuery.cleanup();
        packetQuery.reject(queryFailure("worker_failed"));
        this.#abort(internalFailure());
        return;
      }
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
    for (const pending of this.#packetQueries.values()) {
      pending.cleanup();
      pending.reject(queryFailure("worker_failed"));
    }
    this.#commands.clear();
    this.#imports.clear();
    this.#packetQueries.clear();
    this.#activeJobId = undefined;
    this.#startingImport = false;
  }

  #invalidatePacketQueries(detail: PacketQueryError): void {
    for (const pending of this.#packetQueries.values()) {
      pending.cleanup();
      pending.reject(new CapturePacketQueryError(detail));
    }
    this.#packetQueries.clear();
  }

  #abort(error: CaptureImportClientError): void {
    if (!this.#closed) {
      this.#closed = true;
      this.#worker.terminate();
    }
    this.#failAll(error);
  }
}
