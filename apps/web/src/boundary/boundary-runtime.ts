import init, {
  apiVersion as compiledApiVersion,
  batchSchemaVersion as compiledBatchSchemaVersion,
  capabilities as compiledCapabilities,
  WireLensBoundary,
} from "./generated/wirelens_wasm_boundary.js";
import { validatePacketBatch } from "./packet-batch";
import {
  MAX_PACKET_DETAIL_BYTES,
  PACKET_DETAIL_SCHEMA_VERSION,
  validatePacketDetail,
} from "./packet-detail";
import {
  cancellationPhaseIsTerminal,
  exactU64IsPositive,
  importStateMatchesPhase,
  progressCountersAreOrdered,
} from "./progress-validation";
import type {
  BoundaryErrorCode,
  BoundaryFailure,
  BoundaryRequest,
  BoundarySuccess,
  BoundaryWarning,
  CancellationResult,
  Capabilities,
  DisposalResult,
  ImportStepResult,
  Metadata,
  ProgressSnapshot,
  ResourceStats,
  TransferAudit,
} from "./worker-contract";
import { BOUNDARY_API_VERSION } from "./worker-contract";

const KNOWN_ERROR_CODES = new Set<BoundaryErrorCode>([
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

export class BoundaryProtocolError extends Error {
  constructor(
    readonly code: BoundaryErrorCode,
    message: string,
  ) {
    super(message);
  }
}

/** Safe, validated failure surfaced by the runtime's direct product methods. */
export class BoundaryRuntimeError extends Error {
  readonly code: BoundaryErrorCode;

  constructor(readonly failure: BoundaryFailure) {
    super(failure.message);
    this.code = failure.code;
  }
}

let initialization: Promise<unknown> | undefined;
interface PendingPacketBatch {
  cursorHandle: bigint;
  nextRow: bigint;
  schemaVersion: number;
  startRow: bigint;
}

type RuntimeCommand<T> = T extends unknown ? Omit<T, "requestId"> : never;
type BoundaryRuntimeCommand = RuntimeCommand<BoundaryRequest>;
const MAX_OUTSTANDING_TRANSFERS = 1;
const MAX_U64 = (1n << 64n) - 1n;

function property(value: unknown, key: string): unknown {
  return typeof value === "object" && value !== null && key in value
    ? (value as Record<string, unknown>)[key]
    : undefined;
}

export function normalizeBoundaryFailure(error: unknown): BoundaryFailure {
  if (error instanceof BoundaryRuntimeError) return error.failure;
  const rawCode = property(error, "code");
  const code =
    typeof rawCode === "string" && KNOWN_ERROR_CODES.has(rawCode as BoundaryErrorCode)
      ? (rawCode as BoundaryErrorCode)
      : "internal_invariant";
  const rawMessage = property(error, "message");
  const failure: BoundaryFailure = {
    code,
    message: typeof rawMessage === "string" ? rawMessage : "boundary operation failed",
  };
  const inputOffsetHi = exactWord(property(error, "inputOffsetHi"));
  const inputOffsetLo = exactWord(property(error, "inputOffsetLo"));
  if (inputOffsetHi !== undefined && inputOffsetLo !== undefined) {
    failure.inputOffsetHi = inputOffsetHi;
    failure.inputOffsetLo = inputOffsetLo;
  }
  const resourceLimitHi = exactWord(property(error, "resourceLimitHi"));
  const resourceLimitLo = exactWord(property(error, "resourceLimitLo"));
  if (resourceLimitHi !== undefined && resourceLimitLo !== undefined) {
    failure.resourceLimitHi = resourceLimitHi;
    failure.resourceLimitLo = resourceLimitLo;
  }
  const rawProgress = property(error, "progress");
  if (rawProgress !== undefined) {
    const progress = normalizeProgress(rawProgress);
    if (progress === undefined || progress.phase !== "failed") {
      return {
        code: "internal_invariant",
        message: "Wasm returned invalid terminal error progress",
      };
    }
    failure.progress = progress;
  }
  return failure;
}

function exactWord(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffffffff
    ? value
    : undefined;
}

function requiredWord(value: unknown, label: string): number {
  const word = exactWord(value);
  if (word === undefined) {
    throw new BoundaryProtocolError("internal_invariant", `${label} is not an exact unsigned word`);
  }
  return word;
}

function requiredSafeInteger(value: unknown, label: string, minimum = 0): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) {
    throw new BoundaryProtocolError("internal_invariant", `${label} is not an exact integer`);
  }
  return value;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string") {
    throw new BoundaryProtocolError("internal_invariant", `${label} is not a string`);
  }
  return value;
}

function normalizeProgress(value: unknown): ProgressSnapshot | undefined {
  const phase = property(value, "phase");
  if (
    phase !== "cancelled" &&
    phase !== "complete" &&
    phase !== "failed" &&
    phase !== "parsing" &&
    phase !== "validating"
  ) {
    return undefined;
  }
  const words = {
    bytesConsumedHi: exactWord(property(value, "bytesConsumedHi")),
    bytesConsumedLo: exactWord(property(value, "bytesConsumedLo")),
    diagnostics: exactWord(property(value, "diagnostics")),
    packetsRetainedHi: exactWord(property(value, "packetsRetainedHi")),
    packetsRetainedLo: exactWord(property(value, "packetsRetainedLo")),
    recordsHi: exactWord(property(value, "recordsHi")),
    recordsLo: exactWord(property(value, "recordsLo")),
    totalBytesHi: exactWord(property(value, "totalBytesHi")),
    totalBytesLo: exactWord(property(value, "totalBytesLo")),
  };
  if (Object.values(words).some((word) => word === undefined)) return undefined;
  const progress = { ...words, phase } as ProgressSnapshot;
  return progressCountersAreOrdered(progress) ? progress : undefined;
}

function requiredProgress(value: unknown): ProgressSnapshot {
  const progress = normalizeProgress(value);
  if (progress === undefined) {
    throw new BoundaryProtocolError("internal_invariant", "Wasm returned invalid import progress");
  }
  return progress;
}

function wasmHandle(value: unknown): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm returned a non-canonical boundary handle",
    );
  }
  return value;
}

function normalizeCapabilities(value: unknown): Capabilities {
  const positiveIntegerKeys = [
    "apiVersion",
    "batchSchemaVersion",
    "maxBlockBytes",
    "maxCaptureBytes",
    "maxDatasetHandles",
    "maxDecodedItemsPerBlock",
    "maxDecodedItemsPerStep",
    "maxDiagnostics",
    "maxEvidenceBytes",
    "maxImportHandles",
    "maxImportStepBytes",
    "maxImportStepRecords",
    "maxInterfaces",
    "maxInternedStringBytes",
    "maxPacketBatchBytes",
    "maxPacketBatchRows",
    "maxPacketCursorHandles",
    "maxPackets",
    "maxSections",
    "maxTotalCaptureBytes",
    "maxTotalLogicalBytes",
    "packetAdmissionBase",
    "packetAdmissionBytesPerPacket",
  ] as const;
  const optionalPositiveIntegerKeys = [
    "detailSchemaVersion",
    "decodedFieldAdmissionBase",
    "decodedFieldAdmissionBytesPerItem",
    "decodedLayerAdmissionBase",
    "decodedLayerAdmissionBytesPerItem",
    "fieldChildAdmissionBase",
    "fieldChildAdmissionBytesPerItem",
    "maxFieldChildren",
    "maxFieldChildrenPerPacket",
    "maxCorrelationMatches",
    "maxFields",
    "maxFieldsPerPacket",
    "maxLayers",
    "maxLayersPerPacket",
    "maxPacketDetailBytes",
    "maxPacketEvidenceBytes",
  ] as const;
  const normalized = Object.fromEntries(
    positiveIntegerKeys.map((key) => [
      key,
      requiredSafeInteger(property(value, key), `capability ${key}`, 1),
    ]),
  ) as unknown as Pick<Capabilities, (typeof positiveIntegerKeys)[number]>;
  const optionalIntegers = Object.fromEntries(
    optionalPositiveIntegerKeys.flatMap((key) => {
      const candidate = property(value, key);
      return candidate === undefined
        ? []
        : [[key, requiredSafeInteger(candidate, `capability ${key}`, 1)]];
    }),
  ) as Partial<Pick<Capabilities, (typeof optionalPositiveIntegerKeys)[number]>>;
  if (
    normalized.apiVersion !== compiledApiVersion() ||
    normalized.batchSchemaVersion !== compiledBatchSchemaVersion()
  ) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm capability versions are inconsistent",
    );
  }
  const inspectionCapabilityKeys = [
    "detailSchemaVersion",
    "maxCorrelationMatches",
    "maxPacketDetailBytes",
    "maxPacketEvidenceBytes",
  ] as const;
  const inspectionCapabilityCount = inspectionCapabilityKeys.filter(
    (key) => optionalIntegers[key] !== undefined,
  ).length;
  if (
    inspectionCapabilityCount !== 0 &&
    inspectionCapabilityCount !== inspectionCapabilityKeys.length
  ) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm packet-inspection capabilities are incomplete",
    );
  }
  if (
    inspectionCapabilityCount !== 0 &&
    (optionalIntegers.detailSchemaVersion !== PACKET_DETAIL_SCHEMA_VERSION ||
      (optionalIntegers.maxPacketDetailBytes ?? 0) > MAX_PACKET_DETAIL_BYTES ||
      (optionalIntegers.maxPacketEvidenceBytes ?? 0) > normalized.maxEvidenceBytes ||
      (optionalIntegers.maxCorrelationMatches ?? 0) >
        (optionalIntegers.maxFieldsPerPacket ?? Number.MAX_SAFE_INTEGER))
  ) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm packet-inspection capabilities are inconsistent",
    );
  }
  const decodedArenaAdmissionRule = property(value, "decodedArenaAdmissionRule");
  return {
    ...normalized,
    ...optionalIntegers,
    ...(decodedArenaAdmissionRule === undefined
      ? {}
      : {
          decodedArenaAdmissionRule: requiredString(
            decodedArenaAdmissionRule,
            "capability decodedArenaAdmissionRule",
          ),
        }),
    packetAdmissionRule: requiredString(
      property(value, "packetAdmissionRule"),
      "capability packetAdmissionRule",
    ),
  };
}

function normalizeWarning(value: unknown): BoundaryWarning {
  const severity = property(value, "severity");
  const recovery = property(value, "recovery");
  const scope = property(value, "scope");
  if (
    severity !== "error" &&
    severity !== "fatal" &&
    severity !== "info" &&
    severity !== "warning"
  ) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm returned invalid diagnostic severity",
    );
  }
  if (
    recovery !== "capture_rejected" &&
    recovery !== "continued" &&
    recovery !== "record_skipped"
  ) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm returned invalid diagnostic recovery",
    );
  }
  if (scope !== "capture" && scope !== "packet") {
    throw new BoundaryProtocolError("internal_invariant", "Wasm returned invalid diagnostic scope");
  }
  const warning: BoundaryWarning = {
    code: requiredSafeInteger(property(value, "code"), "diagnostic code"),
    message: requiredString(property(value, "message"), "diagnostic message"),
    recovery,
    scope,
    severity,
  };
  if (warning.code > 0xffff) {
    throw new BoundaryProtocolError("internal_invariant", "Wasm diagnostic code exceeds u16");
  }
  const packetId = property(value, "packetId");
  if (scope === "packet") {
    warning.packetId = requiredWord(packetId, "diagnostic packetId");
  } else if (packetId !== undefined) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "capture diagnostic contains a packet ID",
    );
  }
  const evidenceLength = property(value, "evidenceLength");
  const evidenceStartHi = property(value, "evidenceStartHi");
  const evidenceStartLo = property(value, "evidenceStartLo");
  const hasEvidence =
    evidenceLength !== undefined || evidenceStartHi !== undefined || evidenceStartLo !== undefined;
  if (hasEvidence) {
    warning.evidenceLength = requiredWord(evidenceLength, "diagnostic evidenceLength");
    warning.evidenceStartHi = requiredWord(evidenceStartHi, "diagnostic evidenceStartHi");
    warning.evidenceStartLo = requiredWord(evidenceStartLo, "diagnostic evidenceStartLo");
  }
  return warning;
}

function normalizeImportStep(value: unknown): ImportStepResult {
  const state = property(value, "state");
  if (state !== "cancelled" && state !== "complete" && state !== "in_progress") {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm returned invalid import step state",
    );
  }
  const result: ImportStepResult = {
    progress: requiredProgress(property(value, "progress")),
    state,
  };
  if (!importStateMatchesPhase(result.state, result.progress.phase)) {
    throw new BoundaryProtocolError("internal_invariant", "Wasm import state and phase disagree");
  }
  const minimumBytesHi = property(value, "minimumBytesHi");
  const minimumBytesLo = property(value, "minimumBytesLo");
  if (minimumBytesHi !== undefined || minimumBytesLo !== undefined) {
    result.minimumBytesHi = requiredWord(minimumBytesHi, "minimumBytesHi");
    result.minimumBytesLo = requiredWord(minimumBytesLo, "minimumBytesLo");
    if (
      state !== "in_progress" ||
      result.progress.phase !== "parsing" ||
      !exactU64IsPositive(result.minimumBytesHi, result.minimumBytesLo)
    ) {
      throw new BoundaryProtocolError(
        "internal_invariant",
        "Wasm returned an invalid minimum budget",
      );
    }
  }
  const datasetHandle = property(value, "datasetHandle");
  const warningCodes = property(value, "warningCodes");
  const warnings = property(value, "warnings");
  if (state === "complete") {
    result.datasetHandle = wasmHandle(datasetHandle);
    if (!(warningCodes instanceof Uint16Array) || !Array.isArray(warnings)) {
      throw new BoundaryProtocolError(
        "internal_invariant",
        "Wasm returned invalid completion diagnostics",
      );
    }
    result.warningCodes = warningCodes;
    result.warnings = warnings.map(normalizeWarning);
    if (
      result.warningCodes.length !== result.warnings.length ||
      result.warnings.some((warning, index) => warning.code !== result.warningCodes?.[index])
    ) {
      throw new BoundaryProtocolError("internal_invariant", "Wasm diagnostic views disagree");
    }
  } else if (datasetHandle !== undefined || warningCodes !== undefined || warnings !== undefined) {
    throw new BoundaryProtocolError("internal_invariant", "non-terminal import exposed a dataset");
  }
  return result;
}

function normalizeCancellation(value: unknown): CancellationResult {
  const status = property(value, "status");
  if (status !== "already_terminal" && status !== "cancelled") {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm returned invalid cancellation status",
    );
  }
  const rawProgress = property(value, "progress");
  if (status === "cancelled") {
    const progress = requiredProgress(rawProgress);
    if (!cancellationPhaseIsTerminal(progress)) {
      throw new BoundaryProtocolError(
        "internal_invariant",
        "Wasm cancellation phase is not terminal",
      );
    }
    return { progress, status };
  }
  if (rawProgress !== undefined) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "terminal cancellation included progress",
    );
  }
  return { status };
}

function normalizeDisposal(value: unknown): DisposalResult {
  const status = property(value, "status");
  if (status !== "already_disposed" && status !== "disposed") {
    throw new BoundaryProtocolError("internal_invariant", "Wasm returned invalid disposal status");
  }
  const result: DisposalResult = { status };
  const dependentCursors = property(value, "dependentCursors");
  if (dependentCursors !== undefined) {
    result.dependentCursors = requiredWord(dependentCursors, "dependent cursor count");
  }
  return result;
}

function normalizeResourceStats(value: unknown): ResourceStats {
  const countKeys = ["cursors", "datasets", "imports"] as const;
  const laneKeys = [
    "currentOwnedCaptureBytesHi",
    "currentOwnedCaptureBytesLo",
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
  return {
    ...Object.fromEntries(
      countKeys.map((key) => [key, requiredWord(property(value, key), `resource stat ${key}`)]),
    ),
    ...Object.fromEntries(
      laneKeys.map((key) => [key, requiredWord(property(value, key), `resource stat ${key}`)]),
    ),
  } as unknown as ResourceStats;
}

function canonicalHandle(value: unknown): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64) {
    throw new BoundaryProtocolError(
      "invalid_handle",
      "boundary handle is not a canonical u64 BigInt",
    );
  }
  return value;
}

function exactByteArray(value: unknown, maximum: number, label: string): Uint8Array {
  if (
    !(value instanceof Uint8Array) ||
    !(value.buffer instanceof ArrayBuffer) ||
    value.byteOffset !== 0 ||
    value.byteLength !== value.buffer.byteLength ||
    value.byteLength > maximum
  ) {
    throw new BoundaryProtocolError("internal_invariant", `Wasm returned invalid ${label}`);
  }
  return value;
}

function exactFieldIds(value: unknown, maximum: number): Uint32Array {
  if (
    !(value instanceof Uint32Array) ||
    !(value.buffer instanceof ArrayBuffer) ||
    value.byteOffset !== 0 ||
    value.byteLength !== value.buffer.byteLength ||
    value.length > maximum
  ) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "Wasm returned invalid correlated field IDs",
    );
  }
  const seen = new Set<number>();
  for (const fieldId of value) {
    if (seen.has(fieldId)) {
      throw new BoundaryProtocolError(
        "internal_invariant",
        "Wasm returned duplicate correlated field IDs",
      );
    }
    seen.add(fieldId);
  }
  return value;
}

async function initialize(): Promise<void> {
  initialization ??= init();
  await initialization;
}

function assertApiVersion(requested: number): void {
  if (!Number.isSafeInteger(requested) || requested !== compiledApiVersion()) {
    throw new BoundaryProtocolError("unsupported_version", "worker API version is unsupported");
  }
}

/**
 * Product-owned, validated runtime for the versioned Rust/Wasm boundary.
 *
 * The runtime contains no main-thread UI behavior and installs no message
 * listener by itself. Product orchestration can call [`dispatch`] directly;
 * the issue #9 harness uses [`installBoundaryWorker`] below to preserve its
 * reviewed request/response and transfer-audit transport.
 */
export class BoundaryRuntime {
  readonly #workerContext: string;
  #boundary: WireLensBoundary | undefined;
  #nextDirectRequestId = 1;
  readonly #outstandingTransfers = new Set<number>();
  readonly #pendingPacketBatches = new Map<number, PendingPacketBatch>();

  constructor(workerContext = globalThis.constructor.name) {
    this.#workerContext = workerContext;
  }

  metadata(apiVersion = BOUNDARY_API_VERSION): Promise<Metadata> {
    return this.#dispatchDirect<Metadata>({ apiVersion, operation: "metadata" });
  }

  beginImport(bytes: Uint8Array, apiVersion = BOUNDARY_API_VERSION): Promise<bigint> {
    return this.#dispatchDirect<bigint>({ apiVersion, bytes, operation: "begin_import" });
  }

  stepImport(
    handle: bigint,
    maxRecords: number,
    maxBytes: number,
    apiVersion = BOUNDARY_API_VERSION,
  ): Promise<ImportStepResult> {
    return this.#dispatchDirect<ImportStepResult>({
      apiVersion,
      handle,
      maxBytes,
      maxRecords,
      operation: "step_import",
    });
  }

  cancelImport(handle: bigint, apiVersion = BOUNDARY_API_VERSION): Promise<CancellationResult> {
    return this.#dispatchDirect<CancellationResult>({
      apiVersion,
      handle,
      operation: "cancel_import",
    });
  }

  readPacketDetail(
    datasetHandle: bigint,
    packetId: number,
    detailSchemaVersion: number,
    maxBytes: number,
    apiVersion = BOUNDARY_API_VERSION,
  ): Promise<Uint8Array> {
    return this.#dispatchDirect<Uint8Array>({
      apiVersion,
      datasetHandle,
      detailSchemaVersion,
      maxBytes,
      operation: "read_packet_detail",
      packetId,
    });
  }

  readPacketEvidence(
    datasetHandle: bigint,
    packetId: number,
    relativeStart: number,
    maxBytes: number,
    apiVersion = BOUNDARY_API_VERSION,
  ): Promise<Uint8Array> {
    return this.#dispatchDirect<Uint8Array>({
      apiVersion,
      datasetHandle,
      maxBytes,
      operation: "read_packet_evidence",
      packetId,
      relativeStart,
    });
  }

  correlatePacketRange(
    datasetHandle: bigint,
    packetId: number,
    relativeStart: number,
    length: number,
    apiVersion = BOUNDARY_API_VERSION,
  ): Promise<Uint32Array> {
    return this.#dispatchDirect<Uint32Array>({
      apiVersion,
      datasetHandle,
      length,
      operation: "correlate_packet_range",
      packetId,
      relativeStart,
    });
  }

  dispose(handle: bigint, apiVersion = BOUNDARY_API_VERSION): Promise<DisposalResult> {
    return this.#dispatchDirect<DisposalResult>({ apiVersion, handle, operation: "dispose" });
  }

  resourceStats(apiVersion = BOUNDARY_API_VERSION): Promise<ResourceStats> {
    return this.#dispatchDirect<ResourceStats>({ apiVersion, operation: "resource_stats" });
  }

  async shutdown(apiVersion = BOUNDARY_API_VERSION): Promise<void> {
    await this.#dispatchDirect({ apiVersion, operation: "shutdown" });
  }

  async dispatch(request: BoundaryRequest): Promise<unknown> {
    await initialize();
    assertApiVersion(request.apiVersion);

    if (request.operation === "metadata") {
      const capabilities = normalizeCapabilities(compiledCapabilities());
      const metadata: Metadata = {
        apiVersion: compiledApiVersion(),
        batchSchemaVersion: compiledBatchSchemaVersion(),
        capabilities,
        workerContext: this.#workerContext,
      };
      return metadata;
    }

    const adapter = this.#state(request.apiVersion);
    switch (request.operation) {
      case "begin_import": {
        if (
          !(request.bytes instanceof Uint8Array) ||
          !(request.bytes.buffer instanceof ArrayBuffer) ||
          request.bytes.byteOffset !== 0 ||
          request.bytes.byteLength !== request.bytes.buffer.byteLength
        ) {
          throw new BoundaryProtocolError(
            "invalid_argument",
            "capture bytes must span one exact transferable ArrayBuffer",
          );
        }
        return wasmHandle(adapter.beginImport(request.bytes));
      }
      case "step_import":
        return normalizeImportStep(
          adapter.stepImport(canonicalHandle(request.handle), request.maxRecords, request.maxBytes),
        );
      case "cancel_import":
        return normalizeCancellation(adapter.cancelImport(canonicalHandle(request.handle)));
      case "dispose":
        return normalizeDisposal(adapter.dispose(canonicalHandle(request.handle)));
      case "open_packet_cursor":
        return wasmHandle(
          adapter.openPacketCursor(canonicalHandle(request.datasetHandle), request.startRow),
        );
      case "read_packet_batch": {
        this.#assertTransferCapacity();
        const cursorHandle = canonicalHandle(request.cursorHandle);
        const bytes = adapter.readPacketBatch(
          cursorHandle,
          request.batchSchemaVersion,
          request.maxRows,
          request.maxBytes,
        );
        try {
          const validated = validatePacketBatch(bytes);
          this.#pendingPacketBatches.set(request.requestId, {
            cursorHandle,
            nextRow: validated.nextRow,
            schemaVersion: request.batchSchemaVersion,
            startRow: validated.startRow,
          });
        } catch {
          // A corrupt Wasm result cannot be committed or safely retried. Disposing
          // the cursor releases the staged transaction without advancing it.
          adapter.dispose(cursorHandle);
          throw new BoundaryProtocolError(
            "internal_invariant",
            "Wasm returned an invalid packet batch",
          );
        }
        return bytes;
      }
      case "read_evidence": {
        this.#assertTransferCapacity();
        return adapter.readEvidence(
          canonicalHandle(request.datasetHandle),
          request.startHi,
          request.startLo,
          request.length,
        );
      }
      case "read_packet_detail": {
        this.#assertTransferCapacity();
        const bytes = exactByteArray(
          adapter.readPacketDetail(
            canonicalHandle(request.datasetHandle),
            request.packetId,
            request.detailSchemaVersion,
            request.maxBytes,
          ),
          Math.min(MAX_PACKET_DETAIL_BYTES, request.maxBytes),
          "packet detail",
        );
        try {
          validatePacketDetail(bytes, request.packetId);
        } catch {
          throw new BoundaryProtocolError(
            "internal_invariant",
            "Wasm returned an invalid packet detail",
          );
        }
        return bytes;
      }
      case "read_packet_evidence": {
        this.#assertTransferCapacity();
        return exactByteArray(
          adapter.readPacketEvidence(
            canonicalHandle(request.datasetHandle),
            request.packetId,
            request.relativeStart,
            request.maxBytes,
          ),
          request.maxBytes,
          "packet evidence",
        );
      }
      case "correlate_packet_range": {
        this.#assertTransferCapacity();
        const maximum = normalizeCapabilities(compiledCapabilities()).maxCorrelationMatches;
        if (maximum === undefined) {
          throw new BoundaryProtocolError(
            "unsupported_version",
            "packet correlation is unavailable",
          );
        }
        return exactFieldIds(
          adapter.correlatePacketRange(
            canonicalHandle(request.datasetHandle),
            request.packetId,
            request.relativeStart,
            request.length,
          ),
          maximum,
        );
      }
      case "resource_stats":
        return normalizeResourceStats(adapter.resourceStats());
      case "wasm_memory_bytes": {
        const bytes = adapter.wasmMemoryBytes();
        if (typeof bytes !== "bigint" || bytes < 0n || bytes > MAX_U64) {
          throw new BoundaryProtocolError(
            "internal_invariant",
            "Wasm returned invalid memory bytes",
          );
        }
        return bytes;
      }
      case "commit_packet_batch":
      case "discard_packet_batch": {
        if (!Number.isSafeInteger(request.transferRequestId) || request.transferRequestId <= 0) {
          throw new BoundaryProtocolError(
            "invalid_argument",
            "packet batch transaction ID is invalid",
          );
        }
        const pending = this.#pendingPacketBatches.get(request.transferRequestId);
        if (pending === undefined) {
          throw new BoundaryProtocolError(
            "invalid_state",
            "packet batch transaction is not pending",
          );
        }
        try {
          if (request.operation === "commit_packet_batch") {
            adapter.commitPacketBatch(
              pending.cursorHandle,
              pending.schemaVersion,
              pending.startRow,
              pending.nextRow,
            );
          } else {
            adapter.discardPacketBatch(
              pending.cursorHandle,
              pending.schemaVersion,
              pending.startRow,
              pending.nextRow,
            );
          }
        } catch (error) {
          // Once resolution fails, the runtime cannot know whether the adapter
          // mutated its staged cursor transaction before rejecting. Fail closed
          // by disposing that cursor; an already-invalid cursor is harmless.
          try {
            adapter.dispose(pending.cursorHandle);
          } catch {
            // Preserve the transaction error. Wasm teardown remains the final
            // reclamation boundary if even idempotent cursor disposal fails.
          }
          throw error;
        } finally {
          // Never leave transfer acknowledgement blocked by stale transaction
          // metadata, including when commit, discard, or cleanup rejects.
          this.#pendingPacketBatches.delete(request.transferRequestId);
        }
        return null;
      }
      case "ack_transfer": {
        if (!Number.isSafeInteger(request.transferRequestId) || request.transferRequestId <= 0) {
          throw new BoundaryProtocolError(
            "invalid_argument",
            "transfer acknowledgement is invalid",
          );
        }
        if (this.#pendingPacketBatches.has(request.transferRequestId)) {
          throw new BoundaryProtocolError(
            "invalid_state",
            "packet batch must be committed or discarded before acknowledgement",
          );
        }
        return { acknowledged: this.#outstandingTransfers.delete(request.transferRequestId) };
      }
      case "shutdown":
        adapter.free();
        this.#boundary = undefined;
        this.#outstandingTransfers.clear();
        this.#pendingPacketBatches.clear();
        return null;
      default:
        throw new BoundaryProtocolError("invalid_argument", "worker operation is unsupported");
    }
  }

  /** Records a binary response only after its source buffer was transferred. */
  recordTransfer(requestId: number): void {
    this.#outstandingTransfers.add(requestId);
  }

  /**
   * Rolls back a staged packet transaction if transport fails after dispatch.
   * Cleanup intentionally preserves the original transport/protocol failure.
   */
  rollbackPendingPacketBatch(requestId: number): void {
    const pending = this.#pendingPacketBatches.get(requestId);
    if (pending === undefined) return;
    try {
      this.#boundary?.discardPacketBatch(
        pending.cursorHandle,
        pending.schemaVersion,
        pending.startRow,
        pending.nextRow,
      );
    } catch {
      // The transfer failed after staging and discard could not restore a
      // known cursor state. Fail closed without replacing the original error.
      try {
        this.#boundary?.dispose(pending.cursorHandle);
      } catch {
        // Wasm teardown remains the final reclamation boundary.
      }
    }
    this.#pendingPacketBatches.delete(requestId);
  }

  #assertTransferCapacity(): void {
    if (this.#outstandingTransfers.size >= MAX_OUTSTANDING_TRANSFERS) {
      throw new BoundaryProtocolError(
        "resource_limit",
        "a binary response is still awaiting acknowledgement",
      );
    }
  }

  #dispatchDirect<T>(command: BoundaryRuntimeCommand): Promise<T> {
    if (this.#nextDirectRequestId > Number.MAX_SAFE_INTEGER) {
      throw new BoundaryProtocolError("resource_limit", "boundary request IDs are exhausted");
    }
    const requestId = this.#nextDirectRequestId;
    this.#nextDirectRequestId += 1;
    return (this.dispatch({ ...command, requestId } as BoundaryRequest) as Promise<T>).catch(
      (error: unknown) => {
        throw new BoundaryRuntimeError(normalizeBoundaryFailure(error));
      },
    );
  }

  #state(requestedVersion: number): WireLensBoundary {
    this.#boundary ??= new WireLensBoundary(requestedVersion);
    return this.#boundary;
  }
}

/** Installs the reviewed issue #9 API-v1 worker transport around the runtime. */
export function installBoundaryWorker(): BoundaryRuntime {
  const runtime = new BoundaryRuntime(globalThis.constructor.name);
  globalThis.addEventListener("message", (event: MessageEvent<unknown>) => {
    const rawRequest = event.data;
    const rawOperation = property(rawRequest, "operation");
    const operation = typeof rawOperation === "string" ? rawOperation : "invalid_request";
    const rawRequestId = property(rawRequest, "requestId");
    const requestId =
      typeof rawRequestId === "number" && Number.isSafeInteger(rawRequestId) && rawRequestId > 0
        ? rawRequestId
        : 0;
    void (async () => {
      try {
        if (
          typeof rawRequest !== "object" ||
          rawRequest === null ||
          requestId === 0 ||
          typeof property(rawRequest, "apiVersion") !== "number" ||
          typeof rawOperation !== "string"
        ) {
          throw new BoundaryProtocolError("invalid_argument", "worker request envelope is invalid");
        }
        const request = rawRequest as BoundaryRequest;
        const value = await runtime.dispatch(request);
        const response: BoundarySuccess = {
          apiVersion: BOUNDARY_API_VERSION,
          kind: "success",
          operation: request.operation,
          requestId: request.requestId,
          status: "ok",
          value,
        };
        if (
          request.operation === "read_packet_batch" ||
          request.operation === "read_evidence" ||
          request.operation === "read_packet_detail" ||
          request.operation === "read_packet_evidence" ||
          request.operation === "correlate_packet_range"
        ) {
          if (!(value instanceof Uint8Array) && !(value instanceof Uint32Array)) {
            throw new BoundaryProtocolError(
              "internal_invariant",
              "binary response is not a typed array",
            );
          }
          if (!(value.buffer instanceof ArrayBuffer)) {
            throw new BoundaryProtocolError(
              "internal_invariant",
              "binary response is not transferable",
            );
          }
          globalThis.postMessage(response, { transfer: [value.buffer] });
          runtime.recordTransfer(request.requestId);
          const audit: TransferAudit = {
            apiVersion: BOUNDARY_API_VERSION,
            detached: value.byteLength === 0,
            kind: "transfer_audit",
            operation: request.operation,
            requestId: request.requestId,
            status: "transferred",
          };
          globalThis.postMessage(audit);
        } else {
          globalThis.postMessage(response);
        }
      } catch (error) {
        runtime.rollbackPendingPacketBatch(requestId);
        globalThis.postMessage({
          apiVersion: BOUNDARY_API_VERSION,
          error: normalizeBoundaryFailure(error),
          kind: "error",
          operation,
          requestId,
          status: "error",
        });
      }
    })();
  });
  return runtime;
}
