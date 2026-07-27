/// <reference lib="webworker" />

import {
  BoundaryProtocolError,
  BoundaryRuntime,
  normalizeBoundaryFailure,
} from "../boundary/boundary-runtime";
import type {
  BoundaryErrorCode,
  BoundaryFailure,
  ProgressSnapshot,
} from "../boundary/worker-contract";
import {
  CAPTURE_INGESTION_PROTOCOL_VERSION,
  type CaptureWorkerCommand,
  type CaptureWorkerEvent,
  type ImportError,
  type ImportSummary,
  type IngestionCapabilities,
  PACKET_EVIDENCE_PAGE_BYTES,
  type PacketInspectionCapabilities,
  type PacketQueryError,
  type ParseProgress,
  type ReadProgress,
} from "../ingestion/capture-contract";
import {
  type DetectedCaptureFormat,
  detectCaptureFormat,
  filenameHint,
} from "../ingestion/capture-format";
import { reclaimImportHandle } from "../ingestion/import-cleanup";

const READ_CHUNK_BYTES = 4 * 1024 * 1024;
const PARSE_STEP_BYTES = 4 * 1024 * 1024;
const PARSE_STEP_RECORDS = 4_096;
const MAX_ACTIVE_PACKET_QUERIES = 8;

const runtime = new BoundaryRuntime(globalThis.constructor.name);
let capabilities: IngestionCapabilities | undefined;
interface LiveDataset {
  generation: number;
  handle: bigint;
  packetCount: number;
}

let liveDataset: LiveDataset | undefined;
let nextDatasetGeneration = 1;
let shuttingDown = false;

interface ActiveJob {
  cancelRequested: boolean;
  cancellingReported: boolean;
  id: number;
  importHandle?: bigint;
  lastParseProgress?: ParseProgress;
  lastReadProgress?: ReadProgress;
}

let activeJob: ActiveJob | undefined;
let activeWork: Promise<void> | undefined;
const activePacketQueries = new Map<number, Promise<void>>();

class ImportFailure extends Error {
  constructor(
    readonly detail: ImportError,
    readonly boundaryCode?: BoundaryErrorCode,
  ) {
    super(detail.code);
  }
}

class ImportCancelled extends Error {}

class PacketQueryFailure extends Error {
  constructor(readonly detail: PacketQueryError) {
    super(detail.code);
  }
}

function post(event: CaptureWorkerEvent): void {
  globalThis.postMessage(event);
}

function envelope(): { protocolVersion: number } {
  return { protocolVersion: CAPTURE_INGESTION_PROTOCOL_VERSION };
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null
    ? (value as Record<string, unknown>)
    : undefined;
}

function exactPositiveId(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0 ? value : undefined;
}

function exactU32(value: unknown): number | undefined {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= 0xffff_ffff
    ? value
    : undefined;
}

function takeDatasetGeneration(): number {
  if (!Number.isSafeInteger(nextDatasetGeneration) || nextDatasetGeneration <= 0) {
    throw new BoundaryProtocolError("resource_limit", "dataset generations are exhausted");
  }
  const generation = nextDatasetGeneration;
  nextDatasetGeneration += 1;
  return generation;
}

function exactU64(high: number, low: number): bigint {
  return (BigInt(high) << 32n) | BigInt(low);
}

function exactSafeNumber(high: number, low: number): number {
  const value = exactU64(high, low);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new BoundaryProtocolError(
      "internal_invariant",
      "progress exceeded the exact browser presentation range",
    );
  }
  return Number(value);
}

function parseProgress(progress: ProgressSnapshot): ParseProgress {
  return {
    bytesConsumed: exactSafeNumber(progress.bytesConsumedHi, progress.bytesConsumedLo),
    diagnostics: progress.diagnostics,
    packetsRetained: exactSafeNumber(progress.packetsRetainedHi, progress.packetsRetainedLo),
    phase: progress.phase,
    records: exactSafeNumber(progress.recordsHi, progress.recordsLo),
    totalBytes: exactSafeNumber(progress.totalBytesHi, progress.totalBytesLo),
  };
}

function boundaryFailure(error: unknown): {
  boundaryCode: BoundaryErrorCode;
  detail: ImportError;
  progress?: ParseProgress;
} {
  const failure: BoundaryFailure = normalizeBoundaryFailure(error);
  const code: ImportError["code"] =
    failure.code === "malformed_capture" ||
    failure.code === "resource_limit" ||
    failure.code === "truncated_capture" ||
    failure.code === "unsupported_format" ||
    failure.code === "unsupported_version"
      ? failure.code
      : "internal_failure";
  const detail: ImportError = { code };
  if (failure.inputOffsetHi !== undefined && failure.inputOffsetLo !== undefined) {
    detail.inputOffset = exactU64(failure.inputOffsetHi, failure.inputOffsetLo).toString();
  }
  if (failure.resourceLimitHi !== undefined && failure.resourceLimitLo !== undefined) {
    const limit = exactU64(failure.resourceLimitHi, failure.resourceLimitLo);
    if (limit <= BigInt(Number.MAX_SAFE_INTEGER)) detail.limitBytes = Number(limit);
  }
  return {
    boundaryCode: failure.code,
    detail,
    ...(failure.progress === undefined ? {} : { progress: parseProgress(failure.progress) }),
  };
}

function failIfCancelled(job: ActiveJob): void {
  if (job.cancelRequested) throw new ImportCancelled();
}

function yieldMacrotask(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function ensureCapabilities(): Promise<IngestionCapabilities> {
  if (capabilities !== undefined) return capabilities;
  const metadata = await runtime.metadata();
  const packetInspection = packetInspectionCapabilities(metadata.capabilities);
  capabilities = {
    maxCaptureBytes: metadata.capabilities.maxCaptureBytes,
    ...(packetInspection === undefined ? {} : { packetInspection }),
    readChunkBytes: READ_CHUNK_BYTES,
    wasm: {
      apiVersion: metadata.capabilities.apiVersion,
      maxImportStepBytes: metadata.capabilities.maxImportStepBytes,
      maxImportStepRecords: metadata.capabilities.maxImportStepRecords,
      maxPackets: metadata.capabilities.maxPackets,
    },
  };
  return capabilities;
}

function packetInspectionCapabilities(
  value: Awaited<ReturnType<BoundaryRuntime["metadata"]>>["capabilities"],
): PacketInspectionCapabilities | undefined {
  const {
    detailSchemaVersion,
    maxCorrelationMatches,
    maxFieldsPerPacket,
    maxLayersPerPacket,
    maxPacketDetailBytes,
    maxPacketEvidenceBytes,
  } = value;
  if (
    detailSchemaVersion === undefined ||
    maxCorrelationMatches === undefined ||
    maxFieldsPerPacket === undefined ||
    maxLayersPerPacket === undefined ||
    maxPacketDetailBytes === undefined ||
    maxPacketEvidenceBytes === undefined ||
    maxPacketEvidenceBytes < PACKET_EVIDENCE_PAGE_BYTES
  ) {
    return undefined;
  }
  return {
    detailSchemaVersion,
    evidencePageBytes: PACKET_EVIDENCE_PAGE_BYTES,
    maxCorrelationMatches,
    maxDetailBytes: maxPacketDetailBytes,
    maxFieldsPerPacket,
    maxLayersPerPacket,
  };
}

async function releaseDataset(): Promise<void> {
  const dataset = liveDataset;
  liveDataset = undefined;
  if (dataset === undefined) return;
  await runtime.dispose(dataset.handle);
}

async function readSlice(file: File, start: number, end: number): Promise<ArrayBuffer> {
  try {
    return await file.slice(start, end).arrayBuffer();
  } catch {
    throw new ImportFailure({ code: "read_failed" });
  }
}

async function classify(file: File, job: ActiveJob): Promise<DetectedCaptureFormat> {
  const header = new Uint8Array(await readSlice(file, 0, Math.min(file.size, 12)));
  failIfCancelled(job);
  const detection = detectCaptureFormat(header);
  if (detection.kind === "detected") return detection.value;
  if (detection.kind === "malformed") {
    throw new ImportFailure({ code: "malformed_capture", inputOffset: "8" });
  }
  if (detection.kind === "need_more_bytes") {
    throw new ImportFailure({ code: "truncated_capture" });
  }
  throw new ImportFailure({ code: "unsupported_format" });
}

async function readCapture(file: File, job: ActiveJob): Promise<Uint8Array> {
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(file.size);
  } catch {
    throw new ImportFailure({
      code: "resource_limit",
      limitBytes: (await ensureCapabilities()).maxCaptureBytes,
    });
  }
  post({
    ...envelope(),
    jobId: job.id,
    phase: "reading",
    progress: { bytesRead: 0, totalBytes: file.size },
    type: "progress",
  });
  job.lastReadProgress = { bytesRead: 0, totalBytes: file.size };
  for (let start = 0; start < file.size; start += READ_CHUNK_BYTES) {
    failIfCancelled(job);
    const end = Math.min(start + READ_CHUNK_BYTES, file.size);
    const chunk = new Uint8Array(await readSlice(file, start, end));
    failIfCancelled(job);
    if (chunk.byteLength !== end - start) {
      throw new ImportFailure({ code: "read_failed" });
    }
    bytes.set(chunk, start);
    const progress = { bytesRead: end, totalBytes: file.size };
    job.lastReadProgress = progress;
    post({
      ...envelope(),
      jobId: job.id,
      phase: "reading",
      progress,
      type: "progress",
    });
    await yieldMacrotask();
  }
  failIfCancelled(job);
  return bytes;
}

async function cancelAndDispose(job: ActiveJob): Promise<void> {
  if (job.importHandle === undefined) return;
  const handle = job.importHandle;
  const cancellation = await reclaimImportHandle(runtime, handle, true);
  if (cancellation?.progress !== undefined) {
    job.lastParseProgress = parseProgress(cancellation.progress);
  }
  job.importHandle = undefined;
}

async function failAndDispose(job: ActiveJob): Promise<void> {
  if (job.importHandle === undefined) return;
  const handle = job.importHandle;
  await reclaimImportHandle(runtime, handle, false);
  job.importHandle = undefined;
}

async function failClosedAfterCleanupLoss(job: ActiveJob): Promise<void> {
  shuttingDown = true;
  post({
    ...envelope(),
    error: { code: "worker_failed" },
    jobId: job.id,
    ...(job.lastParseProgress === undefined ? {} : { lastParseProgress: job.lastParseProgress }),
    ...(job.lastReadProgress === undefined ? {} : { lastReadProgress: job.lastReadProgress }),
    type: "import_error",
  });
  try {
    await runtime.shutdown();
  } catch {
    // Closing the worker is the final process-level reclamation boundary when
    // the Wasm runtime can no longer confirm individual-handle cleanup.
  } finally {
    liveDataset = undefined;
    globalThis.close();
  }
}

async function runImport(job: ActiveJob, file: File): Promise<void> {
  try {
    const currentCapabilities = await ensureCapabilities();
    failIfCancelled(job);
    if (!Number.isSafeInteger(file.size) || file.size < 0) {
      throw new ImportFailure({ code: "invalid_selection" });
    }
    if (file.size === 0) throw new ImportFailure({ code: "empty_capture" });
    if (file.size > currentCapabilities.maxCaptureBytes) {
      throw new ImportFailure({
        code: "resource_limit",
        limitBytes: currentCapabilities.maxCaptureBytes,
      });
    }

    await releaseDataset();
    failIfCancelled(job);
    post({ ...envelope(), jobId: job.id, phase: "validating", type: "progress" });
    const detected = await classify(file, job);
    const hint = filenameHint(file.name, detected.format);
    let bytes: Uint8Array | undefined = await readCapture(file, job);
    failIfCancelled(job);
    job.importHandle = await runtime.beginImport(bytes);
    // wasm-bindgen copies the complete input into Rust-owned Wasm memory. Drop
    // the worker-side assembly buffer immediately after that call returns.
    bytes = undefined;

    const maxRecords = Math.min(PARSE_STEP_RECORDS, currentCapabilities.wasm.maxImportStepRecords);
    const maxBytes = Math.min(PARSE_STEP_BYTES, currentCapabilities.wasm.maxImportStepBytes);

    for (;;) {
      failIfCancelled(job);
      const result = await runtime.stepImport(job.importHandle, maxRecords, maxBytes);
      const progress = parseProgress(result.progress);
      job.lastParseProgress = progress;
      if (result.state === "cancelled") throw new ImportCancelled();
      post({
        ...envelope(),
        jobId: job.id,
        phase: "parsing",
        progress,
        type: "progress",
      });
      if (result.state === "complete") {
        if (result.datasetHandle === undefined || result.warnings === undefined) {
          throw new BoundaryProtocolError(
            "internal_invariant",
            "completed import omitted its dataset or diagnostics",
          );
        }
        job.importHandle = undefined;
        let datasetGeneration: number;
        try {
          datasetGeneration = takeDatasetGeneration();
        } catch (error) {
          await runtime.dispose(result.datasetHandle);
          throw error;
        }
        liveDataset = {
          generation: datasetGeneration,
          handle: result.datasetHandle,
          packetCount: progress.packetsRetained,
        };
        const summary: ImportSummary = {
          byteLength: file.size,
          byteOrder: detected.byteOrder,
          ...(currentCapabilities.packetInspection === undefined ? {} : { datasetGeneration }),
          filename: file.name,
          filenameHintMismatch: hint.mismatchesDetectedFormat,
          format: detected.format,
          packetsRetained: progress.packetsRetained,
          records: progress.records,
          warningCount: result.warnings.length + (hint.mismatchesDetectedFormat ? 1 : 0),
        };
        post({ ...envelope(), jobId: job.id, summary, type: "complete" });
        return;
      }
      await yieldMacrotask();
    }
  } catch (error) {
    if (error instanceof ImportCancelled || job.cancelRequested) {
      try {
        await cancelAndDispose(job);
      } catch {
        await failClosedAfterCleanupLoss(job);
        return;
      }
      post({
        ...envelope(),
        ...(job.lastParseProgress === undefined
          ? {}
          : { lastParseProgress: job.lastParseProgress }),
        ...(job.lastReadProgress === undefined ? {} : { lastReadProgress: job.lastReadProgress }),
        jobId: job.id,
        type: "cancelled",
      });
      return;
    }
    try {
      await failAndDispose(job);
    } catch {
      await failClosedAfterCleanupLoss(job);
      return;
    }
    const failure: {
      boundaryCode?: BoundaryErrorCode;
      detail: ImportError;
      progress?: ParseProgress;
    } =
      error instanceof ImportFailure
        ? { boundaryCode: error.boundaryCode, detail: error.detail }
        : boundaryFailure(error);
    if (failure.progress !== undefined) job.lastParseProgress = failure.progress;
    post({
      ...envelope(),
      ...(failure.boundaryCode === undefined ? {} : { boundaryCode: failure.boundaryCode }),
      error: failure.detail,
      jobId: job.id,
      ...(job.lastParseProgress === undefined ? {} : { lastParseProgress: job.lastParseProgress }),
      ...(job.lastReadProgress === undefined ? {} : { lastReadProgress: job.lastReadProgress }),
      type: "import_error",
    });
  } finally {
    if (activeJob === job) activeJob = undefined;
  }
}

function commandError(requestId: number, error: ImportError): void {
  post({ ...envelope(), error, requestId, type: "command_error" });
}

interface PacketQueryContext {
  readonly dataset: LiveDataset;
  readonly inspection: PacketInspectionCapabilities;
}

interface PacketQueryIdentity {
  readonly datasetGeneration: number;
  readonly packetId: number;
  readonly requestId: number;
}

function postPacketQueryError(identity: PacketQueryIdentity, error: PacketQueryError): void {
  post({ ...envelope(), ...identity, error, type: "packet_query_error" });
}

function packetQueryContext(identity: PacketQueryIdentity): PacketQueryContext {
  const inspection = capabilities?.packetInspection;
  if (inspection === undefined) {
    throw new PacketQueryFailure({ code: "unsupported_version" });
  }
  if (activeJob !== undefined || shuttingDown || liveDataset === undefined) {
    throw new PacketQueryFailure({ code: "dataset_unavailable" });
  }
  if (liveDataset.generation !== identity.datasetGeneration) {
    throw new PacketQueryFailure({ code: "stale_dataset" });
  }
  if (identity.packetId >= liveDataset.packetCount) {
    throw new PacketQueryFailure({ code: "invalid_packet" });
  }
  return { dataset: liveDataset, inspection };
}

function packetQueryError(error: unknown): PacketQueryError {
  if (error instanceof PacketQueryFailure) return error.detail;
  const failure = normalizeBoundaryFailure(error);
  switch (failure.code) {
    case "cancelled":
      return { code: "cancelled" };
    case "invalid_argument":
      return { code: "invalid_range" };
    case "resource_limit":
      return { code: "resource_limit" };
    case "unsupported_version":
      return { code: "unsupported_version" };
    default:
      return { code: "worker_failed" };
  }
}

function queryStillCurrent(context: PacketQueryContext): boolean {
  return !shuttingDown && liveDataset === context.dataset && activeJob === undefined;
}

function postTransferred(
  event: Extract<
    CaptureWorkerEvent,
    { type: "packet_detail" | "packet_evidence_page" | "packet_selection_resolved" }
  >,
  value: Uint8Array | Uint32Array,
): void {
  globalThis.postMessage(event, { transfer: [value.buffer] });
}

function startPacketQuery(identity: PacketQueryIdentity, operation: () => Promise<void>): void {
  if (
    activePacketQueries.size >= MAX_ACTIVE_PACKET_QUERIES ||
    activePacketQueries.has(identity.requestId)
  ) {
    postPacketQueryError(identity, { code: "resource_limit" });
    return;
  }
  const work = operation().finally(() => {
    activePacketQueries.delete(identity.requestId);
  });
  activePacketQueries.set(identity.requestId, work);
}

async function readPacketDetail(
  identity: PacketQueryIdentity,
  detailSchemaVersion: number,
): Promise<void> {
  let context: PacketQueryContext | undefined;
  try {
    context = packetQueryContext(identity);
    if (detailSchemaVersion !== context.inspection.detailSchemaVersion) {
      throw new PacketQueryFailure({ code: "unsupported_version" });
    }
    const bytes = await runtime.readPacketDetail(
      context.dataset.handle,
      identity.packetId,
      detailSchemaVersion,
      context.inspection.maxDetailBytes,
    );
    if (!queryStillCurrent(context)) return;
    postTransferred({ ...envelope(), ...identity, bytes, type: "packet_detail" }, bytes);
  } catch (error) {
    if (context !== undefined && !queryStillCurrent(context)) return;
    postPacketQueryError(identity, packetQueryError(error));
  }
}

async function readPacketEvidencePage(
  identity: PacketQueryIdentity,
  pageStart: number,
): Promise<void> {
  let context: PacketQueryContext | undefined;
  try {
    context = packetQueryContext(identity);
    if (
      pageStart % context.inspection.evidencePageBytes !== 0 ||
      context.inspection.evidencePageBytes !== PACKET_EVIDENCE_PAGE_BYTES
    ) {
      throw new PacketQueryFailure({ code: "invalid_range" });
    }
    const bytes = await runtime.readPacketEvidence(
      context.dataset.handle,
      identity.packetId,
      pageStart,
      context.inspection.evidencePageBytes,
    );
    if (!queryStillCurrent(context)) return;
    postTransferred(
      { ...envelope(), ...identity, bytes, pageStart, type: "packet_evidence_page" },
      bytes,
    );
  } catch (error) {
    if (context !== undefined && !queryStillCurrent(context)) return;
    postPacketQueryError(identity, packetQueryError(error));
  }
}

async function resolvePacketSelection(
  identity: PacketQueryIdentity,
  selectionStart: number,
  selectionLength: number,
): Promise<void> {
  let context: PacketQueryContext | undefined;
  try {
    context = packetQueryContext(identity);
    const selectionEnd = selectionStart + selectionLength;
    if (!Number.isSafeInteger(selectionEnd) || selectionEnd > 0xffff_ffff) {
      throw new PacketQueryFailure({ code: "invalid_range" });
    }
    const fieldIds = await runtime.correlatePacketRange(
      context.dataset.handle,
      identity.packetId,
      selectionStart,
      selectionLength,
    );
    if (!queryStillCurrent(context)) return;
    postTransferred(
      {
        ...envelope(),
        ...identity,
        fieldIds,
        primaryFieldId: fieldIds[0] ?? null,
        selectionLength,
        selectionStart,
        type: "packet_selection_resolved",
      },
      fieldIds,
    );
  } catch (error) {
    if (context !== undefined && !queryStillCurrent(context)) return;
    postPacketQueryError(identity, packetQueryError(error));
  }
}

async function handleCommand(raw: unknown): Promise<void> {
  const candidate = asRecord(raw);
  const type = candidate?.type;
  const protocolVersion = candidate?.protocolVersion;
  const requestId = exactPositiveId(candidate?.requestId);
  const jobId = exactPositiveId(candidate?.jobId);
  const datasetGeneration = exactPositiveId(candidate?.datasetGeneration);
  const packetId = exactU32(candidate?.packetId);

  if (protocolVersion !== CAPTURE_INGESTION_PROTOCOL_VERSION) {
    if (
      requestId !== undefined &&
      datasetGeneration !== undefined &&
      packetId !== undefined &&
      (type === "read_packet_detail" ||
        type === "read_packet_evidence_page" ||
        type === "resolve_packet_selection")
    ) {
      postPacketQueryError(
        { datasetGeneration, packetId, requestId },
        { code: "unsupported_version" },
      );
    } else if (jobId !== undefined) {
      post({
        ...envelope(),
        error: { code: "unsupported_version" },
        jobId,
        type: "import_error",
      });
    } else if (requestId !== undefined) commandError(requestId, { code: "unsupported_version" });
    return;
  }

  if (type === "cancel_import" && jobId !== undefined) {
    if (activeJob?.id === jobId) {
      activeJob.cancelRequested = true;
      if (!activeJob.cancellingReported) {
        activeJob.cancellingReported = true;
        post({ ...envelope(), jobId, phase: "cancelling", type: "progress" });
      }
    }
    return;
  }

  if (type === "start_import" && jobId !== undefined) {
    if (!(candidate?.file instanceof File) || activeJob !== undefined || shuttingDown) {
      post({
        ...envelope(),
        error: { code: "invalid_selection" },
        jobId,
        type: "import_error",
      });
      return;
    }
    const job: ActiveJob = {
      cancelRequested: false,
      cancellingReported: false,
      id: jobId,
    };
    activeJob = job;
    activeWork = runImport(job, candidate.file).finally(() => {
      if (activeWork !== undefined && activeJob === undefined) activeWork = undefined;
    });
    return;
  }

  if (
    requestId !== undefined &&
    datasetGeneration !== undefined &&
    packetId !== undefined &&
    (type === "read_packet_detail" ||
      type === "read_packet_evidence_page" ||
      type === "resolve_packet_selection")
  ) {
    const identity = { datasetGeneration, packetId, requestId };
    if (type === "read_packet_detail") {
      const detailSchemaVersion = exactPositiveId(candidate?.detailSchemaVersion);
      if (detailSchemaVersion === undefined) {
        postPacketQueryError(identity, { code: "unsupported_version" });
      } else {
        startPacketQuery(identity, () => readPacketDetail(identity, detailSchemaVersion));
      }
      return;
    }
    if (type === "read_packet_evidence_page") {
      const pageStart = exactU32(candidate?.pageStart);
      if (pageStart === undefined) postPacketQueryError(identity, { code: "invalid_range" });
      else startPacketQuery(identity, () => readPacketEvidencePage(identity, pageStart));
      return;
    }
    const selectionStart = exactU32(candidate?.selectionStart);
    const selectionLength = exactU32(candidate?.selectionLength);
    if (selectionStart === undefined || selectionLength === undefined) {
      postPacketQueryError(identity, { code: "invalid_range" });
    } else {
      startPacketQuery(identity, () =>
        resolvePacketSelection(identity, selectionStart, selectionLength),
      );
    }
    return;
  }

  if (requestId === undefined) return;
  if (type === "initialize") {
    try {
      post({
        ...envelope(),
        capabilities: await ensureCapabilities(),
        requestId,
        type: "initialized",
      });
    } catch {
      commandError(requestId, { code: "internal_failure" });
    }
    return;
  }
  if (type === "resource_stats") {
    try {
      post({
        ...envelope(),
        requestId,
        stats: await runtime.resourceStats(),
        type: "resource_stats",
      });
    } catch {
      commandError(requestId, { code: "internal_failure" });
    }
    return;
  }
  if (type === "dispose_dataset") {
    if (activeJob !== undefined) {
      commandError(requestId, { code: "invalid_selection" });
      return;
    }
    try {
      await releaseDataset();
      post({ ...envelope(), requestId, type: "dataset_disposed" });
    } catch {
      commandError(requestId, { code: "internal_failure" });
    }
    return;
  }
  if (type === "shutdown") {
    shuttingDown = true;
    if (activeJob !== undefined) activeJob.cancelRequested = true;
    try {
      await activeWork;
      await Promise.all(activePacketQueries.values());
      await releaseDataset();
      await runtime.shutdown();
      post({ ...envelope(), requestId, type: "shutdown_complete" });
      globalThis.close();
    } catch {
      commandError(requestId, { code: "internal_failure" });
    }
    return;
  }
  commandError(requestId, { code: "invalid_selection" });
}

globalThis.addEventListener("message", (event: MessageEvent<CaptureWorkerCommand>) => {
  void handleCommand(event.data);
});
