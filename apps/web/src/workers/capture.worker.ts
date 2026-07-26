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

const runtime = new BoundaryRuntime(globalThis.constructor.name);
let capabilities: IngestionCapabilities | undefined;
let datasetHandle: bigint | undefined;
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

class ImportFailure extends Error {
  constructor(
    readonly detail: ImportError,
    readonly boundaryCode?: BoundaryErrorCode,
  ) {
    super(detail.code);
  }
}

class ImportCancelled extends Error {}

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
  capabilities = {
    maxCaptureBytes: metadata.capabilities.maxCaptureBytes,
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

async function releaseDataset(): Promise<void> {
  if (datasetHandle === undefined) return;
  const handle = datasetHandle;
  await runtime.dispose(handle);
  if (datasetHandle === handle) datasetHandle = undefined;
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
    datasetHandle = undefined;
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
        datasetHandle = result.datasetHandle;
        const summary: ImportSummary = {
          byteLength: file.size,
          byteOrder: detected.byteOrder,
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

async function handleCommand(raw: unknown): Promise<void> {
  const candidate = asRecord(raw);
  const type = candidate?.type;
  const protocolVersion = candidate?.protocolVersion;
  const requestId = exactPositiveId(candidate?.requestId);
  const jobId = exactPositiveId(candidate?.jobId);

  if (protocolVersion !== CAPTURE_INGESTION_PROTOCOL_VERSION) {
    if (jobId !== undefined) {
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
