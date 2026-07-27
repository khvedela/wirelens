import type {
  BoundaryFailure,
  BoundaryOperation,
  BoundaryRequest,
  BoundaryResponse,
  CancellationResult,
  Capabilities,
  DisposalResult,
  ImportStepResult,
  Metadata,
  ResourceStats,
} from "./worker-contract";
import { HARNESS_API_VERSION } from "./worker-contract";
import { validatePacketBatchEnvelope } from "./packet-batch";

type Command<T> = T extends unknown ? Omit<T, "requestId"> : never;
export type BoundaryCommand = Command<BoundaryRequest>;

interface PendingRequest {
  operation: BoundaryOperation;
  reject(error: Error): void;
  resolve(value: unknown): void;
}

interface PendingAudit {
  operation: BinaryOperation;
  reject(error: Error): void;
  resolve(detached: boolean): void;
}

type BinaryOperation = Extract<
  BoundaryOperation,
  | "correlate_packet_range"
  | "read_evidence"
  | "read_packet_batch"
  | "read_packet_detail"
  | "read_packet_evidence"
>;
type BinaryValue = Uint32Array | Uint8Array;

export class BoundaryClientError extends Error {
  readonly code: BoundaryFailure["code"];

  constructor(readonly failure: BoundaryFailure) {
    super(failure.message);
    this.code = failure.code;
  }
}

export class BoundaryClient {
  readonly worker: Worker;
  #nextRequestId = 1;
  readonly #pending = new Map<number, PendingRequest>();
  readonly #pendingAudits = new Map<number, PendingAudit>();
  #binaryRequestInFlight = false;

  constructor() {
    this.worker = new Worker(new URL("./workers/boundary.worker.ts", import.meta.url), {
      name: "wirelens-wasm-boundary-harness",
      type: "module",
    });
    this.worker.addEventListener("message", (event: MessageEvent<unknown>) => {
      const response = boundaryResponse(event.data);
      if (response === undefined) {
        this.#rejectAll(
          new BoundaryClientError({
            code: "internal_invariant",
            message: "worker returned an invalid response envelope",
          }),
        );
        return;
      }
      if (response.kind === "transfer_audit") {
        const audit = this.#pendingAudits.get(response.requestId);
        if (audit !== undefined) {
          this.#pendingAudits.delete(response.requestId);
          const mismatch = responseMismatch(response, audit.operation);
          if (mismatch === undefined) audit.resolve(response.detached);
          else audit.reject(mismatch);
        }
        return;
      }

      const pending = this.#pending.get(response.requestId);
      if (pending === undefined) return;
      this.#pending.delete(response.requestId);
      const mismatch = responseMismatch(response, pending.operation);
      if (mismatch !== undefined) {
        pending.reject(mismatch);
        this.#rejectAudit(response.requestId, mismatch);
        return;
      }
      if (response.kind === "error") {
        const error = new BoundaryClientError(response.error);
        pending.reject(error);
        this.#rejectAudit(response.requestId, error);
      } else {
        pending.resolve(response.value);
      }
    });
    this.worker.addEventListener("error", (event) => {
      this.#rejectAll(new Error(event.message || "boundary worker failed"));
    });
  }

  metadata(apiVersion = HARNESS_API_VERSION): Promise<Metadata> {
    return this.#send<Metadata>({ apiVersion, operation: "metadata" });
  }

  async beginImport(
    bytes: Uint8Array,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<{ handle: bigint; inputDetached: boolean }> {
    if (
      !(bytes.buffer instanceof ArrayBuffer) ||
      bytes.byteOffset !== 0 ||
      bytes.byteLength !== bytes.buffer.byteLength
    ) {
      throw new BoundaryClientError({
        code: "invalid_argument",
        message: "capture bytes must span one exact transferable ArrayBuffer",
      });
    }
    const handlePromise = this.#send<bigint>(
      { apiVersion, bytes, operation: "begin_import" },
      [bytes.buffer],
    );
    const inputDetached = bytes.byteLength === 0;
    return { handle: await handlePromise, inputDetached };
  }

  stepImport(
    handle: bigint,
    maxRecords: number,
    maxBytes: number,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<ImportStepResult> {
    canonicalHandle(handle);
    return this.#send({ apiVersion, handle, maxBytes, maxRecords, operation: "step_import" });
  }

  cancelImport(handle: bigint, apiVersion = HARNESS_API_VERSION): Promise<CancellationResult> {
    canonicalHandle(handle);
    return this.#send<CancellationResult>({ apiVersion, handle, operation: "cancel_import" });
  }

  dispose(handle: bigint, apiVersion = HARNESS_API_VERSION): Promise<DisposalResult> {
    canonicalHandle(handle);
    return this.#send<DisposalResult>({ apiVersion, handle, operation: "dispose" });
  }

  openPacketCursor(
    datasetHandle: bigint,
    startRow = 0,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<bigint> {
    canonicalHandle(datasetHandle);
    return this.#send({ apiVersion, datasetHandle, operation: "open_packet_cursor", startRow });
  }

  async readPacketBatch(
    cursorHandle: bigint,
    batchSchemaVersion: number,
    maxRows: number,
    maxBytes: number,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<{ bytes: Uint8Array; workerSourceDetached: boolean }> {
    canonicalHandle(cursorHandle);
    return this.#readBinary(
      {
        apiVersion,
        batchSchemaVersion,
        cursorHandle,
        maxBytes,
        maxRows,
        operation: "read_packet_batch",
      },
      "read_packet_batch",
    );
  }

  async readEvidence(
    datasetHandle: bigint,
    startHi: number,
    startLo: number,
    length: number,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<{ bytes: Uint8Array; workerSourceDetached: boolean }> {
    canonicalHandle(datasetHandle);
    return this.#readBinary(
      {
        apiVersion,
        datasetHandle,
        length,
        operation: "read_evidence",
        startHi,
        startLo,
      },
      "read_evidence",
    );
  }

  async readPacketDetail(
    datasetHandle: bigint,
    packetId: number,
    detailSchemaVersion: number,
    maxBytes: number,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<{ bytes: Uint8Array; workerSourceDetached: boolean }> {
    canonicalHandle(datasetHandle);
    return this.#readBinary<Uint8Array>(
      {
        apiVersion,
        datasetHandle,
        detailSchemaVersion,
        maxBytes,
        operation: "read_packet_detail",
        packetId,
      },
      "read_packet_detail",
    );
  }

  async readPacketEvidence(
    datasetHandle: bigint,
    packetId: number,
    relativeStart: number,
    maxBytes: number,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<{ bytes: Uint8Array; workerSourceDetached: boolean }> {
    canonicalHandle(datasetHandle);
    return this.#readBinary<Uint8Array>(
      {
        apiVersion,
        datasetHandle,
        maxBytes,
        operation: "read_packet_evidence",
        packetId,
        relativeStart,
      },
      "read_packet_evidence",
    );
  }

  async correlatePacketRange(
    datasetHandle: bigint,
    packetId: number,
    relativeStart: number,
    length: number,
    apiVersion = HARNESS_API_VERSION,
  ): Promise<{ fieldIds: Uint32Array; workerSourceDetached: boolean }> {
    canonicalHandle(datasetHandle);
    const result = await this.#readBinary<Uint32Array>(
      {
        apiVersion,
        datasetHandle,
        length,
        operation: "correlate_packet_range",
        packetId,
        relativeStart,
      },
      "correlate_packet_range",
    );
    return { fieldIds: result.bytes, workerSourceDetached: result.workerSourceDetached };
  }

  resourceStats(apiVersion = HARNESS_API_VERSION): Promise<ResourceStats> {
    return this.#send<ResourceStats>({ apiVersion, operation: "resource_stats" });
  }

  wasmMemoryBytes(apiVersion = HARNESS_API_VERSION): Promise<bigint> {
    return this.#send<bigint>({ apiVersion, operation: "wasm_memory_bytes" });
  }

  async shutdown(apiVersion = HARNESS_API_VERSION): Promise<void> {
    await this.#send({ apiVersion, operation: "shutdown" });
    this.worker.terminate();
  }

  async capabilities(apiVersion = HARNESS_API_VERSION): Promise<Required<Capabilities>> {
    // This harness is coupled to the current production Wasm and asserts every
    // additive field. Product API-v1 consumers still tolerate older v1 modules
    // that do not advertise the optional decoded-arena capabilities.
    return (await this.metadata(apiVersion)).capabilities as Required<Capabilities>;
  }

  #send<T>(
    command: BoundaryCommand,
    transfer: Transferable[] = [],
    fixedRequestId?: number,
  ): Promise<T> {
    const requestId = fixedRequestId ?? this.#nextRequestId;
    this.#nextRequestId = Math.max(this.#nextRequestId, requestId + 1);
    const request = { ...command, requestId } as BoundaryRequest;
    const result = new Promise<T>((resolve, reject) => {
      this.#pending.set(requestId, {
        operation: command.operation,
        reject,
        resolve: (value) => resolve(value as T),
      });
    });
    this.worker.postMessage(request, transfer);
    return result;
  }

  async #readBinary<T extends BinaryValue>(
    command: Extract<BoundaryCommand, { operation: BinaryOperation }>,
    operation: BinaryOperation,
  ): Promise<{ bytes: T; workerSourceDetached: boolean }> {
    if (this.#binaryRequestInFlight) {
      throw new BoundaryClientError({
        code: "resource_limit",
        message: "a binary boundary request is already in flight",
      });
    }
    this.#binaryRequestInFlight = true;
    const requestId = this.#nextRequestId;
    const audit = new Promise<boolean>((resolve, reject) => {
      this.#pendingAudits.set(requestId, { operation, reject, resolve });
    });
    let receivedTransfer = false;
    let packetBatchResolutionAttempted = false;
    try {
      const bytes = this.#send<BinaryValue>(command, [], requestId).then((value) => {
        receivedTransfer = true;
        if (
          (!(value instanceof Uint8Array) && !(value instanceof Uint32Array)) ||
          !(value.buffer instanceof ArrayBuffer)
        ) {
          throw new BoundaryClientError({
            code: "internal_invariant",
            message: "worker returned a non-transferable binary value",
          });
        }
        return value as T;
      });
      const [transferredBytes, workerSourceDetached] = await Promise.all([bytes, audit]);
      if (!workerSourceDetached) {
        throw new BoundaryClientError({
          code: "internal_invariant",
          message: "worker retained the source of a transferred binary response",
        });
      }
      if (operation === "read_packet_batch") {
        if (!(transferredBytes instanceof Uint8Array)) {
          throw new BoundaryClientError({
            code: "internal_invariant",
            message: "packet batch transfer is not a byte array",
          });
        }
        // The worker performs the bounded row-level semantic scan before
        // transfer. Keep the main-thread check constant-work by validating
        // only the fixed header and twelve descriptors before commit.
        validatePacketBatchEnvelope(transferredBytes);
        packetBatchResolutionAttempted = true;
        await this.#resolvePacketBatch(requestId, "commit_packet_batch");
      }
      return { bytes: transferredBytes, workerSourceDetached };
    } catch (error) {
      if (operation === "read_packet_batch" && !packetBatchResolutionAttempted) {
        try {
          await this.#resolvePacketBatch(requestId, "discard_packet_batch");
        } catch {
          // A discard error makes the worker dispose the cursor and delete its
          // pending metadata before acknowledgement.
        }
      }
      throw error;
    } finally {
      if (receivedTransfer) this.#acknowledgeTransfer(requestId);
      this.#binaryRequestInFlight = false;
    }
  }

  #resolvePacketBatch(
    transferRequestId: number,
    operation: "commit_packet_batch" | "discard_packet_batch",
  ): Promise<unknown> {
    return this.#send({
      apiVersion: HARNESS_API_VERSION,
      operation,
      transferRequestId,
    });
  }

  #acknowledgeTransfer(transferRequestId: number): void {
    const requestId = this.#nextRequestId;
    this.#nextRequestId += 1;
    const request: BoundaryRequest = {
      apiVersion: HARNESS_API_VERSION,
      operation: "ack_transfer",
      requestId,
      transferRequestId,
    };
    this.worker.postMessage(request);
  }

  #rejectAudit(requestId: number, error: Error): void {
    const audit = this.#pendingAudits.get(requestId);
    if (audit !== undefined) {
      this.#pendingAudits.delete(requestId);
      audit.reject(error);
    }
  }

  #rejectAll(error: Error): void {
    for (const pending of this.#pending.values()) pending.reject(error);
    for (const pending of this.#pendingAudits.values()) pending.reject(error);
    this.#pending.clear();
    this.#pendingAudits.clear();
  }
}

const MAX_U64 = (1n << 64n) - 1n;
const ERROR_CODES = new Set<BoundaryFailure["code"]>([
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

function boundaryResponse(value: unknown): BoundaryResponse | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const candidate = value as Record<string, unknown>;
  if (
    candidate.apiVersion !== HARNESS_API_VERSION ||
    typeof candidate.operation !== "string" ||
    typeof candidate.requestId !== "number" ||
    !Number.isSafeInteger(candidate.requestId) ||
    candidate.requestId <= 0 ||
    (candidate.kind !== "success" &&
      candidate.kind !== "error" &&
      candidate.kind !== "transfer_audit")
  ) {
    return undefined;
  }
  if (
    (candidate.kind === "success" && candidate.status !== "ok") ||
    (candidate.kind === "error" &&
      (candidate.status !== "error" || !isBoundaryFailure(candidate.error))) ||
    (candidate.kind === "transfer_audit" &&
      (candidate.status !== "transferred" || typeof candidate.detached !== "boolean"))
  ) {
    return undefined;
  }
  return value as BoundaryResponse;
}

function isBoundaryFailure(value: unknown): value is BoundaryFailure {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  if (
    typeof candidate.code !== "string" ||
    !ERROR_CODES.has(candidate.code as BoundaryFailure["code"]) ||
    typeof candidate.message !== "string"
  ) {
    return false;
  }
  const optionalWords = [
    "inputOffsetHi",
    "inputOffsetLo",
    "resourceLimitHi",
    "resourceLimitLo",
  ];
  if (
    optionalWords.some((key) => candidate[key] !== undefined && !isWord(candidate[key])) ||
    (candidate.progress !== undefined && !isProgress(candidate.progress))
  ) {
    return false;
  }
  return true;
}

function isWord(value: unknown): value is number {
  return (
    typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 0xffff_ffff
  );
}

function isProgress(value: unknown): boolean {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  const phases = new Set(["cancelled", "complete", "failed", "parsing", "validating"]);
  return (
    typeof candidate.phase === "string" &&
    phases.has(candidate.phase) &&
    [
      "bytesConsumedHi",
      "bytesConsumedLo",
      "diagnostics",
      "packetsRetainedHi",
      "packetsRetainedLo",
      "recordsHi",
      "recordsLo",
      "totalBytesHi",
      "totalBytesLo",
    ].every((key) => isWord(candidate[key]))
  );
}

function canonicalHandle(value: unknown): asserts value is bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64) {
    throw new BoundaryClientError({
      code: "invalid_handle",
      message: "boundary handle is not a canonical u64 BigInt",
    });
  }
}

function responseMismatch(
  response: BoundaryResponse,
  expectedOperation: BoundaryOperation,
): Error | undefined {
  if (
    response.apiVersion !== HARNESS_API_VERSION ||
    response.operation !== expectedOperation ||
    (response.kind !== "success" &&
      response.kind !== "error" &&
      response.kind !== "transfer_audit") ||
    (response.kind === "success"
      ? response.status !== "ok"
      : response.kind === "error"
        ? response.status !== "error"
        : response.status !== "transferred")
  ) {
    return new BoundaryClientError({
      code: "internal_invariant",
      message: "worker response envelope does not match its request",
    });
  }
  return undefined;
}
