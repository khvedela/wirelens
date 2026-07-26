export const BOUNDARY_API_VERSION = 1;
export const BOUNDARY_BATCH_SCHEMA_VERSION = 1;

/** Compatibility aliases retained for the issue #9 engineering harness. */
export const HARNESS_API_VERSION = BOUNDARY_API_VERSION;
export const HARNESS_BATCH_SCHEMA_VERSION = BOUNDARY_BATCH_SCHEMA_VERSION;
export const MAX_BATCH_BYTES = 8 * 1024 * 1024;
export const MAX_BATCH_ROWS = 65_536;

export type BoundaryErrorCode =
  | "cancelled"
  | "internal_invariant"
  | "invalid_argument"
  | "invalid_handle"
  | "invalid_state"
  | "malformed_capture"
  | "resource_limit"
  | "stale_handle"
  | "truncated_capture"
  | "unsupported_format"
  | "unsupported_version"
  | "wrong_handle_kind";

export interface BoundaryFailure {
  code: BoundaryErrorCode;
  inputOffsetHi?: number;
  inputOffsetLo?: number;
  message: string;
  progress?: ProgressSnapshot;
  resourceLimitHi?: number;
  resourceLimitLo?: number;
}

export interface BoundaryWarning {
  code: number;
  evidenceLength?: number;
  evidenceStartHi?: number;
  evidenceStartLo?: number;
  message: string;
  packetId?: number;
  recovery: "capture_rejected" | "continued" | "record_skipped";
  scope: "capture" | "packet";
  severity: "error" | "fatal" | "info" | "warning";
}

export interface Capabilities {
  apiVersion: number;
  batchSchemaVersion: number;
  maxBlockBytes: number;
  maxCaptureBytes: number;
  maxDatasetHandles: number;
  maxDecodedItemsPerBlock: number;
  maxDecodedItemsPerStep: number;
  maxDiagnostics: number;
  maxEvidenceBytes: number;
  maxImportHandles: number;
  maxImportStepBytes: number;
  maxImportStepRecords: number;
  maxInterfaces: number;
  maxInternedStringBytes: number;
  maxPackets: number;
  maxPacketBatchBytes: number;
  maxPacketBatchRows: number;
  maxPacketCursorHandles: number;
  maxSections: number;
  maxTotalCaptureBytes: number;
  maxTotalLogicalBytes: number;
  packetAdmissionBase: number;
  packetAdmissionBytesPerPacket: number;
  packetAdmissionRule: string;
}

export interface ProgressSnapshot {
  bytesConsumedHi: number;
  bytesConsumedLo: number;
  diagnostics: number;
  packetsRetainedHi: number;
  packetsRetainedLo: number;
  phase: "cancelled" | "complete" | "failed" | "parsing" | "validating";
  recordsHi: number;
  recordsLo: number;
  totalBytesHi: number;
  totalBytesLo: number;
}

export interface ImportStepResult {
  datasetHandle?: bigint;
  minimumBytesHi?: number;
  minimumBytesLo?: number;
  progress: ProgressSnapshot;
  state: "cancelled" | "complete" | "in_progress";
  warningCodes?: Uint16Array;
  warnings?: BoundaryWarning[];
}

export interface ResourceStats {
  currentOwnedCaptureBytesHi: number;
  currentOwnedCaptureBytesLo: number;
  cursors: number;
  datasets: number;
  imports: number;
  peakOwnedCaptureBytesHi: number;
  peakOwnedCaptureBytesLo: number;
  peakTransientImportInputBytesHi: number;
  peakTransientImportInputBytesLo: number;
  retainedBatchBytesHi: number;
  retainedBatchBytesLo: number;
  retainedCaptureBytesHi: number;
  retainedCaptureBytesLo: number;
  retainedIndexBytesHi: number;
  retainedIndexBytesLo: number;
  retainedLogicalBytesHi: number;
  retainedLogicalBytesLo: number;
  retainedPacketIndexBytesHi: number;
  retainedPacketIndexBytesLo: number;
  totalLogicalBytesUpperBoundHi: number;
  totalLogicalBytesUpperBoundLo: number;
  transientAuxiliaryBytesUpperBoundHi: number;
  transientAuxiliaryBytesUpperBoundLo: number;
  transientImportInputBytesHi: number;
  transientImportInputBytesLo: number;
  transientPacketIndexBytesUpperBoundHi: number;
  transientPacketIndexBytesUpperBoundLo: number;
  transientParserBufferBytesUpperBoundHi: number;
  transientParserBufferBytesUpperBoundLo: number;
}

export interface Metadata {
  apiVersion: number;
  batchSchemaVersion: number;
  capabilities: Capabilities;
  workerContext: string;
}

interface RequestBase {
  apiVersion: number;
  requestId: number;
}

export type BoundaryRequest =
  | (RequestBase & { operation: "metadata" })
  | (RequestBase & { bytes: Uint8Array; operation: "begin_import" })
  | (RequestBase & {
      handle: bigint;
      maxBytes: number;
      maxRecords: number;
      operation: "step_import";
    })
  | (RequestBase & { handle: bigint; operation: "cancel_import" })
  | (RequestBase & { handle: bigint; operation: "dispose" })
  | (RequestBase & {
      datasetHandle: bigint;
      operation: "open_packet_cursor";
      startRow: number;
    })
  | (RequestBase & {
      batchSchemaVersion: number;
      cursorHandle: bigint;
      maxBytes: number;
      maxRows: number;
      operation: "read_packet_batch";
    })
  | (RequestBase & {
      datasetHandle: bigint;
      length: number;
      operation: "read_evidence";
      startHi: number;
      startLo: number;
    })
  | (RequestBase & { operation: "resource_stats" })
  | (RequestBase & { operation: "wasm_memory_bytes" })
  | (RequestBase & {
      operation: "commit_packet_batch" | "discard_packet_batch";
      transferRequestId: number;
    })
  | (RequestBase & { operation: "ack_transfer"; transferRequestId: number })
  | (RequestBase & { operation: "shutdown" });

export type BoundaryOperation = BoundaryRequest["operation"];

interface ResponseBase {
  apiVersion: number;
  operation: string;
  requestId: number;
}

export interface BoundarySuccess extends ResponseBase {
  kind: "success";
  status: "ok";
  value: unknown;
}

export interface BoundaryErrorResponse extends ResponseBase {
  error: BoundaryFailure;
  kind: "error";
  status: "error";
}

export interface TransferAudit extends ResponseBase {
  detached: boolean;
  kind: "transfer_audit";
  status: "transferred";
}

export type BoundaryResponse = BoundaryErrorResponse | BoundarySuccess | TransferAudit;

export interface DisposalResult {
  dependentCursors?: number;
  status: "already_disposed" | "disposed";
}

export interface CancellationResult {
  progress?: ProgressSnapshot;
  status: "already_terminal" | "cancelled";
}
