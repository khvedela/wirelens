import type { BoundaryErrorCode, Capabilities, ResourceStats } from "../boundary/worker-contract";
import type { CaptureByteOrder, CaptureFormat } from "./capture-format";

export const CAPTURE_INGESTION_PROTOCOL_VERSION = 1;

export type ImportErrorCode =
  | "empty_capture"
  | "internal_failure"
  | "invalid_selection"
  | "malformed_capture"
  | "read_failed"
  | "resource_limit"
  | "truncated_capture"
  | "unsupported_format"
  | "unsupported_version"
  | "worker_failed";

export interface ImportError {
  code: ImportErrorCode;
  inputOffset?: string;
  limitBytes?: number;
}

export interface IngestionCapabilities {
  maxCaptureBytes: number;
  readChunkBytes: number;
  wasm: Pick<
    Capabilities,
    "apiVersion" | "maxImportStepBytes" | "maxImportStepRecords" | "maxPackets"
  >;
}

export interface ReadProgress {
  bytesRead: number;
  totalBytes: number;
}

export interface ParseProgress {
  bytesConsumed: number;
  diagnostics: number;
  packetsRetained: number;
  phase: "cancelled" | "complete" | "failed" | "parsing" | "validating";
  records: number;
  totalBytes: number;
}

export interface ImportSummary {
  byteLength: number;
  byteOrder: CaptureByteOrder;
  filename: string;
  filenameHintMismatch: boolean;
  format: CaptureFormat;
  packetsRetained: number;
  records: number;
  warningCount: number;
}

export interface TerminalProgress {
  lastParseProgress?: ParseProgress;
  lastReadProgress?: ReadProgress;
}

interface ProtocolEnvelope {
  protocolVersion: number;
}

export type CaptureWorkerCommand =
  | (ProtocolEnvelope & { requestId: number; type: "initialize" })
  | (ProtocolEnvelope & { file: File; jobId: number; type: "start_import" })
  | (ProtocolEnvelope & { jobId: number; type: "cancel_import" })
  | (ProtocolEnvelope & { requestId: number; type: "dispose_dataset" })
  | (ProtocolEnvelope & { requestId: number; type: "resource_stats" })
  | (ProtocolEnvelope & { requestId: number; type: "shutdown" });

export type CaptureWorkerEvent =
  | (ProtocolEnvelope & {
      capabilities: IngestionCapabilities;
      requestId: number;
      type: "initialized";
    })
  | (ProtocolEnvelope & {
      jobId: number;
      phase: "validating";
      type: "progress";
    })
  | (ProtocolEnvelope & {
      jobId: number;
      phase: "reading";
      progress: ReadProgress;
      type: "progress";
    })
  | (ProtocolEnvelope & {
      jobId: number;
      phase: "parsing";
      progress: ParseProgress;
      type: "progress";
    })
  | (ProtocolEnvelope & {
      jobId: number;
      phase: "cancelling";
      type: "progress";
    })
  | (ProtocolEnvelope & { jobId: number; summary: ImportSummary; type: "complete" })
  | (ProtocolEnvelope & TerminalProgress & { jobId: number; type: "cancelled" })
  | (ProtocolEnvelope & {
      boundaryCode?: BoundaryErrorCode;
      error: ImportError;
      jobId: number;
      type: "import_error";
    } & TerminalProgress)
  | (ProtocolEnvelope & { requestId: number; type: "dataset_disposed" })
  | (ProtocolEnvelope & { requestId: number; stats: ResourceStats; type: "resource_stats" })
  | (ProtocolEnvelope & { requestId: number; type: "shutdown_complete" })
  | (ProtocolEnvelope & {
      error: ImportError;
      requestId: number;
      type: "command_error";
    });
