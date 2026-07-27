import type { BoundaryErrorCode, Capabilities, ResourceStats } from "../boundary/worker-contract";
import type { CaptureByteOrder, CaptureFormat } from "./capture-format";

export const CAPTURE_INGESTION_PROTOCOL_VERSION = 1;
export const PACKET_EVIDENCE_PAGE_BYTES = 4 * 1024;

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
  packetInspection?: PacketInspectionCapabilities;
  readChunkBytes: number;
  wasm: Pick<
    Capabilities,
    "apiVersion" | "maxImportStepBytes" | "maxImportStepRecords" | "maxPackets"
  >;
}

export interface PacketInspectionCapabilities {
  detailSchemaVersion: number;
  evidencePageBytes: number;
  maxCorrelationMatches: number;
  maxDetailBytes: number;
  maxFieldsPerPacket: number;
  maxLayersPerPacket: number;
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
  datasetGeneration?: number;
  filename: string;
  filenameHintMismatch: boolean;
  format: CaptureFormat;
  packetsRetained: number;
  records: number;
  warningCount: number;
}

export type PacketQueryErrorCode =
  | "cancelled"
  | "dataset_unavailable"
  | "invalid_packet"
  | "invalid_range"
  | "resource_limit"
  | "stale_dataset"
  | "unsupported_version"
  | "worker_failed";

export interface PacketQueryError {
  code: PacketQueryErrorCode;
}

export interface PacketEvidencePage {
  bytes: Uint8Array;
  datasetGeneration: number;
  packetId: number;
  pageStart: number;
}

export interface PacketSelectionResolution {
  datasetGeneration: number;
  fieldIds: Uint32Array;
  packetId: number;
  primaryFieldId: number | null;
  selectionLength: number;
  selectionStart: number;
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
  | (ProtocolEnvelope & {
      datasetGeneration: number;
      detailSchemaVersion: number;
      packetId: number;
      requestId: number;
      type: "read_packet_detail";
    })
  | (ProtocolEnvelope & {
      datasetGeneration: number;
      packetId: number;
      pageStart: number;
      requestId: number;
      type: "read_packet_evidence_page";
    })
  | (ProtocolEnvelope & {
      datasetGeneration: number;
      packetId: number;
      requestId: number;
      selectionLength: number;
      selectionStart: number;
      type: "resolve_packet_selection";
    })
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
  | (ProtocolEnvelope & {
      bytes: Uint8Array;
      datasetGeneration: number;
      packetId: number;
      requestId: number;
      type: "packet_detail";
    })
  | (ProtocolEnvelope &
      PacketEvidencePage & {
        requestId: number;
        type: "packet_evidence_page";
      })
  | (ProtocolEnvelope &
      PacketSelectionResolution & {
        requestId: number;
        type: "packet_selection_resolved";
      })
  | (ProtocolEnvelope & {
      datasetGeneration: number;
      error: PacketQueryError;
      packetId: number;
      requestId: number;
      type: "packet_query_error";
    })
  | (ProtocolEnvelope & { requestId: number; type: "shutdown_complete" })
  | (ProtocolEnvelope & {
      error: ImportError;
      requestId: number;
      type: "command_error";
    });
