export type CaptureImportPhase =
  | "booting"
  | "idle"
  | "validating"
  | "reading"
  | "parsing"
  | "cancelling"
  | "cancelled"
  | "error"
  | "complete";

export type CaptureFormat = "pcap" | "pcapng";

export type CaptureImportErrorCode =
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

export interface CaptureByteProgress {
  readonly bytesRead: number;
  readonly totalBytes: number;
}

export interface CaptureParseProgress {
  readonly bytesConsumed: number;
  readonly packetsRetained: number;
  readonly records: number;
  readonly totalBytes: number;
}

export interface CaptureImportError {
  readonly code: CaptureImportErrorCode;
  readonly inputOffset?: string;
  readonly limitBytes?: number;
}

export interface CaptureImportSummary {
  readonly byteLength: number;
  readonly datasetGeneration?: number;
  readonly filename: string;
  readonly filenameHintMismatch: boolean;
  readonly format: CaptureFormat;
  readonly packetsRetained: number;
  readonly records: number;
  readonly warningCount: number;
}

/**
 * Presentation-only import state. The worker/controller owns all file reads,
 * validation, Wasm handles, and cleanup; this model contains display-safe
 * metadata only.
 */
export interface CaptureImportModel {
  readonly error?: CaptureImportError;
  readonly filename?: string;
  readonly fileSize?: number;
  readonly maxCaptureBytes?: number;
  readonly parseProgress?: CaptureParseProgress;
  readonly phase: CaptureImportPhase;
  readonly readProgress?: CaptureByteProgress;
  readonly summary?: CaptureImportSummary;
}

export interface CaptureSelectionRejection {
  readonly code: "multiple_files";
}

export interface CaptureImporterProps {
  readonly model: CaptureImportModel;
  readonly onCancel: () => void;
  readonly onFileSelected: (file: File) => void;
  readonly onReset: () => void;
  readonly onSelectionRejected?: (rejection: CaptureSelectionRejection) => void;
}
