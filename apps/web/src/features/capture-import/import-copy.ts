import type {
  CaptureFormat,
  CaptureImportError,
  CaptureImportModel,
  CaptureImportPhase,
} from "./import-state";

export interface ImportErrorCopy {
  readonly body: string;
  readonly title: string;
}

// biome-ignore lint/suspicious/noControlCharactersInRegex: Security sanitization intentionally matches control and bidi-override code points.
const CONTROL_OR_DIRECTIONAL_CHARACTER = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/gu;

export function safeFileName(fileName: string | undefined): string {
  if (fileName === undefined) return "Selected capture";
  const sanitized = fileName.replace(CONTROL_OR_DIRECTIONAL_CHARACTER, "�").trim();
  return sanitized.length === 0 ? "Unnamed capture" : sanitized;
}

export function formatCaptureFormat(format: CaptureFormat): string {
  return format === "pcapng" ? "PCAPNG" : "PCAP";
}

export function formatByteCount(bytes: bigint | number | undefined): string {
  if (bytes === undefined) return "Unknown size";
  const exactBytes = typeof bytes === "bigint" ? bytes : BigInt(Math.max(0, Math.trunc(bytes)));
  if (exactBytes < 0n) return "Unknown size";
  const units = ["bytes", "KiB", "MiB", "GiB"] as const;
  let unitIndex = 0;
  let divisor = 1n;
  while (unitIndex < units.length - 1 && exactBytes >= divisor * 1024n) {
    divisor *= 1024n;
    unitIndex += 1;
  }

  if (unitIndex === 0) {
    return `${new Intl.NumberFormat().format(exactBytes)} ${exactBytes === 1n ? "byte" : "bytes"}`;
  }

  const tenths = (exactBytes * 10n + divisor / 2n) / divisor;
  const value = Number(tenths) / 10;
  return `${new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 }).format(value)} ${units[unitIndex]}`;
}

export function formatCount(value: bigint | number | string): string {
  if (typeof value !== "string") return new Intl.NumberFormat().format(value);
  return /^\d+$/u.test(value) ? new Intl.NumberFormat().format(BigInt(value)) : "unknown";
}

export function progressPercent(completedBytes: number, totalBytes: number): number {
  if (!Number.isFinite(totalBytes) || totalBytes <= 0) return 0;
  const bounded = Math.min(Math.max(0, completedBytes), totalBytes);
  return Math.floor((bounded / totalBytes) * 1_000) / 10;
}

export function phaseTitle(phase: CaptureImportPhase): string {
  switch (phase) {
    case "booting":
      return "Starting local analyzer";
    case "idle":
      return "Choose a capture";
    case "validating":
      return "Checking capture format";
    case "reading":
      return "Reading capture locally";
    case "parsing":
      return "Analyzing capture";
    case "cancelling":
      return "Cancelling import";
    case "cancelled":
      return "Import cancelled";
    case "error":
      return "Capture could not be opened";
    case "complete":
      return "Capture ready";
  }
}

export function phaseDescription(model: CaptureImportModel): string {
  switch (model.phase) {
    case "booting":
      return "Preparing the private browser worker used for local analysis.";
    case "idle":
      return "PCAP and PCAPNG captures are supported.";
    case "validating":
      return `Checking ${safeFileName(model.filename)} without uploading it.`;
    case "reading":
      return "Reading the selected file inside a background worker.";
    case "parsing":
      return "Building a local capture index in a background worker.";
    case "cancelling":
      return "Releasing temporary capture data and parser resources.";
    case "cancelled":
      return "The selected capture was released. Nothing was saved or uploaded.";
    case "error":
      return "No capture dataset was retained.";
    case "complete":
      return model.summary === undefined
        ? "The capture was indexed locally."
        : `${formatCount(model.summary.packetsRetained)} ${model.summary.packetsRetained === 1 ? "packet was" : "packets were"} indexed locally.`;
  }
}

export function errorCopy(error: CaptureImportError | undefined): ImportErrorCopy {
  if (error === undefined) {
    return {
      body: "The local analyzer stopped unexpectedly. Your capture was not uploaded. Try again.",
      title: "The local analyzer stopped",
    };
  }

  switch (error.code) {
    case "invalid_selection":
      return {
        body: "Choose one local PCAP or PCAPNG capture and try again.",
        title: "That file selection is not valid",
      };
    case "empty_capture":
      return {
        body: "Choose a PCAP or PCAPNG capture that contains data.",
        title: "This file is empty",
      };
    case "unsupported_format":
      return {
        body: "This file does not have a valid PCAP or PCAPNG header. Renaming a file does not change its format.",
        title: "Unsupported capture format",
      };
    case "truncated_capture":
      return {
        body:
          error.inputOffset === undefined
            ? "This capture ends unexpectedly. It may be incomplete or damaged."
            : `This capture ends unexpectedly near byte ${formatCount(error.inputOffset)}. It may be incomplete or damaged.`,
        title: "Capture is incomplete",
      };
    case "malformed_capture":
      return {
        body:
          error.inputOffset === undefined
            ? "This capture has invalid structure and could not be opened."
            : `This capture has invalid structure near byte ${formatCount(error.inputOffset)} and could not be opened.`,
        title: "Capture is malformed",
      };
    case "resource_limit":
      return {
        body:
          error.limitBytes === undefined
            ? "This capture exceeds a local analysis resource limit."
            : `This capture exceeds WireLens's ${formatByteCount(error.limitBytes)} local import limit.`,
        title: "Capture is too large",
      };
    case "read_failed":
      return {
        body: "The file may have moved, or browser access may have changed. Choose the file again.",
        title: "WireLens could not read this file",
      };
    case "unsupported_version":
      return {
        body: "Reload the app. If the problem continues, report an incompatibility.",
        title: "The local analyzer is incompatible with this build",
      };
    case "worker_failed":
      return {
        body: "Reload the app and try again. Your capture was not uploaded.",
        title: "The local analyzer is unavailable",
      };
    case "internal_failure":
      return {
        body: "The local analyzer stopped unexpectedly. Your capture was not uploaded. Try again.",
        title: "The local analyzer stopped",
      };
  }
}
