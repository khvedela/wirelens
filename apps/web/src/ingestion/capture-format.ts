export type CaptureFormat = "pcap" | "pcapng";
export type CaptureByteOrder = "big-endian" | "little-endian";
export type CaptureTimestampResolution = "microseconds" | "nanoseconds" | "section-defined";

export interface DetectedCaptureFormat {
  byteOrder: CaptureByteOrder;
  format: CaptureFormat;
  timestampResolution: CaptureTimestampResolution;
}

export type HeaderDetection =
  | { kind: "detected"; value: DetectedCaptureFormat }
  | { kind: "malformed" }
  | { kind: "need_more_bytes"; minimumBytes: number }
  | { kind: "unsupported" };

const PCAP_MAGICS = new Map<string, DetectedCaptureFormat>([
  ["d4c3b2a1", { byteOrder: "little-endian", format: "pcap", timestampResolution: "microseconds" }],
  ["a1b2c3d4", { byteOrder: "big-endian", format: "pcap", timestampResolution: "microseconds" }],
  ["4d3cb2a1", { byteOrder: "little-endian", format: "pcap", timestampResolution: "nanoseconds" }],
  ["a1b23c4d", { byteOrder: "big-endian", format: "pcap", timestampResolution: "nanoseconds" }],
]);

function hex(bytes: Uint8Array, start: number, length: number): string {
  let result = "";
  for (let index = start; index < start + length; index += 1) {
    result += bytes[index]?.toString(16).padStart(2, "0") ?? "";
  }
  return result;
}

/**
 * Classifies only the capture container header. Rust remains authoritative for
 * the full hostile-input validation and all record/block parsing.
 */
export function detectCaptureFormat(header: Uint8Array): HeaderDetection {
  if (header.byteLength < 4) return { kind: "need_more_bytes", minimumBytes: 4 };

  const magic = hex(header, 0, 4);
  const pcap = PCAP_MAGICS.get(magic);
  if (pcap !== undefined) return { kind: "detected", value: pcap };
  if (magic !== "0a0d0d0a") return { kind: "unsupported" };
  if (header.byteLength < 12) return { kind: "need_more_bytes", minimumBytes: 12 };

  const byteOrderMagic = hex(header, 8, 4);
  if (byteOrderMagic === "4d3c2b1a") {
    return {
      kind: "detected",
      value: {
        byteOrder: "little-endian",
        format: "pcapng",
        timestampResolution: "section-defined",
      },
    };
  }
  if (byteOrderMagic === "1a2b3c4d") {
    return {
      kind: "detected",
      value: {
        byteOrder: "big-endian",
        format: "pcapng",
        timestampResolution: "section-defined",
      },
    };
  }
  return { kind: "malformed" };
}

export interface FilenameHint {
  extension: "pcap" | "pcapng" | "other" | "none";
  mismatchesDetectedFormat: boolean;
}

export function filenameHint(name: string, format: CaptureFormat): FilenameHint {
  const match = /\.([^.]+)$/u.exec(name);
  const rawExtension = match?.[1]?.toLocaleLowerCase("en-US");
  const extension =
    rawExtension === undefined
      ? "none"
      : rawExtension === "pcap" || rawExtension === "pcapng"
        ? rawExtension
        : "other";
  return {
    extension,
    mismatchesDetectedFormat: extension !== format,
  };
}
