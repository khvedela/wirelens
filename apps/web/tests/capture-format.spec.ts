import { expect, test } from "@playwright/test";

import { detectCaptureFormat, filenameHint } from "../src/ingestion/capture-format";

function bytes(hex: string): Uint8Array {
  return Uint8Array.from(hex.match(/.{2}/gu)?.map((byte) => Number.parseInt(byte, 16)) ?? []);
}

test.describe("capture header classification", () => {
  for (const [magic, byteOrder, timestampResolution] of [
    ["d4c3b2a1", "little-endian", "microseconds"],
    ["a1b2c3d4", "big-endian", "microseconds"],
    ["4d3cb2a1", "little-endian", "nanoseconds"],
    ["a1b23c4d", "big-endian", "nanoseconds"],
  ] as const) {
    test(`recognizes classic PCAP ${magic}`, () => {
      expect(detectCaptureFormat(bytes(magic))).toEqual({
        kind: "detected",
        value: { byteOrder, format: "pcap", timestampResolution },
      });
    });
  }

  for (const [byteOrderMagic, byteOrder] of [
    ["4d3c2b1a", "little-endian"],
    ["1a2b3c4d", "big-endian"],
  ] as const) {
    test(`recognizes PCAPNG ${byteOrder}`, () => {
      expect(detectCaptureFormat(bytes(`0a0d0d0a1c000000${byteOrderMagic}`))).toEqual({
        kind: "detected",
        value: { byteOrder, format: "pcapng", timestampResolution: "section-defined" },
      });
    });
  }

  test("distinguishes short and unsupported headers", () => {
    expect(detectCaptureFormat(bytes("d4c3b2"))).toEqual({
      kind: "need_more_bytes",
      minimumBytes: 4,
    });
    expect(detectCaptureFormat(bytes("0a0d0d0a1c000000"))).toEqual({
      kind: "need_more_bytes",
      minimumBytes: 12,
    });
    expect(detectCaptureFormat(bytes("0a0d0d0a1c00000000000000"))).toEqual({ kind: "malformed" });
    expect(detectCaptureFormat(bytes("00010203"))).toEqual({ kind: "unsupported" });
  });

  test("treats filenames only as advisory hints", () => {
    expect(filenameHint("capture.PCAP", "pcap")).toEqual({
      extension: "pcap",
      mismatchesDetectedFormat: false,
    });
    expect(filenameHint("capture.pcap", "pcapng").mismatchesDetectedFormat).toBe(true);
    expect(filenameHint("capture", "pcap").mismatchesDetectedFormat).toBe(true);
    expect(filenameHint("capture.bin", "pcapng").mismatchesDetectedFormat).toBe(true);
  });
});
