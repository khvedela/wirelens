import { expect, test, type Page } from "@playwright/test";

import { validatePacketBatch, validatePacketBatchEnvelope } from "../web/packet-batch";
import {
  cancellationPhaseIsTerminal,
  exactU64IsPositive,
  importStateMatchesPhase,
  progressCountersAreOrdered,
} from "../web/progress-validation";
import type { ProgressSnapshot } from "../web/worker-contract";

interface RuntimeErrorAudit {
  consoleErrors: string[];
  pageErrors: string[];
}

const runtimeErrorAudits = new WeakMap<Page, RuntimeErrorAudit>();

test.beforeEach(async ({ page }) => {
  const audit: RuntimeErrorAudit = { consoleErrors: [], pageErrors: [] };
  runtimeErrorAudits.set(page, audit);
  page.on("console", (message) => {
    if (message.type() === "error") audit.consoleErrors.push(message.text());
  });
  page.on("pageerror", (error) => audit.pageErrors.push(error.message));
});

test.afterEach(async ({ page }) => {
  const audit = runtimeErrorAudits.get(page);
  expect(audit, "batch schema runtime audit was installed").toBeDefined();
  expect(audit?.pageErrors, "schema checks emitted no page errors").toEqual([]);
  expect(audit?.consoleErrors, "expected schema rejections stayed off console.error").toEqual([]);
});

const HEADER_BYTES = 64;
const DESCRIPTOR_BYTES = 24;
const COLUMN_SPECS = [
  [1, 2, 0, 4],
  [2, 2, 0, 4],
  [3, 2, 0, 4],
  [4, 2, 0, 4],
  [5, 2, 0, 4],
  [6, 2, 0, 4],
  [7, 3, 0, 8],
  [8, 4, 1, 8],
  [9, 3, 1, 8],
  [10, 1, 0, 1],
  [11, 1, 1, 1],
  [12, 1, 1, 1],
] as const;

function validEmptyBatch(): Uint8Array {
  const bytes = new Uint8Array(HEADER_BYTES + DESCRIPTOR_BYTES * COLUMN_SPECS.length);
  const view = new DataView(bytes.buffer);
  bytes.set([..."WLPKTB01"].map((character) => character.charCodeAt(0)));
  view.setUint16(8, 1, true);
  view.setUint16(10, HEADER_BYTES, true);
  view.setUint32(12, 1, true);
  view.setUint16(16, DESCRIPTOR_BYTES, true);
  view.setUint16(18, COLUMN_SPECS.length, true);
  view.setUint32(20, 1, true);
  view.setUint32(24, 0, true);
  view.setUint32(28, HEADER_BYTES, true);
  view.setUint32(32, bytes.byteLength, true);
  view.setUint32(36, bytes.byteLength, true);
  for (const [index, [id, type, nullable, width]] of COLUMN_SPECS.entries()) {
    const offset = HEADER_BYTES + index * DESCRIPTOR_BYTES;
    view.setUint16(offset, id, true);
    view.setUint8(offset + 2, type);
    view.setUint8(offset + 3, nullable);
    view.setUint32(offset + 4, width, true);
    view.setUint32(offset + 8, bytes.byteLength, true);
  }
  return bytes;
}

test("independently validates the complete packet batch schema", () => {
  const expected = {
    done: true,
    nextRow: 0n,
    rowCount: 0,
    startRow: 0n,
    totalRows: 0n,
  };
  expect(validatePacketBatchEnvelope(validEmptyBatch())).toEqual(expected);
  expect(validatePacketBatch(validEmptyBatch())).toEqual(expected);
});

test("rejects corrupted packet batch headers and descriptors", () => {
  const corruptions: Array<(bytes: Uint8Array, view: DataView) => void> = [
    (bytes) => {
      bytes[0] = 0;
    },
    (_bytes, view) => view.setUint16(8, 2, true),
    (_bytes, view) => view.setUint32(20, 2, true),
    (_bytes, view) => view.setUint32(36, 64, true),
    (_bytes, view) => view.setUint16(HEADER_BYTES, 99, true),
    (_bytes, view) => view.setUint32(HEADER_BYTES + 4, 8, true),
    (_bytes, view) => view.setUint32(HEADER_BYTES + 8, 1, true),
    (_bytes, view) => view.setUint32(HEADER_BYTES + 20, 1, true),
  ];
  for (const corrupt of corruptions) {
    const bytes = validEmptyBatch();
    corrupt(bytes, new DataView(bytes.buffer));
    expect(() => validatePacketBatch(bytes)).toThrow();
  }
});

test("rejects a row count above the bounded schema cap before walking rows", () => {
  const bytes = validEmptyBatch();
  new DataView(bytes.buffer).setUint32(24, 65_537, true);
  expect(() => validatePacketBatch(bytes)).toThrow(
    "packet batch row count exceeds the schema cap",
  );
});

test("rejects contradictory progress counters, phases, and zero minimum budgets", () => {
  const progress: ProgressSnapshot = {
    bytesConsumedHi: 0,
    bytesConsumedLo: 10,
    diagnostics: 0,
    packetsRetainedHi: 0,
    packetsRetainedLo: 2,
    phase: "parsing",
    recordsHi: 0,
    recordsLo: 3,
    totalBytesHi: 0,
    totalBytesLo: 10,
  };
  expect(progressCountersAreOrdered(progress)).toBe(true);
  expect(progressCountersAreOrdered({ ...progress, bytesConsumedLo: 11 })).toBe(false);
  expect(progressCountersAreOrdered({ ...progress, packetsRetainedLo: 4 })).toBe(false);
  expect(importStateMatchesPhase("in_progress", "parsing")).toBe(true);
  expect(importStateMatchesPhase("in_progress", "validating")).toBe(true);
  expect(importStateMatchesPhase("complete", "complete")).toBe(true);
  expect(importStateMatchesPhase("complete", "parsing")).toBe(false);
  expect(importStateMatchesPhase("in_progress", "failed")).toBe(false);
  expect(cancellationPhaseIsTerminal({ ...progress, phase: "cancelled" })).toBe(true);
  expect(cancellationPhaseIsTerminal(progress)).toBe(false);
  expect(exactU64IsPositive(0, 1)).toBe(true);
  expect(exactU64IsPositive(0, 0)).toBe(false);
});
