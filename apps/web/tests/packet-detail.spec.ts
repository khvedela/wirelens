import { expect, test } from "@playwright/test";

import { decodePacketDetail, validatePacketDetail } from "../src/boundary/packet-detail";
import { validatedFieldMatchState } from "../src/features/packet-detail/packet-detail-model";
import {
  buildMaximumPacketDetailTestBatch,
  buildPacketDetailTestBatch,
  packetDetailDescriptorOffset,
} from "./support/packet-detail-test-batch";

function columnOffset(bytes: Uint8Array, index: number): number {
  return new DataView(bytes.buffer).getUint32(packetDetailDescriptorOffset(index) + 8, true);
}

test("decodes every field value without losing ranges or 64-bit integers", () => {
  const detail = decodePacketDetail(buildPacketDetailTestBatch(), 0);

  expect(detail).toMatchObject({
    capturedLength: 16,
    evidenceStart: 100n,
    originalLength: 20,
    packetId: 0,
    protocolTruncated: true,
    wireTruncated: true,
  });
  expect(detail.layers).toEqual([
    {
      byteRange: { length: 16, start: 0 },
      index: 0,
      protocol: "ethernet",
      rootFieldId: 10,
    },
  ]);
  expect(detail.fields.map(({ id, parentId, depth }) => ({ depth, id, parentId }))).toEqual([
    { depth: 0, id: 10, parentId: null },
    { depth: 1, id: 11, parentId: 10 },
    { depth: 1, id: 12, parentId: 10 },
    { depth: 1, id: 13, parentId: 10 },
    { depth: 1, id: 14, parentId: 10 },
    { depth: 1, id: 15, parentId: 10 },
    { depth: 1, id: 16, parentId: 10 },
  ]);
  expect(detail.fields.map((field) => field.value)).toEqual([
    { kind: "none" },
    { kind: "unsigned", value: 0xffff_ffff_ffff_ffffn },
    { kind: "signed", value: -2n },
    { kind: "boolean", value: true },
    { kind: "string", value: "normalized.test" },
    { kind: "bytes", range: { length: 2, start: 4 } },
    { kind: "none" },
  ]);
  expect(detail.fields.at(-1)?.byteRange).toEqual({ length: 0, start: 16 });
});

test("rejects incompatible headers, descriptors, packet identity, and truncation flags", () => {
  for (const mutate of [
    (view: DataView) => view.setUint16(8, 2, true),
    (view: DataView) => view.setUint32(20, 0x8000_0000, true),
    (view: DataView) => view.setUint32(20, 2, true),
    (view: DataView) => view.setUint32(24, 4, true),
    (view: DataView) => view.setUint32(packetDetailDescriptorOffset(0) + 16, 8, true),
    (view: DataView) => view.setUint32(packetDetailDescriptorOffset(17) + 8, 561, true),
  ]) {
    const bytes = buildPacketDetailTestBatch();
    mutate(new DataView(bytes.buffer));
    expect(() => validatePacketDetail(bytes, 0)).toThrow();
  }
});

test("rejects malformed hierarchy, ranges, values, strings, and trailing data", () => {
  const hierarchy = buildPacketDetailTestBatch();
  new DataView(hierarchy.buffer).setUint32(columnOffset(hierarchy, 5) + 2 * 4, 0xffff_ffff, true);
  expect(() => decodePacketDetail(hierarchy)).toThrow(/hierarchy/u);

  const range = buildPacketDetailTestBatch();
  new DataView(range.buffer).setUint32(columnOffset(range, 9) + 6 * 4, 17, true);
  expect(() => decodePacketDetail(range)).toThrow(/range/u);

  const value = buildPacketDetailTestBatch();
  new DataView(value.buffer).setUint8(columnOffset(value, 18) + 1, 9);
  expect(() => decodePacketDetail(value)).toThrow(/value/u);

  const utf8 = buildPacketDetailTestBatch();
  utf8[columnOffset(utf8, 19)] = 0xff;
  expect(() => decodePacketDetail(utf8)).toThrow(/UTF-8/u);

  const valid = buildPacketDetailTestBatch();
  const trailing = new Uint8Array(valid.length + 1);
  trailing.set(valid);
  new DataView(trailing.buffer).setUint32(56, trailing.length, true);
  expect(() => decodePacketDetail(trailing)).toThrow(/trailing/u);
});

test("rejects correlation identities that are absent from the displayed packet detail", () => {
  const detail = decodePacketDetail(buildPacketDetailTestBatch());
  expect(
    validatedFieldMatchState(detail.fields, {
      fieldIds: new Uint32Array([11, 10]),
      primaryFieldId: 11,
    }),
  ).toMatchObject({ primaryFieldId: 11 });
  expect(
    validatedFieldMatchState(detail.fields, {
      fieldIds: new Uint32Array([11, 99]),
      primaryFieldId: 11,
    }),
  ).toBeUndefined();
  expect(
    validatedFieldMatchState(detail.fields, {
      fieldIds: new Uint32Array([11, 10]),
      primaryFieldId: 10,
    }),
  ).toBeUndefined();
});

test("decodes the maximum field and string envelope without a main-thread long task", () => {
  const bytes = buildMaximumPacketDetailTestBatch();
  const startedAt = performance.now();
  const detail = decodePacketDetail(bytes);
  const durationMs = performance.now() - startedAt;

  expect(bytes.byteLength).toBeLessThanOrEqual(512 * 1024);
  expect(detail.fields).toHaveLength(1_024);
  expect(durationMs).toBeLessThan(50);
});
