import { BOUNDARY_API_VERSION } from "../../src/boundary/worker-contract";

export const DETAIL_TEST_HEADER_BYTES = 80;
export const DETAIL_TEST_DESCRIPTOR_BYTES = 24;
const COLUMN_COUNT = 20;
const DATA_OFFSET = DETAIL_TEST_HEADER_BYTES + DETAIL_TEST_DESCRIPTOR_BYTES * COLUMN_COUNT;
const ABSENT = 0xffff_ffff;

const strings = [
  [1, "ethernet"],
  [2, "root"],
  [3, "unsigned"],
  [4, "signed"],
  [5, "boolean"],
  [6, "string"],
  [7, "normalized.test"],
  [8, "bytes"],
  [9, "marker"],
] as const;

const fieldIds = [10, 11, 12, 13, 14, 15, 16];
const fieldParents = [ABSENT, 10, 10, 10, 10, 10, 10];
const fieldLayers = [0, 0, 0, 0, 0, 0, 0];
const fieldDepths = [0, 1, 1, 1, 1, 1, 1];
const fieldNames = [2, 3, 4, 5, 6, 8, 9];
const fieldStarts = [0, 0, 1, 2, 3, 4, 16];
const fieldLengths = [16, 1, 1, 1, 1, 2, 0];
const valueStrings = [ABSENT, ABSENT, ABSENT, ABSENT, 7, ABSENT, ABSENT];
const valueByteStarts = [0, 0, 0, 0, 0, 4, 0];
const valueByteLengths = [0, 0, 0, 0, 0, 2, 0];
const valueBits = [0n, 0xffff_ffff_ffff_ffffn, BigInt.asUintN(64, -2n), 1n, 0n, 0n, 0n];
const valueKinds = [0, 1, 2, 3, 4, 5, 0];

interface Column {
  readonly count: number;
  readonly id: number;
  readonly type: number;
  readonly values: readonly (bigint | number)[] | Uint8Array;
  readonly width: number;
}

interface PacketDetailTestInput {
  readonly capturedLength: number;
  readonly fieldDepths: readonly number[];
  readonly fieldIds: readonly number[];
  readonly fieldLayers: readonly number[];
  readonly fieldLengths: readonly number[];
  readonly fieldNames: readonly number[];
  readonly fieldParents: readonly number[];
  readonly fieldStarts: readonly number[];
  readonly flags: number;
  readonly originalLength: number;
  readonly strings: readonly (readonly [number, string])[];
  readonly valueBits: readonly bigint[];
  readonly valueByteLengths: readonly number[];
  readonly valueByteStarts: readonly number[];
  readonly valueKinds: readonly number[];
  readonly valueStrings: readonly number[];
}

function align(value: number, width: number): number {
  return (value + width - 1) & ~(width - 1);
}

function writeColumn(view: DataView, offset: number, column: Column): void {
  for (let row = 0; row < column.count; row += 1) {
    const value = column.values[row];
    if (value === undefined) throw new Error("packet-detail test column is incomplete");
    if (column.width === 1) view.setUint8(offset + row, Number(value));
    else if (column.width === 4) view.setUint32(offset + row * 4, Number(value), true);
    else view.setBigUint64(offset + row * 8, BigInt(value), true);
  }
}

export function packetDetailDescriptorOffset(index: number): number {
  return DETAIL_TEST_HEADER_BYTES + index * DETAIL_TEST_DESCRIPTOR_BYTES;
}

function buildPacketDetailBatch({
  capturedLength,
  fieldDepths,
  fieldIds,
  fieldLayers,
  fieldLengths,
  fieldNames,
  fieldParents,
  fieldStarts,
  flags,
  originalLength,
  strings,
  valueBits,
  valueByteLengths,
  valueByteStarts,
  valueKinds,
  valueStrings,
}: PacketDetailTestInput): Uint8Array {
  const encoder = new TextEncoder();
  const encodedStrings = strings.map(([id, value]) => ({ bytes: encoder.encode(value), id }));
  let blobLength = 0;
  const stringOffsets: number[] = [];
  for (const entry of encodedStrings) {
    stringOffsets.push(blobLength);
    blobLength += entry.bytes.length;
  }
  const blob = new Uint8Array(blobLength);
  for (const [index, entry] of encodedStrings.entries()) {
    blob.set(entry.bytes, stringOffsets[index]);
  }
  const columns: Column[] = [
    { count: 1, id: 1, type: 2, values: [1], width: 4 },
    { count: 1, id: 2, type: 2, values: [0], width: 4 },
    { count: 1, id: 3, type: 2, values: [capturedLength], width: 4 },
    { count: 1, id: 4, type: 2, values: [fieldIds[0] ?? ABSENT], width: 4 },
    { count: fieldIds.length, id: 5, type: 2, values: fieldIds, width: 4 },
    { count: fieldIds.length, id: 6, type: 2, values: fieldParents, width: 4 },
    { count: fieldIds.length, id: 7, type: 2, values: fieldLayers, width: 4 },
    { count: fieldIds.length, id: 8, type: 2, values: fieldDepths, width: 4 },
    { count: fieldIds.length, id: 9, type: 2, values: fieldNames, width: 4 },
    { count: fieldIds.length, id: 10, type: 2, values: fieldStarts, width: 4 },
    { count: fieldIds.length, id: 11, type: 2, values: fieldLengths, width: 4 },
    { count: fieldIds.length, id: 12, type: 2, values: valueStrings, width: 4 },
    { count: fieldIds.length, id: 13, type: 2, values: valueByteStarts, width: 4 },
    { count: fieldIds.length, id: 14, type: 2, values: valueByteLengths, width: 4 },
    { count: strings.length, id: 15, type: 2, values: strings.map(([id]) => id), width: 4 },
    { count: strings.length, id: 16, type: 2, values: stringOffsets, width: 4 },
    {
      count: strings.length,
      id: 17,
      type: 2,
      values: encodedStrings.map((entry) => entry.bytes.length),
      width: 4,
    },
    { count: fieldIds.length, id: 18, type: 3, values: valueBits, width: 8 },
    { count: fieldIds.length, id: 19, type: 1, values: valueKinds, width: 1 },
    { count: blob.length, id: 20, type: 1, values: blob, width: 1 },
  ];
  let cursor = DATA_OFFSET;
  const offsets: number[] = [];
  for (const column of columns) {
    cursor = align(cursor, column.width);
    offsets.push(cursor);
    cursor += column.count * column.width;
  }
  const bytes = new Uint8Array(cursor);
  const view = new DataView(bytes.buffer);
  bytes.set(new TextEncoder().encode("WLPKDT01"), 0);
  view.setUint16(8, 1, true);
  view.setUint16(10, DETAIL_TEST_HEADER_BYTES, true);
  view.setUint32(12, BOUNDARY_API_VERSION, true);
  view.setUint16(16, DETAIL_TEST_DESCRIPTOR_BYTES, true);
  view.setUint16(18, COLUMN_COUNT, true);
  view.setUint32(20, flags, true);
  view.setUint32(24, 0, true);
  view.setUint32(28, capturedLength, true);
  view.setUint32(32, originalLength, true);
  view.setUint32(36, 1, true);
  view.setUint32(40, fieldIds.length, true);
  view.setUint32(44, strings.length, true);
  view.setUint32(48, DETAIL_TEST_HEADER_BYTES, true);
  view.setUint32(52, DATA_OFFSET, true);
  view.setUint32(56, bytes.length, true);
  view.setUint32(60, blob.length, true);
  view.setBigUint64(64, 100n, true);
  view.setUint32(72, capturedLength, true);

  for (const [index, column] of columns.entries()) {
    const descriptor = packetDetailDescriptorOffset(index);
    const offset = offsets[index];
    if (offset === undefined) throw new Error("packet-detail test descriptor is absent");
    view.setUint16(descriptor, column.id, true);
    view.setUint8(descriptor + 2, column.type);
    view.setUint32(descriptor + 4, column.width, true);
    view.setUint32(descriptor + 8, offset, true);
    view.setUint32(descriptor + 12, column.count, true);
    view.setUint32(descriptor + 16, column.count * column.width, true);
    writeColumn(view, offset, column);
  }
  return bytes;
}

export function buildPacketDetailTestBatch(): Uint8Array {
  return buildPacketDetailBatch({
    capturedLength: 16,
    fieldDepths,
    fieldIds,
    fieldLayers,
    fieldLengths,
    fieldNames,
    fieldParents,
    fieldStarts,
    flags: 3,
    originalLength: 20,
    strings,
    valueBits,
    valueByteLengths,
    valueByteStarts,
    valueKinds,
    valueStrings,
  });
}

export function buildMaximumPacketDetailTestBatch(): Uint8Array {
  const fieldCount = 1_024;
  const rootFieldId = 10;
  const denseFieldIds = Array.from({ length: fieldCount }, (_, index) => rootFieldId + index);
  return buildPacketDetailBatch({
    capturedLength: fieldCount,
    fieldDepths: Array.from({ length: fieldCount }, (_, index) => (index === 0 ? 0 : 1)),
    fieldIds: denseFieldIds,
    fieldLayers: Array(fieldCount).fill(0),
    fieldLengths: Array.from({ length: fieldCount }, (_, index) => (index === 0 ? fieldCount : 1)),
    fieldNames: Array(fieldCount).fill(2),
    fieldParents: Array.from({ length: fieldCount }, (_, index) =>
      index === 0 ? ABSENT : rootFieldId,
    ),
    fieldStarts: Array.from({ length: fieldCount }, (_, index) => (index === 0 ? 0 : index - 1)),
    flags: 0,
    originalLength: fieldCount,
    strings: [
      [1, "ethernet"],
      [2, "x".repeat(256 * 1024 - "ethernet".length)],
    ],
    valueBits: Array(fieldCount).fill(0n),
    valueByteLengths: Array(fieldCount).fill(0),
    valueByteStarts: Array(fieldCount).fill(0),
    valueKinds: Array(fieldCount).fill(0),
    valueStrings: Array(fieldCount).fill(ABSENT),
  });
}
