import {
  BOUNDARY_API_VERSION,
  BOUNDARY_BATCH_SCHEMA_VERSION,
  MAX_BATCH_BYTES,
  MAX_BATCH_ROWS,
} from "./worker-contract";

const MAGIC = "WLPKTB01";
const HEADER_BYTES = 64;
const DESCRIPTOR_BYTES = 24;
const COLUMN_COUNT = 12;
const DATA_OFFSET = HEADER_BYTES + DESCRIPTOR_BYTES * COLUMN_COUNT;

const COLUMNS = [
  { id: 1, nullable: 0, type: 2, width: 4 },
  { id: 2, nullable: 0, type: 2, width: 4 },
  { id: 3, nullable: 0, type: 2, width: 4 },
  { id: 4, nullable: 0, type: 2, width: 4 },
  { id: 5, nullable: 0, type: 2, width: 4 },
  { id: 6, nullable: 0, type: 2, width: 4 },
  { id: 7, nullable: 0, type: 3, width: 8 },
  { id: 8, nullable: 1, type: 4, width: 8 },
  { id: 9, nullable: 1, type: 3, width: 8 },
  { id: 10, nullable: 0, type: 1, width: 1 },
  { id: 11, nullable: 1, type: 1, width: 1 },
  { id: 12, nullable: 1, type: 1, width: 1 },
] as const;

export interface ValidatedPacketBatch {
  done: boolean;
  nextRow: bigint;
  rowCount: number;
  startRow: bigint;
  totalRows: bigint;
}

interface InspectedPacketBatch {
  offsets: number[];
  result: ValidatedPacketBatch;
  view: DataView;
}

function inspectPacketBatch(bytes: Uint8Array): InspectedPacketBatch {
  if (bytes.byteLength < DATA_OFFSET || bytes.byteLength > MAX_BATCH_BYTES) {
    throw invalid("packet batch byte length is outside the schema bounds");
  }
  const magic = String.fromCharCode(...bytes.subarray(0, 8));
  if (magic !== MAGIC) throw invalid("packet batch magic is invalid");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(8, true) !== BOUNDARY_BATCH_SCHEMA_VERSION) {
    throw invalid("packet batch schema version is unsupported");
  }
  if (view.getUint16(10, true) !== HEADER_BYTES) {
    throw invalid("packet batch header length is invalid");
  }
  if (view.getUint32(12, true) !== BOUNDARY_API_VERSION) {
    throw invalid("packet batch API version is unsupported");
  }
  if (view.getUint16(16, true) !== DESCRIPTOR_BYTES || view.getUint16(18, true) !== COLUMN_COUNT) {
    throw invalid("packet batch descriptor layout is invalid");
  }
  const flags = view.getUint32(20, true);
  if ((flags & ~1) !== 0) throw invalid("packet batch header uses reserved flags");
  const rowCount = view.getUint32(24, true);
  if (rowCount > MAX_BATCH_ROWS) {
    throw invalid("packet batch row count exceeds the schema cap");
  }
  if (
    view.getUint32(28, true) !== HEADER_BYTES ||
    view.getUint32(32, true) !== DATA_OFFSET ||
    view.getUint32(36, true) !== bytes.byteLength
  ) {
    throw invalid("packet batch offsets or total length are inconsistent");
  }
  const startRow = view.getBigUint64(40, true);
  const nextRow = view.getBigUint64(48, true);
  const totalRows = view.getBigUint64(56, true);
  if (
    nextRow < startRow ||
    nextRow > totalRows ||
    nextRow - startRow !== BigInt(rowCount) ||
    ((flags & 1) === 1) !== nextRow >= totalRows
  ) {
    throw invalid("packet batch row range is inconsistent");
  }

  let previousEnd = DATA_OFFSET;
  const offsets: number[] = [];
  for (const [index, expected] of COLUMNS.entries()) {
    const descriptor = HEADER_BYTES + index * DESCRIPTOR_BYTES;
    const id = view.getUint16(descriptor, true);
    const type = view.getUint8(descriptor + 2);
    const nullable = view.getUint8(descriptor + 3);
    const width = view.getUint32(descriptor + 4, true);
    const offset = view.getUint32(descriptor + 8, true);
    const count = view.getUint32(descriptor + 12, true);
    const byteLength = view.getUint32(descriptor + 16, true);
    const reserved = view.getUint32(descriptor + 20, true);
    const expectedLength = rowCount * expected.width;
    const end = offset + byteLength;
    if (
      id !== expected.id ||
      type !== expected.type ||
      nullable !== expected.nullable ||
      width !== expected.width ||
      count !== rowCount ||
      !Number.isSafeInteger(expectedLength) ||
      byteLength !== expectedLength ||
      reserved !== 0 ||
      offset % expected.width !== 0 ||
      offset < previousEnd ||
      !Number.isSafeInteger(end) ||
      end > bytes.byteLength
    ) {
      throw invalid(`packet batch descriptor ${index} is invalid`);
    }
    offsets.push(offset);
    previousEnd = end;
  }
  if (previousEnd !== bytes.byteLength) {
    throw invalid("packet batch has unaccounted trailing bytes");
  }

  return {
    offsets,
    result: { done: (flags & 1) === 1, nextRow, rowCount, startRow, totalRows },
    view,
  };
}

/** Validates the fixed-size header and descriptor envelope only. */
export function validatePacketBatchEnvelope(bytes: Uint8Array): ValidatedPacketBatch {
  return inspectPacketBatch(bytes).result;
}

/** Validates the envelope and every row-level semantic invariant in a worker. */
export function validatePacketBatch(bytes: Uint8Array): ValidatedPacketBatch {
  const { offsets, result, view } = inspectPacketBatch(bytes);
  const { rowCount, startRow } = result;

  const packetIdOffset = offsets[0];
  const capturedLengthOffset = offsets[3];
  const evidenceLengthOffset = offsets[5];
  const timestampPresentOffset = offsets[9];
  const resolutionKindOffset = offsets[10];
  const resolutionExponentOffset = offsets[11];
  if (
    packetIdOffset === undefined ||
    capturedLengthOffset === undefined ||
    evidenceLengthOffset === undefined ||
    timestampPresentOffset === undefined ||
    resolutionKindOffset === undefined ||
    resolutionExponentOffset === undefined
  ) {
    throw invalid("packet batch required columns are absent");
  }
  for (let row = 0; row < rowCount; row += 1) {
    const packetId = view.getUint32(packetIdOffset + row * 4, true);
    if (BigInt(packetId) !== startRow + BigInt(row)) {
      throw invalid("packet batch packet IDs are not the requested row sequence");
    }
    if (
      view.getUint32(capturedLengthOffset + row * 4, true) !==
      view.getUint32(evidenceLengthOffset + row * 4, true)
    ) {
      throw invalid("packet batch evidence and captured lengths disagree");
    }
    const present = view.getUint8(timestampPresentOffset + row);
    const resolutionKind = view.getUint8(resolutionKindOffset + row);
    const exponent = view.getUint8(resolutionExponentOffset + row);
    if (present > 1 || (present === 1 && resolutionKind > 1) || exponent > 127) {
      throw invalid("packet batch timestamp metadata is invalid");
    }
  }

  return result;
}

function invalid(message: string): Error {
  return new Error(message);
}
