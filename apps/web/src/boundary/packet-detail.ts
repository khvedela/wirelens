import { BOUNDARY_API_VERSION } from "./worker-contract";

export const PACKET_DETAIL_SCHEMA_VERSION = 1;
export const MAX_PACKET_DETAIL_BYTES = 512 * 1024;
export const MAX_PACKET_DETAIL_FIELDS = 1_024;
export const MAX_PACKET_DETAIL_LAYERS = 32;

const MAGIC = "WLPKDT01";
const HEADER_BYTES = 80;
const DESCRIPTOR_BYTES = 24;
const COLUMN_COUNT = 20;
const DATA_OFFSET = HEADER_BYTES + DESCRIPTOR_BYTES * COLUMN_COUNT;
const MAX_STRING_BYTES = 256 * 1024;
const ABSENT_ID = 0xffff_ffff;
const MAX_U64 = (1n << 64n) - 1n;
const FLAG_WIRE_TRUNCATED = 1;
const FLAG_PROTOCOL_TRUNCATED = 2;

const TYPE_U8 = 1;
const TYPE_U32 = 2;
const TYPE_U64 = 3;

interface ColumnSpec {
  readonly count: "blob" | "field" | "layer" | "string";
  readonly id: number;
  readonly type: number;
  readonly width: number;
}

const COLUMNS: readonly ColumnSpec[] = [
  { count: "layer", id: 1, type: TYPE_U32, width: 4 },
  { count: "layer", id: 2, type: TYPE_U32, width: 4 },
  { count: "layer", id: 3, type: TYPE_U32, width: 4 },
  { count: "layer", id: 4, type: TYPE_U32, width: 4 },
  { count: "field", id: 5, type: TYPE_U32, width: 4 },
  { count: "field", id: 6, type: TYPE_U32, width: 4 },
  { count: "field", id: 7, type: TYPE_U32, width: 4 },
  { count: "field", id: 8, type: TYPE_U32, width: 4 },
  { count: "field", id: 9, type: TYPE_U32, width: 4 },
  { count: "field", id: 10, type: TYPE_U32, width: 4 },
  { count: "field", id: 11, type: TYPE_U32, width: 4 },
  { count: "field", id: 12, type: TYPE_U32, width: 4 },
  { count: "field", id: 13, type: TYPE_U32, width: 4 },
  { count: "field", id: 14, type: TYPE_U32, width: 4 },
  { count: "string", id: 15, type: TYPE_U32, width: 4 },
  { count: "string", id: 16, type: TYPE_U32, width: 4 },
  { count: "string", id: 17, type: TYPE_U32, width: 4 },
  { count: "field", id: 18, type: TYPE_U64, width: 8 },
  { count: "field", id: 19, type: TYPE_U8, width: 1 },
  { count: "blob", id: 20, type: TYPE_U8, width: 1 },
] as const;

export interface PacketByteRange {
  readonly length: number;
  readonly start: number;
}

export type PacketDetailFieldValue =
  | { readonly kind: "none" }
  | { readonly kind: "unsigned"; readonly value: bigint }
  | { readonly kind: "signed"; readonly value: bigint }
  | { readonly kind: "boolean"; readonly value: boolean }
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "bytes"; readonly range: PacketByteRange };

export interface PacketDetailLayer {
  readonly byteRange: PacketByteRange;
  readonly index: number;
  readonly protocol: string;
  readonly rootFieldId: number | null;
}

export interface PacketDetailField {
  readonly byteRange: PacketByteRange;
  readonly depth: number;
  readonly id: number;
  readonly layerIndex: number;
  readonly name: string;
  readonly parentId: number | null;
  readonly value: PacketDetailFieldValue;
}

export interface PacketDetail {
  readonly capturedLength: number;
  readonly evidenceStart: bigint;
  readonly fields: readonly PacketDetailField[];
  readonly layers: readonly PacketDetailLayer[];
  readonly originalLength: number;
  readonly packetId: number;
  readonly protocolTruncated: boolean;
  readonly wireTruncated: boolean;
}

interface Header {
  readonly capturedLength: number;
  readonly evidenceStart: bigint;
  readonly fieldCount: number;
  readonly flags: number;
  readonly layerCount: number;
  readonly originalLength: number;
  readonly packetId: number;
  readonly stringBlobBytes: number;
  readonly stringCount: number;
}

interface InspectedPacketDetail {
  readonly header: Header;
  readonly offsets: readonly number[];
  readonly view: DataView;
}

function invalid(message: string): Error {
  return new Error(message);
}

function checkedEnd(start: number, length: number, limit: number, label: string): number {
  const end = start + length;
  if (!Number.isSafeInteger(end) || start < 0 || length < 0 || end > limit) {
    throw invalid(`${label} is outside the captured packet`);
  }
  return end;
}

function contains(container: PacketByteRange, child: PacketByteRange): boolean {
  return (
    child.start >= container.start &&
    child.start + child.length <= container.start + container.length
  );
}

function countFor(header: Header, kind: ColumnSpec["count"]): number {
  switch (kind) {
    case "blob":
      return header.stringBlobBytes;
    case "field":
      return header.fieldCount;
    case "layer":
      return header.layerCount;
    case "string":
      return header.stringCount;
  }
}

function paddingIsZero(bytes: Uint8Array, start: number, end: number): boolean {
  for (let index = start; index < end; index += 1) {
    if (bytes[index] !== 0) return false;
  }
  return true;
}

function inspectPacketDetail(bytes: Uint8Array, expectedPacketId?: number): InspectedPacketDetail {
  if (bytes.byteLength < DATA_OFFSET || bytes.byteLength > MAX_PACKET_DETAIL_BYTES) {
    throw invalid("packet detail byte length is outside the schema bounds");
  }
  const magic = String.fromCharCode(...bytes.subarray(0, 8));
  if (magic !== MAGIC) throw invalid("packet detail magic is invalid");
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint16(8, true) !== PACKET_DETAIL_SCHEMA_VERSION) {
    throw invalid("packet detail schema version is unsupported");
  }
  if (view.getUint16(10, true) !== HEADER_BYTES) {
    throw invalid("packet detail header length is invalid");
  }
  if (view.getUint32(12, true) !== BOUNDARY_API_VERSION) {
    throw invalid("packet detail API version is unsupported");
  }
  if (view.getUint16(16, true) !== DESCRIPTOR_BYTES || view.getUint16(18, true) !== COLUMN_COUNT) {
    throw invalid("packet detail descriptor layout is invalid");
  }

  const flags = view.getUint32(20, true);
  if ((flags & ~(FLAG_WIRE_TRUNCATED | FLAG_PROTOCOL_TRUNCATED)) !== 0) {
    throw invalid("packet detail uses reserved flags");
  }
  const packetId = view.getUint32(24, true);
  const capturedLength = view.getUint32(28, true);
  const originalLength = view.getUint32(32, true);
  const layerCount = view.getUint32(36, true);
  const fieldCount = view.getUint32(40, true);
  const stringCount = view.getUint32(44, true);
  const stringBlobBytes = view.getUint32(60, true);
  const evidenceStart = view.getBigUint64(64, true);
  const evidenceLength = view.getUint32(72, true);
  if (
    view.getUint32(48, true) !== HEADER_BYTES ||
    view.getUint32(52, true) !== DATA_OFFSET ||
    view.getUint32(56, true) !== bytes.byteLength ||
    view.getUint32(76, true) !== 0
  ) {
    throw invalid("packet detail offsets, total length, or reserved header are invalid");
  }
  if (expectedPacketId !== undefined && packetId !== expectedPacketId) {
    throw invalid("packet detail identifies a different packet");
  }
  if (layerCount > MAX_PACKET_DETAIL_LAYERS || fieldCount > MAX_PACKET_DETAIL_FIELDS) {
    throw invalid("packet detail row count exceeds its schema cap");
  }
  const maxReferencedStrings = layerCount + fieldCount * 2;
  if (
    !Number.isSafeInteger(maxReferencedStrings) ||
    stringCount > maxReferencedStrings ||
    stringBlobBytes > MAX_STRING_BYTES
  ) {
    throw invalid("packet detail string data exceeds its schema cap");
  }
  if (
    evidenceLength !== capturedLength ||
    evidenceStart + BigInt(capturedLength) > MAX_U64 ||
    ((flags & FLAG_WIRE_TRUNCATED) !== 0) !== originalLength > capturedLength
  ) {
    throw invalid("packet detail evidence or truncation metadata is inconsistent");
  }

  const header: Header = {
    capturedLength,
    evidenceStart,
    fieldCount,
    flags,
    layerCount,
    originalLength,
    packetId,
    stringBlobBytes,
    stringCount,
  };
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
    const expectedCount = countFor(header, expected.count);
    const expectedLength = expectedCount * expected.width;
    const end = offset + byteLength;
    if (
      id !== expected.id ||
      type !== expected.type ||
      nullable !== 0 ||
      width !== expected.width ||
      count !== expectedCount ||
      !Number.isSafeInteger(expectedLength) ||
      byteLength !== expectedLength ||
      reserved !== 0 ||
      offset % expected.width !== 0 ||
      offset < previousEnd ||
      !Number.isSafeInteger(end) ||
      end > bytes.byteLength ||
      !paddingIsZero(bytes, previousEnd, offset)
    ) {
      throw invalid(`packet detail descriptor ${index} is invalid`);
    }
    offsets.push(offset);
    previousEnd = end;
  }
  if (previousEnd !== bytes.byteLength) {
    throw invalid("packet detail has unaccounted trailing bytes");
  }
  return { header, offsets, view };
}

function offsetAt(offsets: readonly number[], index: number): number {
  const offset = offsets[index];
  if (offset === undefined) throw invalid("packet detail required column is absent");
  return offset;
}

function decodeStrings(
  bytes: Uint8Array,
  inspected: InspectedPacketDetail,
): ReadonlyMap<number, string> {
  const { header, offsets, view } = inspected;
  const idOffset = offsetAt(offsets, 14);
  const startOffset = offsetAt(offsets, 15);
  const lengthOffset = offsetAt(offsets, 16);
  const blobOffset = offsetAt(offsets, 19);
  const strings = new Map<number, string>();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let expectedStart = 0;
  for (let row = 0; row < header.stringCount; row += 1) {
    const id = view.getUint32(idOffset + row * 4, true);
    const start = view.getUint32(startOffset + row * 4, true);
    const length = view.getUint32(lengthOffset + row * 4, true);
    const end = checkedEnd(start, length, header.stringBlobBytes, "packet detail string");
    if (id === ABSENT_ID || strings.has(id) || start !== expectedStart) {
      throw invalid("packet detail string dictionary is not unique and tightly packed");
    }
    let value: string;
    try {
      value = decoder.decode(bytes.subarray(blobOffset + start, blobOffset + end));
    } catch {
      throw invalid("packet detail string data is not valid UTF-8");
    }
    strings.set(id, value);
    expectedStart = end;
  }
  if (expectedStart !== header.stringBlobBytes) {
    throw invalid("packet detail string dictionary does not cover its UTF-8 blob");
  }
  return strings;
}

function requiredString(strings: ReadonlyMap<number, string>, id: number, label: string): string {
  const value = strings.get(id);
  if (value === undefined) throw invalid(`${label} references a missing string`);
  return value;
}

function decodeValue(
  kind: number,
  bits: bigint,
  stringId: number,
  bytesRange: PacketByteRange,
  fieldRange: PacketByteRange,
  strings: ReadonlyMap<number, string>,
): PacketDetailFieldValue {
  const noString = stringId === ABSENT_ID;
  const noBytes = bytesRange.start === 0 && bytesRange.length === 0;
  switch (kind) {
    case 0:
      if (bits !== 0n || !noString || !noBytes) break;
      return { kind: "none" };
    case 1:
      if (!noString || !noBytes) break;
      return { kind: "unsigned", value: bits };
    case 2:
      if (!noString || !noBytes) break;
      return { kind: "signed", value: BigInt.asIntN(64, bits) };
    case 3:
      if (!noString || !noBytes || (bits !== 0n && bits !== 1n)) break;
      return { kind: "boolean", value: bits === 1n };
    case 4:
      if (bits !== 0n || noString || !noBytes) break;
      return { kind: "string", value: requiredString(strings, stringId, "field value") };
    case 5:
      if (bits !== 0n || !noString || !contains(fieldRange, bytesRange)) break;
      return { kind: "bytes", range: bytesRange };
    default:
      break;
  }
  throw invalid("packet detail field value is inconsistent");
}

/** Decodes and semantically validates one bounded packet-detail batch. */
export function decodePacketDetail(bytes: Uint8Array, expectedPacketId?: number): PacketDetail {
  const inspected = inspectPacketDetail(bytes, expectedPacketId);
  const { header, offsets, view } = inspected;
  const strings = decodeStrings(bytes, inspected);
  const referencedStrings = new Set<number>();

  const layerProtocolOffset = offsetAt(offsets, 0);
  const layerStartOffset = offsetAt(offsets, 1);
  const layerLengthOffset = offsetAt(offsets, 2);
  const layerRootOffset = offsetAt(offsets, 3);
  const layers: PacketDetailLayer[] = [];
  for (let row = 0; row < header.layerCount; row += 1) {
    const protocolId = view.getUint32(layerProtocolOffset + row * 4, true);
    referencedStrings.add(protocolId);
    const start = view.getUint32(layerStartOffset + row * 4, true);
    const length = view.getUint32(layerLengthOffset + row * 4, true);
    checkedEnd(start, length, header.capturedLength, "packet detail layer range");
    const root = view.getUint32(layerRootOffset + row * 4, true);
    layers.push({
      byteRange: { length, start },
      index: row,
      protocol: requiredString(strings, protocolId, "layer protocol"),
      rootFieldId: root === ABSENT_ID ? null : root,
    });
  }

  const fieldIdOffset = offsetAt(offsets, 4);
  const parentOffset = offsetAt(offsets, 5);
  const fieldLayerOffset = offsetAt(offsets, 6);
  const depthOffset = offsetAt(offsets, 7);
  const nameOffset = offsetAt(offsets, 8);
  const fieldStartOffset = offsetAt(offsets, 9);
  const fieldLengthOffset = offsetAt(offsets, 10);
  const valueStringOffset = offsetAt(offsets, 11);
  const valueBytesStartOffset = offsetAt(offsets, 12);
  const valueBytesLengthOffset = offsetAt(offsets, 13);
  const valueBitsOffset = offsetAt(offsets, 17);
  const valueKindOffset = offsetAt(offsets, 18);
  const fields: PacketDetailField[] = [];
  const fieldsById = new Map<number, PacketDetailField>();
  let previousLayerIndex = 0;
  for (let row = 0; row < header.fieldCount; row += 1) {
    const id = view.getUint32(fieldIdOffset + row * 4, true);
    const rawParent = view.getUint32(parentOffset + row * 4, true);
    const parentId = rawParent === ABSENT_ID ? null : rawParent;
    const layerIndex = view.getUint32(fieldLayerOffset + row * 4, true);
    const depth = view.getUint32(depthOffset + row * 4, true);
    const nameId = view.getUint32(nameOffset + row * 4, true);
    referencedStrings.add(nameId);
    const start = view.getUint32(fieldStartOffset + row * 4, true);
    const length = view.getUint32(fieldLengthOffset + row * 4, true);
    checkedEnd(start, length, header.capturedLength, "packet detail field range");
    const byteRange = { length, start };
    const valueStringId = view.getUint32(valueStringOffset + row * 4, true);
    if (valueStringId !== ABSENT_ID) referencedStrings.add(valueStringId);
    const valueBytesStart = view.getUint32(valueBytesStartOffset + row * 4, true);
    const valueBytesLength = view.getUint32(valueBytesLengthOffset + row * 4, true);
    checkedEnd(
      valueBytesStart,
      valueBytesLength,
      header.capturedLength,
      "packet detail byte value",
    );
    const layer = layers[layerIndex];
    if (
      id === ABSENT_ID ||
      fieldsById.has(id) ||
      layer === undefined ||
      (row > 0 && layerIndex < previousLayerIndex) ||
      !contains(layer.byteRange, byteRange)
    ) {
      throw invalid("packet detail field ownership is invalid");
    }
    const parent = parentId === null ? undefined : fieldsById.get(parentId);
    if (
      (parentId === null && depth !== 0) ||
      (parentId !== null &&
        (parent === undefined ||
          parent.layerIndex !== layerIndex ||
          depth !== parent.depth + 1 ||
          !contains(parent.byteRange, byteRange)))
    ) {
      throw invalid("packet detail field hierarchy is invalid");
    }
    const field: PacketDetailField = {
      byteRange,
      depth,
      id,
      layerIndex,
      name: requiredString(strings, nameId, "field name"),
      parentId,
      value: decodeValue(
        view.getUint8(valueKindOffset + row),
        view.getBigUint64(valueBitsOffset + row * 8, true),
        valueStringId,
        { length: valueBytesLength, start: valueBytesStart },
        byteRange,
        strings,
      ),
    };
    fields.push(field);
    fieldsById.set(id, field);
    previousLayerIndex = layerIndex;
  }

  for (const layer of layers) {
    const layerFields = fields.filter((field) => field.layerIndex === layer.index);
    if (layer.rootFieldId === null) {
      if (layerFields.length !== 0) throw invalid("rootless layer owns packet detail fields");
      continue;
    }
    const root = fieldsById.get(layer.rootFieldId);
    if (
      root === undefined ||
      root.layerIndex !== layer.index ||
      root.parentId !== null ||
      layerFields[0]?.id !== root.id ||
      layerFields.some((field) => {
        let ancestor = field;
        while (ancestor.parentId !== null) {
          const parent = fieldsById.get(ancestor.parentId);
          if (parent === undefined) return true;
          ancestor = parent;
        }
        return ancestor.id !== root.id;
      })
    ) {
      throw invalid("packet detail layer root is invalid");
    }
  }
  if (
    referencedStrings.size !== strings.size ||
    [...strings.keys()].some((id) => !referencedStrings.has(id))
  ) {
    throw invalid("packet detail contains unreferenced strings");
  }

  return {
    capturedLength: header.capturedLength,
    evidenceStart: header.evidenceStart,
    fields,
    layers,
    originalLength: header.originalLength,
    packetId: header.packetId,
    protocolTruncated: (header.flags & FLAG_PROTOCOL_TRUNCATED) !== 0,
    wireTruncated: (header.flags & FLAG_WIRE_TRUNCATED) !== 0,
  };
}

/** Validates a packet-detail payload without retaining its decoded view. */
export function validatePacketDetail(bytes: Uint8Array, expectedPacketId?: number): void {
  decodePacketDetail(bytes, expectedPacketId);
}
