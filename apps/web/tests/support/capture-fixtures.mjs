import { createHash } from "node:crypto";
import { mkdir, mkdtemp, open, readdir, realpath, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";

export const KIB = 1024;
export const MIB = 1024 * KIB;
export const MAX_V1_CAPTURE_BYTES = 256 * MIB;
export const MAX_V1_RECORD_OR_BLOCK_BYTES = 4 * MIB;
export const DEFAULT_SUPPORTED_LARGE_TARGET_BYTES = 8 * MIB;
export const RECOMMENDED_NEAR_CAP_TARGET_BYTES = 240 * MIB;
export const ADR_0001_LARGE_CAPTURE_MINIMUM_BYTES = 500 * MIB;

export const PCAP_VARIANTS = Object.freeze([
  Object.freeze({
    endian: "little",
    fractionResolution: "microseconds",
    id: "little-microseconds",
    magic: Object.freeze([0xd4, 0xc3, 0xb2, 0xa1]),
  }),
  Object.freeze({
    endian: "big",
    fractionResolution: "microseconds",
    id: "big-microseconds",
    magic: Object.freeze([0xa1, 0xb2, 0xc3, 0xd4]),
  }),
  Object.freeze({
    endian: "little",
    fractionResolution: "nanoseconds",
    id: "little-nanoseconds",
    magic: Object.freeze([0x4d, 0x3c, 0xb2, 0xa1]),
  }),
  Object.freeze({
    endian: "big",
    fractionResolution: "nanoseconds",
    id: "big-nanoseconds",
    magic: Object.freeze([0xa1, 0xb2, 0x3c, 0x4d]),
  }),
]);

const PCAP_GLOBAL_HEADER_BYTES = 24;
const PCAP_RECORD_HEADER_BYTES = 16;
const PCAPNG_SECTION_HEADER_BYTES = 28;
const ETHERNET_HEADER_BYTES = 14;
const DEFAULT_MAX_WRITE_CHUNK_BYTES = 4 * MIB;

function assertSafeInteger(value, name, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new RangeError(`${name} must be an integer from ${minimum} through ${maximum}`);
  }
}

function assertEndian(endian) {
  if (endian !== "little" && endian !== "big") {
    throw new TypeError("endian must be little or big");
  }
}

function variantById(variantId) {
  const variant = PCAP_VARIANTS.find(({ id }) => id === variantId);
  if (variant === undefined) throw new TypeError(`unknown PCAP variant: ${variantId}`);
  return variant;
}

function setU16(view, offset, value, endian) {
  view.setUint16(offset, value, endian === "little");
}

function setU32(view, offset, value, endian) {
  view.setUint32(offset, value, endian === "little");
}

function setI64(view, offset, value, endian) {
  view.setBigInt64(offset, value, endian === "little");
}

function concatBytes(...parts) {
  const byteLength = parts.reduce((total, part) => total + part.byteLength, 0);
  const result = new Uint8Array(byteLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.byteLength;
  }
  return result;
}

function recipeDigest(recipe) {
  return createHash("sha256").update(JSON.stringify(recipe)).digest("hex");
}

export function encodePcapGlobalHeader(variantId = "little-microseconds") {
  const variant = variantById(variantId);
  const bytes = new Uint8Array(PCAP_GLOBAL_HEADER_BYTES);
  bytes.set(variant.magic, 0);
  const view = new DataView(bytes.buffer);
  setU16(view, 4, 2, variant.endian);
  setU16(view, 6, 4, variant.endian);
  setU32(view, 8, 0, variant.endian);
  setU32(view, 12, 0, variant.endian);
  setU32(view, 16, 65_535, variant.endian);
  setU32(view, 20, 1, variant.endian);
  return bytes;
}

export function encodePcapRecordHeader({
  capturedLength,
  endian = "little",
  originalLength = capturedLength,
  recordIndex = 0,
} = {}) {
  assertEndian(endian);
  assertSafeInteger(capturedLength, "capturedLength", 0, 0xffff_ffff);
  assertSafeInteger(originalLength, "originalLength", capturedLength, 0xffff_ffff);
  assertSafeInteger(recordIndex, "recordIndex", 0, 0x6fff_ffff);
  const bytes = new Uint8Array(PCAP_RECORD_HEADER_BYTES);
  const view = new DataView(bytes.buffer);
  setU32(view, 0, 1_700_000_000 + recordIndex, endian);
  setU32(view, 4, (recordIndex * 997) % 1_000_000, endian);
  setU32(view, 8, capturedLength, endian);
  setU32(view, 12, originalLength, endian);
  return bytes;
}

function syntheticEthernetPayload(byteLength) {
  assertSafeInteger(byteLength, "payloadBytes", 0, MAX_V1_RECORD_OR_BLOCK_BYTES - 64);
  const bytes = new Uint8Array(byteLength);
  bytes.fill(0x42);
  if (byteLength >= ETHERNET_HEADER_BYTES) {
    bytes.set(
      [0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x00],
      0,
    );
  }
  return bytes;
}

export function encodePcapngSectionHeader(endian = "little") {
  assertEndian(endian);
  const bytes = new Uint8Array(PCAPNG_SECTION_HEADER_BYTES);
  const view = new DataView(bytes.buffer);
  bytes.set([0x0a, 0x0d, 0x0d, 0x0a], 0);
  setU32(view, 4, PCAPNG_SECTION_HEADER_BYTES, endian);
  setU32(view, 8, 0x1a2b_3c4d, endian);
  setU16(view, 12, 1, endian);
  setU16(view, 14, 0, endian);
  setI64(view, 16, -1n, endian);
  setU32(view, 24, PCAPNG_SECTION_HEADER_BYTES, endian);
  return bytes;
}

export function encodePcapngBlock(blockType, body, endian = "little") {
  assertEndian(endian);
  assertSafeInteger(blockType, "blockType", 0, 0xffff_ffff);
  if (!(body instanceof Uint8Array)) throw new TypeError("body must be a Uint8Array");
  if (body.byteLength % 4 !== 0) throw new RangeError("PCAPNG block bodies must be 32-bit aligned");
  const totalLength = 12 + body.byteLength;
  assertSafeInteger(totalLength, "PCAPNG block length", 12, 0xffff_ffff);
  const bytes = new Uint8Array(totalLength);
  const view = new DataView(bytes.buffer);
  setU32(view, 0, blockType, endian);
  setU32(view, 4, totalLength, endian);
  bytes.set(body, 8);
  setU32(view, totalLength - 4, totalLength, endian);
  return bytes;
}

export function encodePcapngInterfaceBlock(endian = "little") {
  const body = new Uint8Array(8);
  const view = new DataView(body.buffer);
  setU16(view, 0, 1, endian);
  setU16(view, 2, 0, endian);
  setU32(view, 4, 65_535, endian);
  return encodePcapngBlock(1, body, endian);
}

export function encodePcapngEnhancedPacket({ endian = "little", payload, recordIndex = 0 } = {}) {
  assertEndian(endian);
  if (!(payload instanceof Uint8Array)) throw new TypeError("payload must be a Uint8Array");
  assertSafeInteger(recordIndex, "recordIndex", 0, 0xffff_ffff);
  const paddedPayloadLength = Math.ceil(payload.byteLength / 4) * 4;
  const body = new Uint8Array(20 + paddedPayloadLength);
  const view = new DataView(body.buffer);
  setU32(view, 0, 0, endian);
  setU32(view, 4, 0, endian);
  setU32(view, 8, recordIndex, endian);
  setU32(view, 12, payload.byteLength, endian);
  setU32(view, 16, payload.byteLength, endian);
  body.set(payload, 20);
  return encodePcapngBlock(6, body, endian);
}

export function identifyCaptureMagic(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new TypeError("bytes must be a Uint8Array");
  if (bytes.byteLength < 4) return { format: "short" };
  for (const variant of PCAP_VARIANTS) {
    if (variant.magic.every((value, index) => bytes[index] === value)) {
      return {
        endian: variant.endian,
        format: "pcap",
        fractionResolution: variant.fractionResolution,
        variant: variant.id,
      };
    }
  }
  if (bytes[0] === 0x0a && bytes[1] === 0x0d && bytes[2] === 0x0d && bytes[3] === 0x0a) {
    let endian;
    if (bytes.byteLength >= 12) {
      const bom = Array.from(bytes.subarray(8, 12));
      if (bom.join(",") === "77,60,43,26") endian = "little";
      if (bom.join(",") === "26,43,60,77") endian = "big";
    }
    return { endian, format: "pcapng" };
  }
  return { format: "unsupported" };
}

async function writeNewFile(path, callback) {
  const handle = await open(path, "wx", 0o600);
  const hash = createHash("sha256");
  let byteLength = 0;
  let largestWriteBytes = 0;
  const write = async (bytes) => {
    if (!(bytes instanceof Uint8Array)) throw new TypeError("fixture writes require Uint8Array");
    let written = 0;
    while (written < bytes.byteLength) {
      const result = await handle.write(bytes, written, bytes.byteLength - written, null);
      if (result.bytesWritten <= 0) throw new Error(`short fixture write for ${path}`);
      const part = bytes.subarray(written, written + result.bytesWritten);
      hash.update(part);
      written += result.bytesWritten;
      byteLength += result.bytesWritten;
    }
    largestWriteBytes = Math.max(largestWriteBytes, bytes.byteLength);
  };
  try {
    await callback({ handle, write });
  } finally {
    await handle.close();
  }
  return { byteLength, largestWriteBytes, sha256: hash.digest("hex") };
}

export async function writePcapFile(
  path,
  {
    maxChunkBytes = DEFAULT_MAX_WRITE_CHUNK_BYTES,
    payloadBytes = 240,
    recordCount = 8,
    variant = "little-microseconds",
  } = {},
) {
  const selectedVariant = variantById(variant);
  assertSafeInteger(recordCount, "recordCount", 0, 1_000_000);
  assertSafeInteger(payloadBytes, "payloadBytes", 0, MAX_V1_RECORD_OR_BLOCK_BYTES - 64);
  assertSafeInteger(maxChunkBytes, "maxChunkBytes", 1, 64 * MIB);
  const payload = syntheticEthernetPayload(payloadBytes);
  const recordBytes = PCAP_RECORD_HEADER_BYTES + payloadBytes;
  const recordsPerChunk = Math.max(1, Math.floor(maxChunkBytes / Math.max(1, recordBytes)));
  const result = await writeNewFile(path, async ({ write }) => {
    await write(encodePcapGlobalHeader(variant));
    for (let first = 0; first < recordCount; first += recordsPerChunk) {
      const count = Math.min(recordsPerChunk, recordCount - first);
      const chunk = new Uint8Array(count * recordBytes);
      for (let local = 0; local < count; local += 1) {
        const offset = local * recordBytes;
        chunk.set(
          encodePcapRecordHeader({
            capturedLength: payloadBytes,
            endian: selectedVariant.endian,
            recordIndex: first + local,
          }),
          offset,
        );
        chunk.set(payload, offset + PCAP_RECORD_HEADER_BYTES);
      }
      await write(chunk);
    }
  });
  return { ...result, payloadBytes, recordCount, variant };
}

export async function writePcapngFile(
  path,
  {
    endian = "little",
    maxChunkBytes = DEFAULT_MAX_WRITE_CHUNK_BYTES,
    payloadBytes = 240,
    recordCount = 8,
  } = {},
) {
  assertEndian(endian);
  assertSafeInteger(recordCount, "recordCount", 0, 1_000_000);
  assertSafeInteger(payloadBytes, "payloadBytes", 0, MAX_V1_RECORD_OR_BLOCK_BYTES - 64);
  assertSafeInteger(maxChunkBytes, "maxChunkBytes", 1, 64 * MIB);
  const payload = syntheticEthernetPayload(payloadBytes);
  const packetBlockBytes = encodePcapngEnhancedPacket({
    endian,
    payload,
    recordIndex: 0,
  }).byteLength;
  const recordsPerChunk = Math.max(1, Math.floor(maxChunkBytes / packetBlockBytes));
  const result = await writeNewFile(path, async ({ write }) => {
    await write(encodePcapngSectionHeader(endian));
    await write(encodePcapngInterfaceBlock(endian));
    for (let first = 0; first < recordCount; first += recordsPerChunk) {
      const count = Math.min(recordsPerChunk, recordCount - first);
      const chunk = new Uint8Array(count * packetBlockBytes);
      for (let local = 0; local < count; local += 1) {
        chunk.set(
          encodePcapngEnhancedPacket({ endian, payload, recordIndex: first + local }),
          local * packetBlockBytes,
        );
      }
      await write(chunk);
    }
  });
  return { ...result, endian, payloadBytes, recordCount };
}

export async function writeSupportedLargePcap(
  path,
  {
    maxChunkBytes = DEFAULT_MAX_WRITE_CHUNK_BYTES,
    payloadBytes = MIB,
    targetBytes = DEFAULT_SUPPORTED_LARGE_TARGET_BYTES,
  } = {},
) {
  assertSafeInteger(
    targetBytes,
    "targetBytes",
    PCAP_GLOBAL_HEADER_BYTES + 1,
    MAX_V1_CAPTURE_BYTES - 1,
  );
  assertSafeInteger(payloadBytes, "payloadBytes", 1, MAX_V1_RECORD_OR_BLOCK_BYTES - 64);
  const recordBytes = PCAP_RECORD_HEADER_BYTES + payloadBytes;
  const recordCount = Math.floor((targetBytes - PCAP_GLOBAL_HEADER_BYTES) / recordBytes);
  if (recordCount < 1) throw new RangeError("targetBytes must admit at least one complete record");
  return writePcapFile(path, {
    maxChunkBytes,
    payloadBytes,
    recordCount,
    variant: "little-microseconds",
  });
}

export async function writeSparseArchitectureOversizePcap(
  path,
  { minimumBytes = ADR_0001_LARGE_CAPTURE_MINIMUM_BYTES } = {},
) {
  assertSafeInteger(
    minimumBytes,
    "minimumBytes",
    ADR_0001_LARGE_CAPTURE_MINIMUM_BYTES,
    Number.MAX_SAFE_INTEGER,
  );
  const recordCount = Math.ceil(
    (minimumBytes - PCAP_GLOBAL_HEADER_BYTES) / PCAP_RECORD_HEADER_BYTES,
  );
  const byteLength = PCAP_GLOBAL_HEADER_BYTES + recordCount * PCAP_RECORD_HEADER_BYTES;
  const handle = await open(path, "wx", 0o600);
  try {
    await handle.writeFile(encodePcapGlobalHeader("little-microseconds"));
    await handle.truncate(byteLength);
  } finally {
    await handle.close();
  }
  return {
    byteLength,
    largestWriteBytes: PCAP_GLOBAL_HEADER_BYTES,
    recordCount,
    sha256: null,
    sparse: true,
  };
}

export function createHostileFixtureBytes() {
  const littleHeader = encodePcapGlobalHeader("little-microseconds");
  const truncatedRecordHeader = encodePcapRecordHeader({
    capturedLength: 128,
    endian: "little",
    originalLength: 128,
  });
  const oversizedRecordHeader = encodePcapRecordHeader({
    capturedLength: MAX_V1_RECORD_OR_BLOCK_BYTES + 1,
    endian: "little",
    originalLength: MAX_V1_RECORD_OR_BLOCK_BYTES + 1,
  });
  const pcapngSection = encodePcapngSectionHeader("little");
  const malformedBom = pcapngSection.slice();
  malformedBom.set([0xff, 0xff, 0xff, 0xff], 8);
  const malformedFooter = concatBytes(pcapngSection, encodePcapngInterfaceBlock("little"));
  new DataView(malformedFooter.buffer).setUint32(malformedFooter.byteLength - 4, 24, true);
  const oversizedPcapngBlock = new Uint8Array(12);
  const oversizedPcapngView = new DataView(oversizedPcapngBlock.buffer);
  oversizedPcapngView.setUint32(0, 6, true);
  oversizedPcapngView.setUint32(4, MAX_V1_RECORD_OR_BLOCK_BYTES + 4, true);
  oversizedPcapngView.setUint32(8, MAX_V1_RECORD_OR_BLOCK_BYTES + 4, true);

  const optionCount = 4_097;
  const optionBody = new Uint8Array(8 + optionCount * 4 + 4);
  const optionView = new DataView(optionBody.buffer);
  optionView.setUint16(0, 1, true);
  optionView.setUint16(2, 0, true);
  optionView.setUint32(4, 65_535, true);
  for (let index = 0; index < optionCount; index += 1) {
    const offset = 8 + index * 4;
    optionView.setUint16(offset, 1, true);
    optionView.setUint16(offset + 2, 0, true);
  }

  const denseRecordCount = 4_096;
  const denseRecords = new Uint8Array(denseRecordCount * PCAP_RECORD_HEADER_BYTES);
  for (let index = 0; index < denseRecordCount; index += 1) {
    denseRecords.set(
      encodePcapRecordHeader({ capturedLength: 0, endian: "little", recordIndex: index }),
      index * PCAP_RECORD_HEADER_BYTES,
    );
  }

  const randomMagic = new Uint8Array(64);
  let randomState = 0x51f1_5eed;
  for (let index = 0; index < randomMagic.byteLength; index += 1) {
    randomState = (Math.imul(randomState, 1_664_525) + 1_013_904_223) >>> 0;
    randomMagic[index] = randomState >>> 24;
  }
  randomMagic.set([0xde, 0xad, 0xbe, 0xef], 0);

  return Object.freeze({
    "dense-packet-admission.pcap": concatBytes(littleHeader, denseRecords),
    "empty.capture": new Uint8Array(),
    "malformed-pcapng-bom.pcapng": malformedBom,
    "malformed-pcapng-footer.pcapng": malformedFooter,
    "option-dense-pcapng.pcapng": concatBytes(
      pcapngSection,
      encodePcapngBlock(1, optionBody, "little"),
    ),
    "oversized-declared-pcap-record.pcap": concatBytes(littleHeader, oversizedRecordHeader),
    "oversized-declared-pcapng-block.pcapng": concatBytes(pcapngSection, oversizedPcapngBlock),
    "random-magic.capture": randomMagic,
    "short-pcap-magic.pcap": littleHeader.slice(0, 3),
    "truncated-pcap-header.pcap": littleHeader.slice(0, 12),
    "truncated-pcap-record.pcap": concatBytes(
      littleHeader,
      truncatedRecordHeader,
      new Uint8Array([0x00, 0x01, 0x02, 0x03]),
    ),
    "truncated-pcapng-section.pcapng": pcapngSection.slice(0, -4),
  });
}

function assertTemporaryOutputDirectory(outputDirectory) {
  const resolvedOutput = resolve(outputDirectory);
  const resolvedTemporaryRoot = resolve(tmpdir());
  if (
    resolvedOutput === resolvedTemporaryRoot ||
    !resolvedOutput.startsWith(`${resolvedTemporaryRoot}${sep}`)
  ) {
    throw new Error(
      `fixture output must be a child of the OS temporary directory: ${resolvedTemporaryRoot}`,
    );
  }
  return resolvedOutput;
}

async function prepareEmptyTemporaryDirectory(outputDirectory) {
  const resolvedOutput = assertTemporaryOutputDirectory(outputDirectory);
  await mkdir(resolvedOutput, { recursive: true });
  const [canonicalOutput, canonicalTemporaryRoot] = await Promise.all([
    realpath(resolvedOutput),
    realpath(tmpdir()),
  ]);
  if (!canonicalOutput.startsWith(`${canonicalTemporaryRoot}${sep}`)) {
    throw new Error(`fixture output resolves outside OS temporary storage: ${canonicalOutput}`);
  }
  const existing = await readdir(canonicalOutput);
  if (existing.length !== 0) {
    throw new Error(`fixture output directory is not empty: ${canonicalOutput}`);
  }
  return canonicalOutput;
}

async function writeByteFixture(path, bytes) {
  await writeFile(path, bytes, { flag: "wx", mode: 0o600 });
  return {
    byteLength: bytes.byteLength,
    largestWriteBytes: bytes.byteLength,
    sha256: createHash("sha256").update(bytes).digest("hex"),
  };
}

function fixtureEntry({ expectedOutcome, fileName, format, intent, recipe, result }) {
  return {
    expectedOutcome,
    fileName,
    format,
    intent,
    largestWriteBytes: result.largestWriteBytes,
    recipe,
    recipeSha256: recipeDigest(recipe),
    sha256: result.sha256,
    sizeBytes: result.byteLength,
    storage: result.sparse === true ? "sparse" : "materialized",
  };
}

export async function createTemporaryFixtureDirectory(prefix = "wirelens-browser-ingestion-") {
  if (typeof prefix !== "string" || prefix.length === 0 || prefix.includes(sep)) {
    throw new TypeError("temporary fixture prefix must be one path segment");
  }
  return mkdtemp(join(tmpdir(), prefix));
}

export async function generateBrowserIngestionFixtures({
  includeArchitectureOversize = true,
  mediumPayloadBytes = 240,
  mediumRecords = 4_096,
  outputDirectory,
  supportedLargePayloadBytes = MIB,
  supportedLargeTargetBytes = DEFAULT_SUPPORTED_LARGE_TARGET_BYTES,
} = {}) {
  if (outputDirectory === undefined) {
    throw new TypeError("outputDirectory is required; use createTemporaryFixtureDirectory()");
  }
  assertSafeInteger(mediumRecords, "mediumRecords", 1, 1_000_000);
  assertSafeInteger(mediumPayloadBytes, "mediumPayloadBytes", 1, MAX_V1_RECORD_OR_BLOCK_BYTES - 64);
  const output = await prepareEmptyTemporaryDirectory(outputDirectory);
  const fixtures = [];

  const addGenerated = async ({ expectedOutcome, fileName, format, intent, recipe, write }) => {
    const result = await write(join(output, fileName));
    fixtures.push(fixtureEntry({ expectedOutcome, fileName, format, intent, recipe, result }));
  };

  for (const variant of PCAP_VARIANTS) {
    const fileName = `small-pcap-${variant.id}.pcap`;
    const recipe = { kind: "pcap", payloadBytes: 64, recordCount: 8, variant: variant.id };
    await addGenerated({
      expectedOutcome: "success",
      fileName,
      format: "pcap",
      intent: `Recognize ${variant.endian}-endian PCAP with ${variant.fractionResolution} timestamps`,
      recipe,
      write: (path) => writePcapFile(path, recipe),
    });
  }

  for (const endian of ["little", "big"]) {
    const fileName = `small-pcapng-${endian}.pcapng`;
    const recipe = { endian, kind: "pcapng", payloadBytes: 64, recordCount: 8 };
    await addGenerated({
      expectedOutcome: "success",
      fileName,
      format: "pcapng",
      intent: `Recognize ${endian}-endian PCAPNG section and packet blocks`,
      recipe,
      write: (path) => writePcapngFile(path, recipe),
    });
  }

  const mediumPcapRecipe = {
    kind: "pcap",
    payloadBytes: mediumPayloadBytes,
    recordCount: mediumRecords,
    variant: "little-microseconds",
  };
  await addGenerated({
    expectedOutcome: "success",
    fileName: "medium.pcap",
    format: "pcap",
    intent:
      "Exercise multi-step file read and parse progress without violating proportional packet admission",
    recipe: mediumPcapRecipe,
    write: (path) => writePcapFile(path, mediumPcapRecipe),
  });

  const mediumPcapngRecipe = {
    endian: "little",
    kind: "pcapng",
    payloadBytes: mediumPayloadBytes,
    recordCount: mediumRecords,
  };
  await addGenerated({
    expectedOutcome: "success",
    fileName: "medium.pcapng",
    format: "pcapng",
    intent: "Exercise multi-step PCAPNG file read and parse progress",
    recipe: mediumPcapngRecipe,
    write: (path) => writePcapngFile(path, mediumPcapngRecipe),
  });

  const hostileIntent = {
    "dense-packet-admission.pcap": [
      "resource_limit",
      "Exceed proportional packet admission with zero-length records",
    ],
    "empty.capture": [
      "structured_rejection",
      "Reject an empty selection without guessing from its name",
    ],
    "malformed-pcapng-bom.pcapng": [
      "malformed_capture",
      "Reject an invalid PCAPNG byte-order magic",
    ],
    "malformed-pcapng-footer.pcapng": [
      "structured_diagnostic",
      "Detect a PCAPNG leading/trailing block-length mismatch",
    ],
    "option-dense-pcapng.pcapng": [
      "resource_limit",
      "Bound decoded PCAPNG option items within one block",
    ],
    "oversized-declared-pcap-record.pcap": [
      "resource_limit",
      "Reject an oversized declared PCAP record before allocation",
    ],
    "oversized-declared-pcapng-block.pcapng": [
      "resource_limit",
      "Reject an oversized declared PCAPNG block before allocation",
    ],
    "random-magic.capture": [
      "unsupported_format",
      "Reject deterministic non-capture bytes independent of extension",
    ],
    "short-pcap-magic.pcap": [
      "truncated_capture",
      "Reject a partial legacy magic/header truthfully",
    ],
    "truncated-pcap-header.pcap": [
      "truncated_capture",
      "Reject an incomplete legacy global header",
    ],
    "truncated-pcap-record.pcap": [
      "success_with_warning",
      "Preserve a bounded diagnostic for a truncated packet record",
    ],
    "truncated-pcapng-section.pcapng": [
      "truncated_capture",
      "Reject an incomplete PCAPNG section header",
    ],
  };
  for (const [fileName, bytes] of Object.entries(createHostileFixtureBytes())) {
    const [expectedOutcome, intent] = hostileIntent[fileName];
    const recipe = { kind: "hostile-bytes", name: fileName };
    await addGenerated({
      expectedOutcome,
      fileName,
      format: fileName.endsWith(".pcapng")
        ? "pcapng"
        : fileName.endsWith(".pcap")
          ? "pcap"
          : "unknown",
      intent,
      recipe,
      write: (path) => writeByteFixture(path, bytes),
    });
  }

  const supportedRecipe = {
    kind: "supported-large-pcap",
    payloadBytes: supportedLargePayloadBytes,
    targetBytes: supportedLargeTargetBytes,
  };
  await addGenerated({
    expectedOutcome: "success",
    fileName: "supported-large.pcap",
    format: "pcap",
    intent: "Exercise the successful large-file path below the v1 256 MiB capture ceiling",
    recipe: supportedRecipe,
    write: (path) => writeSupportedLargePcap(path, supportedRecipe),
  });

  if (includeArchitectureOversize) {
    const oversizeRecipe = {
      kind: "sparse-size-guard-pcap",
      minimumBytes: ADR_0001_LARGE_CAPTURE_MINIMUM_BYTES,
    };
    await addGenerated({
      expectedOutcome: "resource_limit_before_read",
      fileName: "adr-0001-oversize-guard.pcap",
      format: "pcap",
      intent:
        "Prove pre-read rejection at ADR-0001's >=500 MiB criterion; this is not a successful-import fixture",
      recipe: oversizeRecipe,
      write: (path) => writeSparseArchitectureOversizePcap(path, oversizeRecipe),
    });
  }

  const manifest = {
    fixtures,
    generator: "apps/web/tests/support/capture-fixtures.mjs",
    parameters: {
      includeArchitectureOversize,
      mediumPayloadBytes,
      mediumRecords,
      supportedLargePayloadBytes,
      supportedLargeTargetBytes,
    },
    provenance: {
      containsObservedTraffic: false,
      encoding: "WireLens-authored deterministic headers and repeated synthetic payload byte 0x42",
      license: "MIT (WireLens repository license)",
      source: "Generated locally from this repository; no packet capture was observed or copied",
    },
    schemaVersion: 1,
  };
  await writeFile(join(output, "fixture-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, {
    flag: "wx",
    mode: 0o600,
  });
  return { manifest, outputDirectory: output };
}

export async function describeFixtureStorage(path) {
  const details = await stat(path);
  return {
    allocatedBytes: typeof details.blocks === "number" ? details.blocks * 512 : undefined,
    sizeBytes: details.size,
  };
}
