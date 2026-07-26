const GLOBAL_HEADER_BYTES = 24;
const RECORD_HEADER_BYTES = 16;
const ETHERNET_HEADER_BYTES = 14;
const MAX_SYNTHETIC_CAPTURE_BYTES = 512 * 1024 * 1024;

export interface SyntheticCaptureOptions {
  payloadBytes?: number;
  records?: number;
}

export interface OptionDensePcapngOptions {
  blocks?: number;
  itemsPerBlock?: number;
}

/** Generates a deterministic little-endian PCAP entirely in memory. */
export function createSyntheticPcap(options: SyntheticCaptureOptions = {}): Uint8Array {
  const records = options.records ?? 32;
  const payloadBytes = options.payloadBytes ?? 50;
  if (!Number.isSafeInteger(records) || records < 0 || records > 1_000_000) {
    throw new RangeError("synthetic record count is out of range");
  }
  if (!Number.isSafeInteger(payloadBytes) || payloadBytes < 0 || payloadBytes > 65_521) {
    throw new RangeError("synthetic payload size is out of range");
  }

  const capturedLength = ETHERNET_HEADER_BYTES + payloadBytes;
  const totalLength = GLOBAL_HEADER_BYTES + records * (RECORD_HEADER_BYTES + capturedLength);
  if (!Number.isSafeInteger(totalLength) || totalLength > MAX_SYNTHETIC_CAPTURE_BYTES) {
    throw new RangeError("synthetic capture exceeds the harness memory cap");
  }
  const bytes = new Uint8Array(totalLength);
  const view = new DataView(bytes.buffer);

  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(8, 0, true);
  view.setUint32(12, 0, true);
  view.setUint32(16, 65_535, true);
  view.setUint32(20, 1, true);

  let offset = GLOBAL_HEADER_BYTES;
  for (let index = 0; index < records; index += 1) {
    view.setUint32(offset, 1_700_000_000 + index, true);
    view.setUint32(offset + 4, (index * 997) % 1_000_000, true);
    view.setUint32(offset + 8, capturedLength, true);
    view.setUint32(offset + 12, capturedLength, true);
    offset += RECORD_HEADER_BYTES;

    // Keep boundary/performance data higher-layer neutral as more decoders
    // arrive. Dedicated decoder fixtures carry valid IPv4/IPv6 payloads.
    bytes.set([0x02, 0, 0, 0, 0, 1, 0x02, 0, 0, 0, 0, 2, 0x88, 0xb5], offset);
    bytes.fill(
      index & 0xff,
      offset + ETHERNET_HEADER_BYTES,
      offset + ETHERNET_HEADER_BYTES + payloadBytes,
    );
    offset += capturedLength;
  }
  return bytes;
}

/** Generates a valid header followed by a record whose declared bytes are truncated. */
export function createTruncatedPcap(): Uint8Array {
  const bytes = createSyntheticPcap({ payloadBytes: 1, records: 1 }).slice(0, GLOBAL_HEADER_BYTES + 18);
  new DataView(bytes.buffer).setUint32(GLOBAL_HEADER_BYTES + 8, 128, true);
  new DataView(bytes.buffer).setUint32(GLOBAL_HEADER_BYTES + 12, 128, true);
  return bytes;
}

/** Generates PCAPNG interface blocks whose individually valid options form a hostile work tail. */
export function createOptionDensePcapng(options: OptionDensePcapngOptions = {}): Uint8Array {
  const blocks = options.blocks ?? 513;
  const itemsPerBlock = options.itemsPerBlock ?? 4_096;
  if (!Number.isSafeInteger(blocks) || blocks < 1 || blocks > 16_000) {
    throw new RangeError("option-dense block count is out of range");
  }
  if (!Number.isSafeInteger(itemsPerBlock) || itemsPerBlock < 1 || itemsPerBlock > 4_096) {
    throw new RangeError("option-dense item count is out of range");
  }
  const interfaceBlockBytes = 20 + itemsPerBlock * 4;
  const totalLength = 28 + blocks * interfaceBlockBytes;
  if (!Number.isSafeInteger(totalLength) || totalLength > MAX_SYNTHETIC_CAPTURE_BYTES) {
    throw new RangeError("option-dense capture exceeds the harness memory cap");
  }

  const bytes = new Uint8Array(totalLength);
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x0a0d_0d0a, true);
  view.setUint32(4, 28, true);
  view.setUint32(8, 0x1a2b_3c4d, true);
  view.setUint16(12, 1, true);
  view.setUint16(14, 0, true);
  view.setBigInt64(16, -1n, true);
  view.setUint32(24, 28, true);

  let offset = 28;
  for (let block = 0; block < blocks; block += 1) {
    view.setUint32(offset, 1, true);
    view.setUint32(offset + 4, interfaceBlockBytes, true);
    view.setUint16(offset + 8, 1, true);
    view.setUint16(offset + 10, 0, true);
    view.setUint32(offset + 12, 65_535, true);
    let optionOffset = offset + 16;
    for (let item = 0; item < itemsPerBlock; item += 1) {
      view.setUint16(optionOffset, 1, true);
      view.setUint16(optionOffset + 2, 0, true);
      optionOffset += 4;
    }
    view.setUint32(offset + interfaceBlockBytes - 4, interfaceBlockBytes, true);
    offset += interfaceBlockBytes;
  }
  return bytes;
}
