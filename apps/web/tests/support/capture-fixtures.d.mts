export type CaptureEndian = "big" | "little";
export type PcapFractionResolution = "microseconds" | "nanoseconds";

export interface PcapVariant {
  readonly endian: CaptureEndian;
  readonly fractionResolution: PcapFractionResolution;
  readonly id:
    | "big-microseconds"
    | "big-nanoseconds"
    | "little-microseconds"
    | "little-nanoseconds";
  readonly magic: readonly number[];
}

export interface WriteResult {
  byteLength: number;
  largestWriteBytes: number;
  sha256: null | string;
}

export interface GeneratedFixture {
  expectedOutcome: string;
  fileName: string;
  format: "pcap" | "pcapng" | "unknown";
  intent: string;
  largestWriteBytes: number;
  recipe: Readonly<Record<string, unknown>>;
  recipeSha256: string;
  sha256: null | string;
  sizeBytes: number;
  storage: "materialized" | "sparse";
}

export interface FixtureManifest {
  fixtures: GeneratedFixture[];
  generator: string;
  parameters: {
    includeArchitectureOversize: boolean;
    mediumPayloadBytes: number;
    mediumRecords: number;
    supportedLargePayloadBytes: number;
    supportedLargeTargetBytes: number;
  };
  provenance: {
    containsObservedTraffic: false;
    encoding: string;
    license: string;
    source: string;
  };
  schemaVersion: 1;
}

export interface GenerateFixtureOptions {
  includeArchitectureOversize?: boolean;
  mediumPayloadBytes?: number;
  mediumRecords?: number;
  outputDirectory: string;
  supportedLargePayloadBytes?: number;
  supportedLargeTargetBytes?: number;
}

export const KIB: number;
export const MIB: number;
export const MAX_V1_CAPTURE_BYTES: number;
export const MAX_V1_RECORD_OR_BLOCK_BYTES: number;
export const DEFAULT_SUPPORTED_LARGE_TARGET_BYTES: number;
export const RECOMMENDED_NEAR_CAP_TARGET_BYTES: number;
export const ADR_0001_LARGE_CAPTURE_MINIMUM_BYTES: number;
export const PCAP_VARIANTS: readonly PcapVariant[];

export function encodePcapGlobalHeader(variantId?: PcapVariant["id"]): Uint8Array;
export function encodePcapRecordHeader(options: {
  capturedLength: number;
  endian?: CaptureEndian;
  originalLength?: number;
  recordIndex?: number;
}): Uint8Array;
export function encodePcapngSectionHeader(endian?: CaptureEndian): Uint8Array;
export function encodePcapngBlock(
  blockType: number,
  body: Uint8Array,
  endian?: CaptureEndian,
): Uint8Array;
export function encodePcapngInterfaceBlock(endian?: CaptureEndian): Uint8Array;
export function encodePcapngEnhancedPacket(options: {
  endian?: CaptureEndian;
  payload: Uint8Array;
  recordIndex?: number;
}): Uint8Array;
export function identifyCaptureMagic(bytes: Uint8Array):
  | { format: "short" | "unsupported" }
  | {
      endian: CaptureEndian;
      format: "pcap";
      fractionResolution: PcapFractionResolution;
      variant: PcapVariant["id"];
    }
  | { endian: CaptureEndian | undefined; format: "pcapng" };

export function writePcapFile(
  path: string,
  options?: {
    maxChunkBytes?: number;
    payloadBytes?: number;
    recordCount?: number;
    variant?: PcapVariant["id"];
  },
): Promise<WriteResult & { payloadBytes: number; recordCount: number; variant: string }>;
export function writePcapngFile(
  path: string,
  options?: {
    endian?: CaptureEndian;
    maxChunkBytes?: number;
    payloadBytes?: number;
    recordCount?: number;
  },
): Promise<WriteResult & { endian: CaptureEndian; payloadBytes: number; recordCount: number }>;
export function writeSupportedLargePcap(
  path: string,
  options?: { maxChunkBytes?: number; payloadBytes?: number; targetBytes?: number },
): Promise<WriteResult & { payloadBytes: number; recordCount: number; variant: string }>;
export function writeSparseArchitectureOversizePcap(
  path: string,
  options?: { minimumBytes?: number },
): Promise<WriteResult & { recordCount: number; sparse: true }>;
export function createHostileFixtureBytes(): Readonly<Record<string, Uint8Array>>;
export function createPacketInspectorFixtureBytes(): Uint8Array;
export function createTemporaryFixtureDirectory(prefix?: string): Promise<string>;
export function generateBrowserIngestionFixtures(
  options: GenerateFixtureOptions,
): Promise<{ manifest: FixtureManifest; outputDirectory: string }>;
export function describeFixtureStorage(
  path: string,
): Promise<{ allocatedBytes: number | undefined; sizeBytes: number }>;
