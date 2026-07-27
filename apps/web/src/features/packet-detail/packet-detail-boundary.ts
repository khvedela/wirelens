import type {
  PacketByteRange,
  PacketDetail,
  PacketDetailField,
  PacketDetailFieldValue,
  PacketDetailLayer,
} from "../../boundary/packet-detail";

/**
 * The packet-detail UI only imports the worker boundary contract here. Keeping
 * this seam small prevents presentation components from depending on the
 * binary codec or Wasm implementation details.
 */
export type {
  PacketByteRange,
  PacketDetail,
  PacketDetailField,
  PacketDetailFieldValue,
  PacketDetailLayer,
};

export interface PacketEvidencePage {
  readonly bytes: Uint8Array;
  readonly pageStart: number;
}

export interface PacketFieldResolution {
  readonly fieldIds: Uint32Array;
  readonly primaryFieldId: number | null;
}
