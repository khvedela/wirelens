import type {
  PacketByteRange,
  PacketDetailField,
  PacketDetailFieldValue,
} from "./packet-detail-boundary";
import type { PacketFieldResolution } from "./packet-detail-boundary";

export interface PacketByteSelection extends PacketByteRange {
  readonly source: "bytes" | "field";
}

export interface FieldMatchState {
  readonly fieldIds: ReadonlySet<number>;
  readonly pending: boolean;
  readonly primaryFieldId: number | null;
}

export function rangeEnd(range: PacketByteRange): number {
  return range.start + range.length;
}

export function rangeIsCaptured(range: PacketByteRange, capturedLength: number): boolean {
  return (
    Number.isSafeInteger(range.start) &&
    Number.isSafeInteger(range.length) &&
    range.start >= 0 &&
    range.length >= 0 &&
    range.start <= capturedLength &&
    range.length <= capturedLength - range.start
  );
}

export function formatByteCount(value: number): string {
  return `${value.toLocaleString("en-US")} ${value === 1 ? "byte" : "bytes"}`;
}

export function formatByteRange(range: PacketByteRange): string {
  if (range.length === 0) return `offset ${range.start.toLocaleString("en-US")} · 0 bytes`;
  const inclusiveEnd = rangeEnd(range) - 1;
  return `${range.start.toLocaleString("en-US")}–${inclusiveEnd.toLocaleString("en-US")} · ${formatByteCount(range.length)}`;
}

export function formatFieldValue(value: PacketDetailFieldValue): string {
  switch (value.kind) {
    case "none":
      return "";
    case "unsigned":
    case "signed":
      return value.value.toString();
    case "boolean":
      return value.value ? "true" : "false";
    case "string":
      return value.value;
    case "bytes":
      return `bytes ${formatByteRange(value.range)}`;
  }
}

export function fieldAccessibleName(field: PacketDetailField): string {
  const value = formatFieldValue(field.value);
  const valueText = value.length === 0 ? "" : `, value ${value}`;
  return `${field.name}${valueText}, ${formatByteRange(field.byteRange)}`;
}

export function selectedFieldName(
  fields: readonly PacketDetailField[],
  fieldId: number | null,
): string | undefined {
  if (fieldId === null) return undefined;
  return fields.find(({ id }) => id === fieldId)?.name;
}

/** Converts a correlation reply only when every identity belongs to the displayed detail. */
export function validatedFieldMatchState(
  fields: readonly PacketDetailField[],
  resolution: PacketFieldResolution,
): FieldMatchState | undefined {
  const known = new Set(fields.map(({ id }) => id));
  const fieldIds = new Set<number>();
  for (const fieldId of resolution.fieldIds) {
    if (!known.has(fieldId) || fieldIds.has(fieldId)) return undefined;
    fieldIds.add(fieldId);
  }
  const expectedPrimary = resolution.fieldIds[0] ?? null;
  if (resolution.primaryFieldId !== expectedPrimary) return undefined;
  return { fieldIds, pending: false, primaryFieldId: resolution.primaryFieldId };
}
