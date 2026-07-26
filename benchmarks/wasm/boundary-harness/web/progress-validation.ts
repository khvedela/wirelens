import type { ImportStepResult, ProgressSnapshot } from "./worker-contract";

function asU64(high: number, low: number): bigint {
  return (BigInt(high) << 32n) | BigInt(low);
}

export function progressCountersAreOrdered(progress: ProgressSnapshot): boolean {
  return (
    asU64(progress.bytesConsumedHi, progress.bytesConsumedLo) <=
      asU64(progress.totalBytesHi, progress.totalBytesLo) &&
    asU64(progress.packetsRetainedHi, progress.packetsRetainedLo) <=
      asU64(progress.recordsHi, progress.recordsLo)
  );
}

export function importStateMatchesPhase(
  state: ImportStepResult["state"],
  phase: ProgressSnapshot["phase"],
): boolean {
  switch (state) {
    case "cancelled":
      return phase === "cancelled";
    case "complete":
      return phase === "complete";
    case "in_progress":
      return phase === "parsing" || phase === "validating";
  }
}

export function cancellationPhaseIsTerminal(progress: ProgressSnapshot): boolean {
  return progress.phase === "cancelled";
}

export function exactU64IsPositive(high: number, low: number): boolean {
  return high !== 0 || low !== 0;
}
