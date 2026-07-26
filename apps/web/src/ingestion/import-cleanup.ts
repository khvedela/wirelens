import type { CancellationResult, DisposalResult } from "../boundary/worker-contract";

export interface ImportCleanupRuntime {
  cancelImport(handle: bigint): Promise<CancellationResult>;
  dispose(handle: bigint): Promise<DisposalResult>;
}

/**
 * Reclaims one boundary import handle. Cancellation is best-effort because an
 * import may already have crossed a terminal boundary, but disposal must be
 * confirmed before the caller forgets the handle.
 */
export async function reclaimImportHandle(
  runtime: ImportCleanupRuntime,
  handle: bigint,
  requestCancellation: boolean,
): Promise<CancellationResult | undefined> {
  let cancellation: CancellationResult | undefined;
  if (requestCancellation) {
    try {
      cancellation = await runtime.cancelImport(handle);
    } catch {
      // A racing terminal transition can invalidate cancellation. Confirmed
      // disposal below remains the authoritative reclamation boundary.
    }
  }
  await runtime.dispose(handle);
  return cancellation;
}
