# Wasm boundary API v1

This is the reviewed public signature snapshot for ADR-0007, issue #9, and the additive packet-inspection operations from issue #16. The production build regenerates `apps/web/src/boundary/generated/wirelens_wasm_boundary.d.ts`; `verify:contract` reads the marked snapshot below and checks every signature against that declaration. Generated initialization boilerplate remains outside the product API snapshot because it is reproducible from the pinned Rust and `wasm-bindgen` toolchain.

## Raw `wasm-bindgen` exports

<!-- generated-signatures:start -->
```ts
export function apiVersion(): number;
export function batchSchemaVersion(): number;
export function detailSchemaVersion(): number;
export function capabilities(): any;
free(): void;
[Symbol.dispose](): void;
constructor(api_version: number);
beginImport(input: Uint8Array): bigint;
stepImport(raw_handle: bigint, max_records: number, max_bytes: number): any;
cancelImport(raw_handle: bigint): any;
dispose(raw_handle: bigint): any;
openPacketCursor(raw_dataset: bigint, start_row: number): bigint;
readPacketBatch(raw_cursor: bigint, schema_version: number, max_rows: number, max_bytes: number): Uint8Array;
commitPacketBatch(raw_cursor: bigint, schema_version: number, start_row: bigint, next_row: bigint): void;
discardPacketBatch(raw_cursor: bigint, schema_version: number, start_row: bigint, next_row: bigint): void;
readPacketDetail(raw_dataset: bigint, packet_id: number, detail_schema_version: number, max_bytes: number): Uint8Array;
readPacketEvidence(raw_dataset: bigint, packet_id: number, relative_start: number, max_bytes: number): Uint8Array;
correlatePacketRange(raw_dataset: bigint, packet_id: number, relative_start: number, length: number): Uint32Array;
readEvidence(raw_dataset: bigint, start_high: number, start_low: number, length: number): Uint8Array;
resourceStats(): any;
wasmMemoryBytes(): bigint;
```
<!-- generated-signatures:end -->

The raw `any` results are not passed to the application unchecked. The module worker validates and normalizes them into the committed `Capabilities`, `ImportStepResult`, `CancellationResult`, `DisposalResult`, `BoundaryFailure`, `BoundaryWarning`, and `ResourceStats` interfaces in `web/worker-contract.ts`.

## Worker command API

Command API version 1 supports these request operations:

```text
metadata
begin_import
step_import
cancel_import
dispose
open_packet_cursor
read_packet_batch
commit_packet_batch
discard_packet_batch
read_packet_detail
read_packet_evidence
correlate_packet_range
read_evidence
resource_stats
wasm_memory_bytes
ack_transfer
shutdown
```

Every request carries `apiVersion` and `requestId`. Packet-batch commit/discard commands identify the transfer request they resolve. Packet rows and packet details use separate schema versions so either binary layout can evolve without invalidating the other. Binary results use transferable `Uint8Array` or `Uint32Array` payloads; all other responses use the validated control envelope in `web/worker-contract.ts`. Command API and binary schema versions evolve independently as specified by ADR-0007.
