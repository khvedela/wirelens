# Raw-byte and decoded-field correlation

WireLens links the structured field tree for one packet to the packet's captured bytes without
copying raw payloads into the canonical model. The parser continues to store absolute, half-open
capture ranges in Rust. The packet-detail boundary converts those ranges to checked `u32`
packet-relative offsets for presentation.

## Range and selection semantics

- Captured ranges are half-open: `[start, start + length)`.
- Parent and child fields may cover the same bytes, and siblings may overlap when one source byte
  carries several decoded meanings.
- Selecting a field selects its exact evidence range. Every matching range remains visible; the UI
  never hides overlapping parents or bit-level interpretations.
- A non-empty byte selection matches every positive-length field with strict overlap.
- A zero-length selection matches only zero-length fields at that exact insertion boundary. A
  zero-length field is rendered as a boundary marker and never as a byte that was not captured.
- Invalid, overflowing, or out-of-captured-data selections are rejected before any slice is formed.

Matching fields are returned in deterministic primary-first order: exact range, smallest field
containing the complete selection, greatest overlap, deepest field, shortest range, then stable
field identity. The resolver lives in platform-neutral `packet-core`; the browser does not
reimplement this ordering.

## Truncation

The detail header distinguishes on-wire truncation (`original_length > captured_length`) from a
decoder's `TRUNCATED_PROTOCOL` finding. The inspector displays only captured bytes, shows an
explicit boundary or warning, and never synthesizes missing bytes. Decoder fields and diagnostic
evidence are required to stay inside the owning packet's captured range.

## Worker and Wasm boundary

Packet rows keep their existing binary schema. Inspection uses an independent, versioned
`WLPKDT01` structure-of-arrays detail payload with hard limits of 32 layers, 1,024 fields, and 512
KiB. It contains field descriptors, scalar values, a deduplicated UTF-8 dictionary, and evidence
references, but no raw packet bytes.

Raw bytes cross the worker boundary only through explicit packet-relative evidence reads of at
most 4 KiB. The UI retains at most 16 pages (64 KiB) for the active packet and clears that cache
when the packet or dataset changes. Dataset generations and abortable request identities prevent a
late result from an old capture or selection from changing current UI state.

No correlation path performs a network request, writes packet data to browser storage, includes
payload bytes in logs, or exposes the worker-owned dataset handle to the main thread.

## UI dependencies

The raw-byte grid uses the exact-pinned TanStack Virtual React adapter so a maximum-size packet does
not mount one DOM row per 16 bytes. The decoded hierarchy uses exact-pinned Headless Tree core and
React adapters for keyboard and ARIA tree behavior. Both are MIT-licensed, remain confined to
`apps/web`, and do not affect the platform-neutral Rust dependency graph. Their notices are in
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

The focused inspector added for protocol evidence is deliberately not the full packet-table,
filtering, or multi-pane investigation shell planned in later epics.

## Verification

Synthetic tests cover packet-relative conversion, nested and equal ranges, partial overlap,
zero-length markers, truncation, invalid and overflowing selections, hostile detail batches,
packet-scoped evidence reads, stale dataset generations, and field-to-byte/byte-to-field browser
interactions in Chromium and Firefox. The 1,024-field resolver has a dependency-free benchmark;
boundary and browser evidence must be regenerated whenever this contract or its source changes.
