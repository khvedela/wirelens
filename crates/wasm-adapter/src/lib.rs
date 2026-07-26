//! Platform-neutral internals for the `WireLens` worker/WebAssembly boundary.
//!
//! The public seam deliberately contains no file, browser, JavaScript, or
//! `wasm-bindgen` API. [`BoundaryState`] owns bounded incremental capture
//! imports and publishes validated [`packet_core::CaptureDataset`] values. A
//! thin Wasm export layer can represent [`BoundaryHandle`] as JavaScript
//! `BigInt` or as [`HandleWords`], copy a bounded [`EvidenceView`] during the
//! call that borrowed it, and expose [`PacketBatch::bytes`] as a typed byte
//! array.
//!
//! Import steps and cursor reads are intentionally bounded, giving a worker
//! explicit scheduling and cancellation checkpoints. Dataset disposal
//! cascades to dependent cursors so abandoned requests retain no query state.
//!
//! No Rust structure layout is part of the wire contract. Packet batches are
//! encoded explicitly in little-endian order, and exact 64-bit timestamp and
//! evidence values are never converted through JSON or a JavaScript `Number`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod batch;
mod boundary;
mod error;
mod handle;

#[cfg(target_arch = "wasm32")]
mod web;

pub use batch::{
    BATCH_SCHEMA_VERSION, BatchElementType, ColumnDescriptor, PacketBatch, PacketBatchColumn,
};
pub use boundary::{
    API_VERSION, BoundaryState, CAPTURE_BYTES_PER_PACKET, CAPTURE_PACKET_BASE_ALLOWANCE,
    DatasetDiagnostic, DisposeReport, DisposeStatus, EvidenceView, ImportAdmission, ImportAdvance,
    ImportCancelReport, ImportPhase, ImportProgressSnapshot, MAX_CAPTURE_BLOCK_BYTES,
    MAX_CAPTURE_BYTES, MAX_CAPTURE_DECODED_ITEMS_PER_BLOCK, MAX_CAPTURE_DECODED_ITEMS_PER_STEP,
    MAX_CAPTURE_DIAGNOSTICS, MAX_CAPTURE_INTERFACES, MAX_CAPTURE_PACKETS, MAX_CAPTURE_SECTIONS,
    MAX_CAPTURE_STRING_BYTES, MAX_DATASET_HANDLES, MAX_EVIDENCE_BYTES, MAX_IMPORT_HANDLES,
    MAX_IMPORT_STEP_BYTES, MAX_IMPORT_STEP_RECORDS, MAX_PACKET_BATCH_BYTES, MAX_PACKET_BATCH_ROWS,
    MAX_PACKET_CURSOR_HANDLES, MAX_TOTAL_CAPTURE_BYTES, MAX_TOTAL_LOGICAL_BYTES,
    MIN_PACKET_BATCH_BYTES, PublishedDataset, ResourceStats, packet_limit_for_capture,
};
pub use error::{BoundaryError, BoundaryErrorCode};
pub use handle::{BoundaryHandle, HandleKind, HandleWords};
pub use packet_core::ImportLimits;
