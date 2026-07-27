//! Platform-neutral capture and packet primitives for `WireLens`.
//!
//! The model is index-first: capture bytes stay in one owning dataset while
//! packets, decoded fields, diagnostics, and derived layers refer to stable IDs
//! and checked byte ranges. This crate has no browser, WebAssembly, or UI types.

#![forbid(unsafe_code)]

mod correlation;
mod diagnostic;
mod field;
mod flow;
mod import;
mod model;
mod range;
mod timestamp;

pub use correlation::{
    CorrelationError, PacketFieldMatch, PacketFieldPath, PacketFieldSelection, PacketRelativeRange,
};
pub use diagnostic::{Diagnostic, DiagnosticCode, DiagnosticScope, Recovery, Severity};
pub use field::{DecodedField, FieldId, FieldValue, LayerFact, StringId};
pub use flow::{
    BidirectionalFlow, FlowDirection, FlowId, FlowReconstructionError, PacketEvidence,
    PacketPairEvidence, TcpConnectionEstablishment, TcpConnectionFailureCause,
    TcpConnectionHeuristic, TcpConnectionTermination, TcpDirectionalIndicator,
    TcpHeuristicConfidence, TransportProtocol,
};
pub use import::{
    CaptureImporter, ImportError, ImportLimitKind, ImportLimits, ImportProgress, ImportStep,
    PacketDecodeInput, PacketDecodeSink, PacketDecoder, decoder_scratch_bytes_upper_bound,
};
pub use model::{
    ByteOrder, CaptureDataset, CaptureDatasetParts, CaptureFormat, CaptureMetadata, InterfaceId,
    InterfaceMetadata, LinkType, ModelError, PacketId, PacketRecord, SectionId, SectionMetadata,
};
pub use range::{ByteRange, IndexRange};
pub use timestamp::{CaptureTimestamp, TimestampError, TimestampResolution};
