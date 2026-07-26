//! Structured parse diagnostics without payload-bearing log messages.

use crate::{ByteRange, PacketId};

/// Diagnostic severity suitable for consistent boundary mapping.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Severity {
    /// Informational capture condition.
    Info,
    /// Parsing continued with a caveat.
    Warning,
    /// A record or packet could not be fully interpreted.
    Error,
    /// Import cannot safely continue.
    Fatal,
}

/// Stable diagnostic code. Unknown future values remain representable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DiagnosticCode(pub u16);

impl DiagnosticCode {
    /// Capture header or section header is invalid.
    pub const INVALID_CAPTURE_HEADER: Self = Self(1);
    /// A record ends before its declared length.
    pub const TRUNCATED_RECORD: Self = Self(2);
    /// A block type is well-framed but unsupported.
    pub const UNSUPPORTED_BLOCK: Self = Self(3);
    /// An interface link type is not currently decoded.
    pub const UNSUPPORTED_LINK_TYPE: Self = Self(4);
    /// Timestamp metadata or a value is invalid.
    pub const INVALID_TIMESTAMP: Self = Self(5);
    /// Captured/original lengths contradict the containing record.
    pub const INCONSISTENT_LENGTH: Self = Self(6);
    /// A configured resource limit prevented further processing.
    pub const RESOURCE_LIMIT: Self = Self(7);
    /// A protocol header ended before its required bytes were available.
    pub const TRUNCATED_PROTOCOL: Self = Self(8);
    /// Protocol bytes violate the decoded format's structural requirements.
    pub const MALFORMED_PROTOCOL: Self = Self(9);
    /// A recognized link or protocol envelope is outside the supported subset.
    pub const UNSUPPORTED_ENCAPSULATION: Self = Self(10);
    /// A well-framed protocol identifier has no decoder in this version.
    pub const UNSUPPORTED_PROTOCOL: Self = Self(11);
    /// A protocol checksum field does not validate against the captured header.
    pub const INVALID_PROTOCOL_CHECKSUM: Self = Self(12);
}

/// Scope of the evidence attached to a diagnostic.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DiagnosticScope {
    /// Applies to the capture as a whole.
    Capture,
    /// Applies to a packet, optionally with a precise byte range.
    Packet(PacketId),
}

/// How parsing proceeded after the condition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Recovery {
    /// Parsing safely continued.
    Continued,
    /// The affected packet or block was skipped.
    RecordSkipped,
    /// Capture import stopped and temporary state must be discarded.
    CaptureRejected,
}

/// A compact diagnostic referencing interned explanatory text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Diagnostic {
    /// Stable machine-readable condition.
    pub code: DiagnosticCode,
    /// User-facing importance.
    pub severity: Severity,
    /// Capture or packet scope.
    pub scope: DiagnosticScope,
    /// Exact evidence bytes when known.
    pub byte_range: Option<ByteRange>,
    /// Interned non-payload-bearing detail string.
    pub message: crate::StringId,
    /// Parser recovery outcome.
    pub recovery: Recovery,
}
