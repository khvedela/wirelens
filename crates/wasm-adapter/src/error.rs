//! Stable, payload-free error categories for worker boundary calls.

use core::fmt;

use crate::ImportProgressSnapshot;

/// Stable numeric error code. Unknown future values remain representable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BoundaryErrorCode(u16);

impl BoundaryErrorCode {
    /// The raw handle is zero, malformed, or refers to no allocated slot.
    pub const INVALID_HANDLE: Self = Self(1);
    /// A dataset handle was used as a cursor, or vice versa.
    pub const WRONG_HANDLE_KIND: Self = Self(2);
    /// The handle generation no longer owns the addressed slot.
    pub const STALE_HANDLE: Self = Self(3);
    /// A bounded handle registry cannot allocate another slot safely.
    pub const REGISTRY_LIMIT: Self = Self(4);
    /// A packet cursor start position lies beyond its dataset.
    pub const CURSOR_OUT_OF_RANGE: Self = Self(5);
    /// A packet batch request exceeds the stable row cap.
    pub const BATCH_ROW_LIMIT: Self = Self(6);
    /// A planned packet batch would exceed the hard byte cap.
    pub const BATCH_BYTE_LIMIT: Self = Self(7);
    /// Checked integer or offset arithmetic overflowed.
    pub const ARITHMETIC_OVERFLOW: Self = Self(8);
    /// An evidence range lies outside the retained capture bytes.
    pub const EVIDENCE_OUT_OF_RANGE: Self = Self(9);
    /// An evidence request exceeds the per-call byte cap.
    pub const EVIDENCE_BYTE_LIMIT: Self = Self(10);
    /// An internal invariant was violated without exposing capture data.
    pub const INTERNAL_INVARIANT: Self = Self(11);
    /// The caller requested an unsupported API or schema version.
    pub const UNSUPPORTED_VERSION: Self = Self(12);
    /// The requested operation is not valid in the resource's current state.
    pub const INVALID_STATE: Self = Self(13);
    /// A caller-supplied limit, budget, or argument is invalid.
    pub const INVALID_ARGUMENT: Self = Self(14);
    /// Capture framing or format detection failed.
    pub const CAPTURE_FORMAT: Self = Self(15);
    /// Capture structure is malformed or internally contradictory.
    pub const MALFORMED_CAPTURE: Self = Self(16);
    /// Capture bytes end before a declared structure is complete.
    pub const TRUNCATED_CAPTURE: Self = Self(17);
    /// An import or query was cancelled and temporary state was reclaimed.
    pub const CANCELLED: Self = Self(18);
    /// A configured import, memory, or result resource cap was reached.
    pub const RESOURCE_LIMIT: Self = Self(19);
    /// Capture import failed without a more specific stable mapping.
    pub const IMPORT_FAILED: Self = Self(20);

    /// Returns the stable numeric representation used by the worker protocol.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.0
    }
}

/// Structured boundary failure with a stable code and payload-free message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BoundaryError {
    code: BoundaryErrorCode,
    message: &'static str,
    input_offset: Option<u64>,
    resource_limit: Option<u64>,
    import_progress: Option<ImportProgressSnapshot>,
}

impl BoundaryError {
    pub(crate) const fn new(code: BoundaryErrorCode, message: &'static str) -> Self {
        Self {
            code,
            message,
            input_offset: None,
            resource_limit: None,
            import_progress: None,
        }
    }

    pub(crate) const fn with_input_offset(mut self, input_offset: u64) -> Self {
        self.input_offset = Some(input_offset);
        self
    }

    pub(crate) const fn with_resource_context(
        mut self,
        input_offset: u64,
        resource_limit: u64,
    ) -> Self {
        self.input_offset = Some(input_offset);
        self.resource_limit = Some(resource_limit);
        self
    }

    pub(crate) const fn with_resource_limit(mut self, resource_limit: u64) -> Self {
        self.resource_limit = Some(resource_limit);
        self
    }

    pub(crate) const fn with_import_progress(mut self, progress: ImportProgressSnapshot) -> Self {
        self.import_progress = Some(progress);
        self
    }

    /// Returns the stable machine-readable category.
    #[must_use]
    pub const fn code(self) -> BoundaryErrorCode {
        self.code
    }

    /// Returns a static message that never contains capture or decoded data.
    #[must_use]
    pub const fn message(self) -> &'static str {
        self.message
    }

    /// Returns the exact capture offset associated with an import error.
    #[must_use]
    pub const fn input_offset(self) -> Option<u64> {
        self.input_offset
    }

    /// Returns the configured ceiling associated with a resource-limit error.
    #[must_use]
    pub const fn resource_limit(self) -> Option<u64> {
        self.resource_limit
    }

    /// Returns last valid counters when a live importer failed terminally.
    #[must_use]
    pub const fn terminal_import_progress(self) -> Option<ImportProgressSnapshot> {
        self.import_progress
    }
}

impl fmt::Display for BoundaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl std::error::Error for BoundaryError {}
