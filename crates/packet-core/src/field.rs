//! Arena-backed decoded fields and layer facts.

use crate::{ByteRange, IndexRange};

/// Index into the dataset's deduplicated string table.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StringId(pub u32);

/// Stable index into the decoded-field arena.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FieldId(pub u32);

/// Compact value representation for decoded fields.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FieldValue {
    /// Field presence without a separate scalar.
    None,
    /// Unsigned numeric value.
    Unsigned(u64),
    /// Signed numeric value.
    Signed(i64),
    /// Boolean value.
    Boolean(bool),
    /// Interned text such as a field label or normalized name.
    String(StringId),
    /// Raw bytes retained by reference rather than copied.
    Bytes(ByteRange),
}

/// One node in the dataset field arena.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DecodedField {
    /// Stable interned field name.
    pub name: StringId,
    /// Decoded scalar or byte reference.
    pub value: FieldValue,
    /// Evidence bytes for this field.
    pub byte_range: ByteRange,
    /// Consecutive child IDs in the dataset's child-index arena.
    pub children: IndexRange,
}

/// Extensible protocol-layer fact linked to its field subtree.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LayerFact {
    /// Interned protocol identifier (for example `ethernet` or `ipv6`).
    pub protocol: StringId,
    /// Evidence bytes occupied by the layer.
    pub byte_range: ByteRange,
    /// Root field index in the field arena, if decoded fields exist.
    pub root_field: Option<FieldId>,
}
