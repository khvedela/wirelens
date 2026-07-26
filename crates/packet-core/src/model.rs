//! Canonical capture, interface, and packet model.

use core::{fmt, mem::size_of};

use crate::{
    ByteRange, CaptureTimestamp, DecodedField, Diagnostic, FieldId, IndexRange, LayerFact,
    StringId, TimestampResolution,
};

macro_rules! id_type {
    ($name:ident) => {
        #[doc = "Stable, dataset-local identifier."]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub u32);
    };
}

id_type!(SectionId);
id_type!(InterfaceId);
id_type!(PacketId);

/// Capture container format.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptureFormat {
    /// Classic libpcap container.
    Pcap,
    /// PCAP Next Generation container.
    PcapNg,
}

/// Byte order declared by a PCAP file or PCAPNG section.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ByteOrder {
    /// Least-significant byte first.
    LittleEndian,
    /// Most-significant byte first.
    BigEndian,
}

/// Numeric capture link type. Unknown values remain representable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LinkType(pub u32);

/// Capture-wide immutable metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureMetadata {
    /// Parsed container family.
    pub format: CaptureFormat,
    /// Exact source byte length.
    pub byte_length: u64,
    /// Number of packet records retained.
    pub packet_count: u64,
    /// Earliest valid packet timestamp.
    pub started_at: Option<CaptureTimestamp>,
    /// Latest valid packet timestamp.
    pub ended_at: Option<CaptureTimestamp>,
}

/// PCAPNG section metadata (or one synthetic section for legacy PCAP).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SectionMetadata {
    /// Stable dataset-local section ID.
    pub id: SectionId,
    /// Source byte range occupied by the section.
    pub byte_range: ByteRange,
    /// Section-specific byte order.
    pub byte_order: ByteOrder,
    /// Consecutive interfaces belonging to the section.
    pub interfaces: IndexRange,
}

/// Per-interface metadata; PCAPNG values must never be collapsed globally.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InterfaceMetadata {
    /// Stable dataset-local interface ID.
    pub id: InterfaceId,
    /// Parent section.
    pub section_id: SectionId,
    /// Source bytes defining this interface (or the legacy PCAP header).
    pub byte_range: ByteRange,
    /// Interface ordinal within its section.
    pub section_index: u32,
    /// Raw link-type registry value.
    pub link_type: LinkType,
    /// Maximum captured bytes declared by the interface.
    pub snap_length: u32,
    /// Exact timestamp resolution declared by the interface.
    pub timestamp_resolution: TimestampResolution,
    /// Optional interned interface name.
    pub name: Option<StringId>,
}

/// Immutable packet record containing evidence references and arena spans.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketRecord {
    /// Zero-based stable identity. Presentation layers display `id + 1`.
    pub id: PacketId,
    /// Section containing the record.
    pub section_id: SectionId,
    /// Interface used to interpret link type and timestamp resolution.
    pub interface_id: InterfaceId,
    /// Exact timestamp when valid.
    pub timestamp: Option<CaptureTimestamp>,
    /// Captured bytes stored for this packet.
    pub captured_length: u32,
    /// Original on-wire length reported by the capture.
    pub original_length: u32,
    /// Packet payload bytes within the one owned capture buffer.
    pub data: ByteRange,
    /// Consecutive decoded layer facts.
    pub layers: IndexRange,
    /// Consecutive packet-scoped diagnostics.
    pub diagnostics: IndexRange,
}

/// Owned, immutable dataset assembled by capture ingestion.
#[derive(Eq, PartialEq)]
pub struct CaptureDataset {
    /// Capture-wide metadata.
    metadata: CaptureMetadata,
    /// One owned copy of the capture bytes.
    bytes: Box<[u8]>,
    /// Section arena. Its builder allocation is retained without a final copy.
    sections: Vec<SectionMetadata>,
    /// Interface arena. Its builder allocation is retained without a final copy.
    interfaces: Vec<InterfaceMetadata>,
    /// Packet arena. Its builder allocation is retained without a final copy.
    packets: Vec<PacketRecord>,
    /// Protocol-layer arena. Its builder allocation is retained without a final copy.
    layers: Vec<LayerFact>,
    /// Hierarchical decoded-field arena retained from the builder.
    fields: Vec<DecodedField>,
    /// Compact child IDs referenced by decoded-field child spans.
    field_children: Vec<FieldId>,
    /// Structured diagnostics arena retained from the builder.
    diagnostics: Vec<Diagnostic>,
    /// Deduplicated labels, protocol names, and safe diagnostic text.
    strings: Vec<Box<str>>,
}

/// Mutable construction payload consumed exactly once into a validated dataset.
#[derive(Eq, PartialEq)]
pub struct CaptureDatasetParts {
    /// Capture-wide metadata.
    pub metadata: CaptureMetadata,
    /// One owned copy of the capture bytes.
    pub bytes: Box<[u8]>,
    /// Section arena.
    pub sections: Box<[SectionMetadata]>,
    /// Interface arena.
    pub interfaces: Box<[InterfaceMetadata]>,
    /// Packet arena.
    pub packets: Box<[PacketRecord]>,
    /// Protocol-layer arena.
    pub layers: Box<[LayerFact]>,
    /// Hierarchical decoded-field arena.
    pub fields: Box<[DecodedField]>,
    /// Compact child IDs referenced by decoded-field child spans.
    pub field_children: Box<[FieldId]>,
    /// Structured diagnostics arena.
    pub diagnostics: Box<[Diagnostic]>,
    /// Deduplicated labels, protocol names, and safe diagnostic text.
    pub strings: Box<[Box<str>]>,
}

/// Crate-private construction payload that transfers builder allocations.
///
/// The canonical arenas remain private and immutable after construction. Using
/// vectors here avoids shrinking each live builder arena into a second boxed
/// allocation while both allocations contribute to the Wasm high-water mark.
pub(crate) struct CaptureDatasetVecParts {
    pub(crate) metadata: CaptureMetadata,
    pub(crate) bytes: Box<[u8]>,
    pub(crate) sections: Vec<SectionMetadata>,
    pub(crate) interfaces: Vec<InterfaceMetadata>,
    pub(crate) packets: Vec<PacketRecord>,
    pub(crate) layers: Vec<LayerFact>,
    pub(crate) fields: Vec<DecodedField>,
    pub(crate) field_children: Vec<FieldId>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) strings: Vec<Box<str>>,
}

impl fmt::Debug for CaptureDataset {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureDataset")
            .field("metadata", &self.metadata)
            .field("section_count", &self.sections.len())
            .field("interface_count", &self.interfaces.len())
            .field("packet_count", &self.packets.len())
            .field("layer_count", &self.layers.len())
            .field("field_count", &self.fields.len())
            .field("diagnostic_count", &self.diagnostics.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for CaptureDatasetParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureDatasetParts")
            .field("metadata", &self.metadata)
            .field("section_count", &self.sections.len())
            .field("interface_count", &self.interfaces.len())
            .field("packet_count", &self.packets.len())
            .field("layer_count", &self.layers.len())
            .field("field_count", &self.fields.len())
            .field("diagnostic_count", &self.diagnostics.len())
            .finish_non_exhaustive()
    }
}

impl CaptureDataset {
    /// Consumes construction parts and returns an immutable validated dataset.
    ///
    /// # Errors
    ///
    /// Returns the first [`ModelError`] when IDs, ranges, or cross-references
    /// are inconsistent.
    pub fn from_parts(parts: CaptureDatasetParts) -> Result<Self, ModelError> {
        Self::from_vec_parts(CaptureDatasetVecParts {
            metadata: parts.metadata,
            bytes: parts.bytes,
            sections: parts.sections.into_vec(),
            interfaces: parts.interfaces.into_vec(),
            packets: parts.packets.into_vec(),
            layers: parts.layers.into_vec(),
            fields: parts.fields.into_vec(),
            field_children: parts.field_children.into_vec(),
            diagnostics: parts.diagnostics.into_vec(),
            strings: parts.strings.into_vec(),
        })
    }

    /// Transfers vector-backed builder arenas into an immutable dataset.
    pub(crate) fn from_vec_parts(parts: CaptureDatasetVecParts) -> Result<Self, ModelError> {
        let dataset = Self {
            metadata: parts.metadata,
            bytes: parts.bytes,
            sections: parts.sections,
            interfaces: parts.interfaces,
            packets: parts.packets,
            layers: parts.layers,
            fields: parts.fields,
            field_children: parts.field_children,
            diagnostics: parts.diagnostics,
            strings: parts.strings,
        };
        dataset.validate()?;
        Ok(dataset)
    }

    /// Returns capture-wide metadata.
    #[must_use]
    pub const fn metadata(&self) -> &CaptureMetadata {
        &self.metadata
    }

    /// Returns the single owned capture buffer.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns section metadata in stable ID order.
    #[must_use]
    pub fn sections(&self) -> &[SectionMetadata] {
        &self.sections
    }

    /// Returns interface metadata in stable ID order.
    #[must_use]
    pub fn interfaces(&self) -> &[InterfaceMetadata] {
        &self.interfaces
    }

    /// Returns packet records in stable ID order.
    #[must_use]
    pub fn packets(&self) -> &[PacketRecord] {
        &self.packets
    }

    /// Returns decoded protocol-layer facts.
    #[must_use]
    pub fn layers(&self) -> &[LayerFact] {
        &self.layers
    }

    /// Returns the decoded-field arena.
    #[must_use]
    pub fn fields(&self) -> &[DecodedField] {
        &self.fields
    }

    /// Returns the compact field-child index arena.
    #[must_use]
    pub fn field_children(&self) -> &[FieldId] {
        &self.field_children
    }

    /// Returns structured parse diagnostics.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// Returns the number of immutable interned strings.
    #[must_use]
    pub fn interned_string_count(&self) -> usize {
        self.strings.len()
    }

    /// Returns the exact UTF-8 bytes retained by the interned strings.
    #[must_use]
    pub fn interned_string_bytes(&self) -> Option<u64> {
        self.strings.iter().try_fold(0_u64, |total, value| {
            total.checked_add(u64::try_from(value.len()).ok()?)
        })
    }

    /// Returns the retained packet-index allocation in bytes.
    ///
    /// This counts vector capacity rather than logical length because spare
    /// capacity remains owned by the immutable dataset.
    #[must_use]
    pub fn retained_packet_index_bytes(&self) -> Option<u64> {
        arena_capacity_bytes::<PacketRecord>(self.packets.capacity())
    }

    /// Returns the retained canonical index allocation in bytes.
    ///
    /// The checked sum covers the allocated capacity of every fixed-width
    /// vector arena and the outer string vector, plus all interned UTF-8 bytes.
    /// Capacity is used instead of length because finalization transfers the
    /// builder vectors without shrinking them. The capture allocation returned
    /// by [`bytes`](Self::bytes) is intentionally excluded so callers can report
    /// source and index retention independently. `None` indicates that the sum
    /// cannot be represented as `u64`.
    #[must_use]
    pub fn retained_index_bytes(&self) -> Option<u64> {
        let mut total = 0_u64;
        for bytes in [
            arena_capacity_bytes::<SectionMetadata>(self.sections.capacity())?,
            arena_capacity_bytes::<InterfaceMetadata>(self.interfaces.capacity())?,
            self.retained_packet_index_bytes()?,
            arena_capacity_bytes::<LayerFact>(self.layers.capacity())?,
            arena_capacity_bytes::<DecodedField>(self.fields.capacity())?,
            arena_capacity_bytes::<FieldId>(self.field_children.capacity())?,
            arena_capacity_bytes::<Diagnostic>(self.diagnostics.capacity())?,
            arena_capacity_bytes::<Box<str>>(self.strings.capacity())?,
        ] {
            total = total.checked_add(bytes)?;
        }
        total.checked_add(self.interned_string_bytes()?)
    }

    /// Returns a packet by stable identity.
    #[must_use]
    pub fn packet(&self, id: PacketId) -> Option<&PacketRecord> {
        self.packets.get(id.0 as usize)
    }

    /// Resolves an interned string.
    #[must_use]
    pub fn string(&self, id: StringId) -> Option<&str> {
        self.strings.get(id.0 as usize).map(AsRef::as_ref)
    }

    /// Validates all dataset IDs, ranges, arena spans, and cross-references.
    ///
    /// # Errors
    ///
    /// Returns the first [`ModelError`] when untrusted import construction left
    /// the canonical dataset internally inconsistent.
    pub fn validate(&self) -> Result<(), ModelError> {
        self.validate_metadata()?;
        self.validate_sections_and_interfaces()?;
        self.validate_packets()?;
        self.validate_fields()?;
        self.validate_layers_and_diagnostics()
    }

    fn validate_metadata(&self) -> Result<(), ModelError> {
        if self.metadata.byte_length != self.bytes.len() as u64 {
            return Err(ModelError::CaptureByteLength);
        }
        if self.metadata.packet_count != self.packets.len() as u64 {
            return Err(ModelError::PacketCount);
        }
        let mut earliest = None;
        let mut latest = None;
        for timestamp in self.packets.iter().filter_map(|packet| packet.timestamp) {
            if earliest.is_none_or(|current| timestamp.cmp_instant(current).is_lt()) {
                earliest = Some(timestamp);
            }
            if latest.is_none_or(|current| timestamp.cmp_instant(current).is_gt()) {
                latest = Some(timestamp);
            }
        }
        if self.metadata.started_at != earliest || self.metadata.ended_at != latest {
            return Err(ModelError::TimestampBounds);
        }
        Ok(())
    }

    fn validate_sections_and_interfaces(&self) -> Result<(), ModelError> {
        let mut interface_slot_used = vec![false; self.interfaces.len()];
        let mut previous_section_end = 0;
        for (index, section) in self.sections.iter().enumerate() {
            if section.id.0 as usize != index {
                return Err(ModelError::SectionId);
            }
            if !section.byte_range.is_within(self.metadata.byte_length) {
                return Err(ModelError::ByteRange);
            }
            if section.byte_range.start() < previous_section_end {
                return Err(ModelError::SectionRange);
            }
            previous_section_end = section.byte_range.end();
            if !arena_range_fits(section.interfaces, self.interfaces.len()) {
                return Err(ModelError::ArenaRange);
            }
            for (section_index, (slot_used, interface)) in interface_slot_used
                [section.interfaces.start() as usize..section.interfaces.end() as usize]
                .iter_mut()
                .zip(
                    &self.interfaces
                        [section.interfaces.start() as usize..section.interfaces.end() as usize],
                )
                .enumerate()
            {
                if *slot_used
                    || interface.section_id != section.id
                    || interface.section_index as usize != section_index
                {
                    return Err(ModelError::InterfaceSection);
                }
                *slot_used = true;
            }
        }
        if interface_slot_used.contains(&false) {
            return Err(ModelError::InterfaceSection);
        }

        for (index, interface) in self.interfaces.iter().enumerate() {
            if interface.id.0 as usize != index {
                return Err(ModelError::InterfaceId);
            }
            let Some(section) = self.sections.get(interface.section_id.0 as usize) else {
                return Err(ModelError::InterfaceSection);
            };
            if !range_contains(section.byte_range, interface.byte_range) {
                return Err(ModelError::ByteRange);
            }
            if !interface.timestamp_resolution.is_valid() {
                return Err(ModelError::TimestampResolution);
            }
            if interface.name.is_some_and(|id| self.string(id).is_none()) {
                return Err(ModelError::StringId);
            }
        }
        Ok(())
    }

    fn validate_packets(&self) -> Result<(), ModelError> {
        let mut layer_owned = vec![false; self.layers.len()];
        let mut diagnostic_owned = vec![false; self.diagnostics.len()];
        for (index, packet) in self.packets.iter().enumerate() {
            if packet.id.0 as usize != index {
                return Err(ModelError::PacketId);
            }
            if self.sections.get(packet.section_id.0 as usize).is_none() {
                return Err(ModelError::PacketSection);
            }
            let section = &self.sections[packet.section_id.0 as usize];
            let Some(interface) = self.interfaces.get(packet.interface_id.0 as usize) else {
                return Err(ModelError::PacketInterface);
            };
            if interface.section_id != packet.section_id {
                return Err(ModelError::PacketInterface);
            }
            if packet
                .timestamp
                .is_some_and(|timestamp| timestamp.resolution() != interface.timestamp_resolution)
            {
                return Err(ModelError::TimestampResolution);
            }
            if packet.data.length() != packet.captured_length
                || !packet.data.is_within(self.metadata.byte_length)
                || packet.data.start() < section.byte_range.start()
                || packet.data.end() > section.byte_range.end()
            {
                return Err(ModelError::ByteRange);
            }
            if !arena_range_fits(packet.layers, self.layers.len())
                || !arena_range_fits(packet.diagnostics, self.diagnostics.len())
            {
                return Err(ModelError::ArenaRange);
            }
            for (owned, layer) in layer_owned
                [packet.layers.start() as usize..packet.layers.end() as usize]
                .iter_mut()
                .zip(&self.layers[packet.layers.start() as usize..packet.layers.end() as usize])
            {
                if *owned || !range_contains(packet.data, layer.byte_range) {
                    return Err(ModelError::ArenaOwnership);
                }
                *owned = true;
            }
            for (owned, diagnostic) in diagnostic_owned
                [packet.diagnostics.start() as usize..packet.diagnostics.end() as usize]
                .iter_mut()
                .zip(
                    &self.diagnostics
                        [packet.diagnostics.start() as usize..packet.diagnostics.end() as usize],
                )
            {
                if *owned || diagnostic.scope != crate::DiagnosticScope::Packet(packet.id) {
                    return Err(ModelError::ArenaOwnership);
                }
                *owned = true;
            }
        }
        if layer_owned.contains(&false) {
            return Err(ModelError::ArenaOwnership);
        }
        for (diagnostic, owned) in self.diagnostics.iter().zip(diagnostic_owned) {
            match diagnostic.scope {
                crate::DiagnosticScope::Capture if owned => {
                    return Err(ModelError::ArenaOwnership);
                }
                crate::DiagnosticScope::Packet(_) if !owned => {
                    return Err(ModelError::ArenaOwnership);
                }
                crate::DiagnosticScope::Capture | crate::DiagnosticScope::Packet(_) => {}
            }
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), ModelError> {
        let mut child_slot_used = vec![false; self.field_children.len()];
        let mut parent_count = vec![0_u8; self.fields.len()];
        let mut root_count = vec![0_u8; self.fields.len()];
        for (index, field) in self.fields.iter().enumerate() {
            if !field.byte_range.is_within(self.metadata.byte_length)
                || !arena_range_fits(field.children, self.field_children.len())
            {
                return Err(ModelError::ArenaRange);
            }
            let start = field.children.start() as usize;
            let end = field.children.end() as usize;
            for (slot_used, child_id) in child_slot_used[start..end]
                .iter_mut()
                .zip(&self.field_children[start..end])
            {
                if *slot_used {
                    return Err(ModelError::FieldHierarchy);
                }
                *slot_used = true;
                let child = child_id.0 as usize;
                if child <= index
                    || self.fields.get(child).is_none()
                    || !range_contains(field.byte_range, self.fields[child].byte_range)
                {
                    return Err(ModelError::FieldHierarchy);
                }
                parent_count[child] = parent_count[child].saturating_add(1);
                if parent_count[child] > 1 {
                    return Err(ModelError::FieldHierarchy);
                }
            }
            if self.string(field.name).is_none()
                || matches!(field.value, crate::FieldValue::String(id) if self.string(id).is_none())
            {
                return Err(ModelError::StringId);
            }
            if matches!(field.value, crate::FieldValue::Bytes(range) if !range.is_within(self.metadata.byte_length))
            {
                return Err(ModelError::ByteRange);
            }
        }
        if child_slot_used.contains(&false) {
            return Err(ModelError::FieldHierarchy);
        }
        for layer in &self.layers {
            if let Some(id) = layer.root_field {
                let index = id.0 as usize;
                if parent_count.get(index).is_none_or(|count| *count != 0)
                    || !range_contains(layer.byte_range, self.fields[index].byte_range)
                {
                    return Err(ModelError::FieldHierarchy);
                }
                root_count[index] = root_count[index].saturating_add(1);
                if root_count[index] > 1 {
                    return Err(ModelError::FieldHierarchy);
                }
            }
        }
        if parent_count
            .iter()
            .zip(root_count)
            .any(|(parents, roots)| (*parents == 0) != (roots == 1))
        {
            return Err(ModelError::FieldHierarchy);
        }
        Ok(())
    }

    fn validate_layers_and_diagnostics(&self) -> Result<(), ModelError> {
        for layer in &self.layers {
            if self.string(layer.protocol).is_none()
                || !layer.byte_range.is_within(self.metadata.byte_length)
                || layer
                    .root_field
                    .is_some_and(|id| self.fields.get(id.0 as usize).is_none())
            {
                return Err(ModelError::LayerFact);
            }
        }

        for diagnostic in &self.diagnostics {
            if self.string(diagnostic.message).is_none() {
                return Err(ModelError::StringId);
            }
            if diagnostic
                .byte_range
                .is_some_and(|range| !range.is_within(self.metadata.byte_length))
            {
                return Err(ModelError::ByteRange);
            }
            if let crate::DiagnosticScope::Packet(id) = diagnostic.scope {
                if self.packet(id).is_none() {
                    return Err(ModelError::DiagnosticScope);
                }
            }
        }

        Ok(())
    }
}

fn arena_capacity_bytes<T>(capacity: usize) -> Option<u64> {
    u64::try_from(capacity)
        .ok()?
        .checked_mul(u64::try_from(size_of::<T>()).ok()?)
}

fn arena_range_fits(range: IndexRange, arena_length: usize) -> bool {
    range.end() as usize <= arena_length
}

fn range_contains(container: ByteRange, child: ByteRange) -> bool {
    child.start() >= container.start() && child.end() <= container.end()
}

/// Canonical dataset invariant violation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// Metadata byte length differs from owned bytes.
    CaptureByteLength,
    /// Metadata packet count differs from the packet arena.
    PacketCount,
    /// A section ID is not its stable arena index.
    SectionId,
    /// An interface ID is not its stable arena index.
    InterfaceId,
    /// An interface references the wrong or a missing section.
    InterfaceSection,
    /// Section byte ranges overlap or are out of source order.
    SectionRange,
    /// A packet ID is not its stable arena index.
    PacketId,
    /// A packet references a missing section.
    PacketSection,
    /// A packet references a missing or cross-section interface.
    PacketInterface,
    /// A packet timestamp disagrees with its interface resolution.
    TimestampResolution,
    /// Capture timestamp extrema disagree with retained packet timestamps.
    TimestampBounds,
    /// A byte range is outside the owned capture or contradicts a length.
    ByteRange,
    /// An arena span is outside its target arena.
    ArenaRange,
    /// Packet-owned arena entries overlap, are orphaned, or have the wrong scope.
    ArenaOwnership,
    /// A field child span is not a forward, acyclic hierarchy.
    FieldHierarchy,
    /// An interned string identifier is missing.
    StringId,
    /// A layer fact references invalid protocol, bytes, or field data.
    LayerFact,
    /// A diagnostic references a missing packet.
    DiagnosticScope,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_construction_retains_and_accounts_for_spare_capacity() {
        let bytes = vec![0_u8; 64].into_boxed_slice();

        let mut sections = Vec::with_capacity(7);
        sections.push(SectionMetadata {
            id: SectionId(0),
            byte_range: ByteRange::new(0, 64).expect("valid section range"),
            byte_order: ByteOrder::LittleEndian,
            interfaces: IndexRange::new(0, 1).expect("valid interface span"),
        });
        let mut interfaces = Vec::with_capacity(6);
        interfaces.push(InterfaceMetadata {
            id: InterfaceId(0),
            section_id: SectionId(0),
            byte_range: ByteRange::new(0, 24).expect("valid interface range"),
            section_index: 0,
            link_type: LinkType(1),
            snap_length: 65_535,
            timestamp_resolution: TimestampResolution::Decimal(6),
            name: None,
        });
        let mut packets = Vec::with_capacity(9);
        packets.push(PacketRecord {
            id: PacketId(0),
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp: None,
            captured_length: 8,
            original_length: 8,
            data: ByteRange::new(40, 8).expect("valid packet range"),
            layers: IndexRange::default(),
            diagnostics: IndexRange::default(),
        });
        let layers: Vec<LayerFact> = Vec::with_capacity(5);
        let fields: Vec<DecodedField> = Vec::with_capacity(4);
        let field_children: Vec<FieldId> = Vec::with_capacity(3);
        let diagnostics: Vec<Diagnostic> = Vec::with_capacity(2);
        let mut strings = Vec::with_capacity(8);
        strings.push(Box::<str>::from("retained"));

        assert!(packets.capacity() > packets.len());
        assert!(strings.capacity() > strings.len());
        let capture_allocation = bytes.as_ptr();
        let section_allocation = sections.as_ptr();
        let interface_allocation = interfaces.as_ptr();
        let packet_allocation = packets.as_ptr();
        let string_arena_allocation = strings.as_ptr();
        let packet_bytes = arena_capacity_bytes::<PacketRecord>(packets.capacity())
            .expect("packet capacity fits u64");
        let retained_bytes = [
            arena_capacity_bytes::<SectionMetadata>(sections.capacity()),
            arena_capacity_bytes::<InterfaceMetadata>(interfaces.capacity()),
            Some(packet_bytes),
            arena_capacity_bytes::<LayerFact>(layers.capacity()),
            arena_capacity_bytes::<DecodedField>(fields.capacity()),
            arena_capacity_bytes::<FieldId>(field_children.capacity()),
            arena_capacity_bytes::<Diagnostic>(diagnostics.capacity()),
            arena_capacity_bytes::<Box<str>>(strings.capacity()),
            Some(u64::try_from("retained".len()).expect("string length fits u64")),
        ]
        .into_iter()
        .try_fold(0_u64, |total, bytes| total.checked_add(bytes?))
        .expect("retained capacity fits u64");

        let dataset = CaptureDataset::from_vec_parts(CaptureDatasetVecParts {
            metadata: CaptureMetadata {
                format: CaptureFormat::Pcap,
                byte_length: 64,
                packet_count: 1,
                started_at: None,
                ended_at: None,
            },
            bytes,
            sections,
            interfaces,
            packets,
            layers,
            fields,
            field_children,
            diagnostics,
            strings,
        })
        .expect("valid vector-backed dataset");

        assert_eq!(dataset.bytes.as_ptr(), capture_allocation);
        assert_eq!(dataset.sections.as_ptr(), section_allocation);
        assert_eq!(dataset.interfaces.as_ptr(), interface_allocation);
        assert_eq!(dataset.packets.as_ptr(), packet_allocation);
        assert_eq!(dataset.strings.as_ptr(), string_arena_allocation);
        assert_eq!(dataset.retained_packet_index_bytes(), Some(packet_bytes));
        assert_eq!(dataset.retained_index_bytes(), Some(retained_bytes));
        assert_eq!(dataset.interned_string_bytes(), Some(8));
        dataset
            .validate()
            .expect("capacity does not alter invariants");
    }
}
