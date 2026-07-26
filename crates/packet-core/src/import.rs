//! Bounded, incremental capture-container ingestion.

use core::{fmt, mem};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use pcap_parser::{
    Block, LegacyPcapReader, NameRecord, OptionCode, PcapBlockOwned, PcapError, PcapHeader,
    PcapNGOption, PcapNGReader, parse_pcap_header, parse_sectionheaderblock,
    traits::PcapReaderIterator,
};

use crate::model::CaptureDatasetVecParts;
use crate::{
    ByteOrder, ByteRange, CaptureDataset, CaptureFormat, CaptureMetadata, CaptureTimestamp,
    DecodedField, Diagnostic, DiagnosticCode, DiagnosticScope, FieldId, FieldValue, IndexRange,
    InterfaceId, InterfaceMetadata, LayerFact, LinkType, ModelError, PacketId, PacketRecord,
    Recovery, SectionId, SectionMetadata, Severity, StringId, TimestampResolution,
};

const DEFAULT_BUFFER_BYTES: usize = 64 * 1024;
const DEFAULT_DECODED_ITEMS_PER_BLOCK: u32 = 4_096;
const MIN_ARENA_CAPACITY: usize = 8;
const MIN_DIAGNOSTIC_STRING_BYTES: usize = 1024;
const PCAPNG_SHB_TYPE: u32 = 0x0a0d_0d0a;
const PCAPNG_IDB_TYPE: u32 = 0x0000_0001;
const PCAPNG_NRB_TYPE: u32 = 0x0000_0004;
const PCAPNG_ISB_TYPE: u32 = 0x0000_0005;
const PCAPNG_EPB_TYPE: u32 = 0x0000_0006;
const PCAPNG_DSB_TYPE: u32 = 0x0000_000a;
const PCAPNG_PIB_TYPE: u32 = 0x8000_0001;

const MESSAGE_TRUNCATED: &str = "capture ended before the declared record length";
const MESSAGE_MALFORMED: &str = "capture framing is malformed; parsing stopped safely";
const MESSAGE_UNSUPPORTED_BLOCK: &str = "well-framed PCAPNG block is not retained by v0.1";
const MESSAGE_MISSING_INTERFACE: &str =
    "packet references an interface not defined in this section";
const MESSAGE_INVALID_TIMESTAMP: &str = "packet timestamp cannot be represented exactly";
const MESSAGE_INCONSISTENT_LENGTH: &str =
    "captured, original, snap, or padded lengths are inconsistent";
const MESSAGE_INVALID_OPTION: &str = "interface option is malformed; the safe default was retained";

/// Resource ceilings applied before importer allocations grow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportLimits {
    /// Largest accepted capture allocation.
    pub max_capture_bytes: u64,
    /// Largest individual legacy record or PCAPNG block.
    pub max_block_bytes: u32,
    /// Maximum options plus list records decoded from one PCAPNG block.
    ///
    /// Complete block bytes are inspected against this ceiling before they
    /// reach `pcap-parser`, whose option and name-record parsers allocate one
    /// vector element per decoded item.
    pub max_decoded_items_per_block: u32,
    /// Maximum options plus list records decoded during one importer step.
    ///
    /// This ceiling is cumulative across PCAPNG blocks and must be at least
    /// [`Self::max_decoded_items_per_block`], ensuring every individually
    /// admitted block can make progress in a fresh step.
    pub max_decoded_items_per_step: u32,
    /// Maximum retained packets.
    pub max_packets: u32,
    /// Maximum PCAPNG sections.
    pub max_sections: u32,
    /// Maximum interfaces across all sections.
    pub max_interfaces: u32,
    /// Maximum structured diagnostics.
    pub max_diagnostics: u32,
    /// Maximum protocol layers retained across the capture.
    pub max_layers: u32,
    /// Maximum protocol layers retained for one packet.
    pub max_layers_per_packet: u32,
    /// Maximum decoded fields retained across the capture.
    pub max_fields: u32,
    /// Maximum decoded fields retained for one packet.
    pub max_fields_per_packet: u32,
    /// Maximum child references retained across the capture.
    pub max_field_children: u32,
    /// Maximum child references retained for one packet.
    pub max_field_children_per_packet: u32,
    /// Maximum bytes owned by the string interner.
    pub max_string_bytes: u32,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_capture_bytes: u64::from(u32::MAX),
            max_block_bytes: 16 * 1024 * 1024,
            max_decoded_items_per_block: DEFAULT_DECODED_ITEMS_PER_BLOCK,
            max_decoded_items_per_step: DEFAULT_DECODED_ITEMS_PER_BLOCK,
            max_packets: 1_000_000,
            max_sections: 4_096,
            max_interfaces: 65_536,
            max_diagnostics: 4_096,
            max_layers: 8_000_000,
            max_layers_per_packet: 64,
            max_fields: 32_000_000,
            max_fields_per_packet: 4_096,
            max_field_children: 32_000_000,
            max_field_children_per_packet: 8_192,
            max_string_bytes: 1024 * 1024,
        }
    }
}

/// Returns a conservative heap-byte ceiling for one dependency-decoded
/// PCAPNG option/name-record list at the configured per-block item limit.
///
/// The pinned parser uses geometrically growing vectors whose combined item
/// count is prevalidated against this limit. The two-times capacity factor and
/// eight-slot floor also cover Rust's minimum non-zero `Vec` capacity.
#[must_use]
pub fn decoder_scratch_bytes_upper_bound(max_decoded_items_per_block: u32) -> Option<u64> {
    let item_bytes =
        mem::size_of::<PcapNGOption<'static>>().max(mem::size_of::<NameRecord<'static>>());
    let slots = u64::from(max_decoded_items_per_block)
        .checked_mul(2)?
        .max(8);
    slots.checked_mul(u64::try_from(item_bytes).ok()?)
}

/// Machine-readable resource ceiling involved in an import failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportLimitKind {
    /// Input capture bytes.
    CaptureBytes,
    /// A single framed record or block.
    BlockBytes,
    /// Options plus list records decoded from one PCAPNG block.
    DecodedItemsPerBlock,
    /// Retained packet records.
    Packets,
    /// Capture sections.
    Sections,
    /// Capture interfaces.
    Interfaces,
    /// Structured diagnostics.
    Diagnostics,
    /// Protocol-layer facts across the capture.
    Layers,
    /// Protocol-layer facts for one packet.
    LayersPerPacket,
    /// Decoded fields across the capture.
    Fields,
    /// Decoded fields for one packet.
    FieldsPerPacket,
    /// Field-child references across the capture.
    FieldChildren,
    /// Field-child references for one packet.
    FieldChildrenPerPacket,
    /// Interned safe text.
    StringBytes,
}

/// Redacted importer failure. No variant owns or formats capture payload bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportError {
    /// The supplied limits are internally inconsistent.
    InvalidLimits,
    /// A step must allow at least one record and one byte.
    InvalidStepBudget,
    /// The capture header is absent, unsupported, or malformed.
    InvalidHeader,
    /// Input ended before an initial header or declared first block completed.
    TruncatedInput {
        /// Start of the incomplete framing unit.
        offset: u64,
    },
    /// A configured resource ceiling was reached.
    ResourceLimit {
        /// Resource that reached its ceiling.
        kind: ImportLimitKind,
        /// Configured ceiling.
        limit: u64,
        /// Absolute source offset when known.
        offset: u64,
    },
    /// Finalization was requested before a terminal step.
    NotReady,
    /// Reader ownership did not collapse back to the one capture allocation.
    OwnershipInvariant,
    /// Canonical model validation rejected importer output.
    Model(ModelError),
    /// Checked offset or arena arithmetic failed.
    Arithmetic,
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid capture import limits"),
            Self::InvalidStepBudget => formatter.write_str("invalid capture import step budget"),
            Self::InvalidHeader => formatter.write_str("invalid or unsupported capture header"),
            Self::TruncatedInput { .. } => formatter.write_str("capture input is truncated"),
            Self::ResourceLimit { kind, .. } => write!(formatter, "capture import {kind:?} limit"),
            Self::NotReady => formatter.write_str("capture import is not ready to finalize"),
            Self::OwnershipInvariant => formatter.write_str("capture ownership invariant failed"),
            Self::Model(error) => write!(formatter, "capture model invariant failed: {error:?}"),
            Self::Arithmetic => formatter.write_str("capture import arithmetic overflow"),
        }
    }
}

impl std::error::Error for ImportError {}

/// Monotonic import counters suitable for worker progress messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImportProgress {
    /// Source bytes belonging to completely consumed records.
    pub consumed_bytes: u64,
    /// Exact source byte length.
    pub total_bytes: u64,
    /// Completely processed container records, including headers and metadata blocks.
    pub records_processed: u64,
    /// Packet records retained in the canonical model.
    pub packets_retained: u64,
    /// Structured diagnostics retained so far.
    pub diagnostics: u32,
}

/// Outcome of one bounded importer step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportStep {
    /// The budget was consumed and more input remains.
    Progress(ImportProgress),
    /// The next complete record cannot fit the byte budget without consuming it.
    NeedsBudget {
        /// Unchanged progress.
        progress: ImportProgress,
        /// Minimum byte budget needed for the next record.
        minimum_bytes: u64,
    },
    /// Clean EOF or a safely diagnosed terminal condition was reached.
    Ready(ImportProgress),
}

/// Borrowed packet bytes and metadata supplied to one protocol decode.
///
/// `bytes` is valid only for the duration of [`PacketDecoder::decode`]. The
/// corresponding [`Self::data_range`] remains an absolute range into the
/// capture allocation retained by the completed dataset.
#[derive(Clone, Copy, Debug)]
pub struct PacketDecodeInput<'a> {
    packet_id: PacketId,
    link_type: LinkType,
    data_range: ByteRange,
    bytes: &'a [u8],
}

impl<'a> PacketDecodeInput<'a> {
    /// Returns the stable packet identity being decoded.
    #[must_use]
    pub const fn packet_id(self) -> PacketId {
        self.packet_id
    }

    /// Returns the capture-interface link type for this packet.
    #[must_use]
    pub const fn link_type(self) -> LinkType {
        self.link_type
    }

    /// Returns the packet's absolute range in the capture allocation.
    #[must_use]
    pub const fn data_range(self) -> ByteRange {
        self.data_range
    }

    /// Returns the packet bytes borrowed from the active framing step.
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// Platform-neutral protocol decoder invoked while a framed packet slice is live.
pub trait PacketDecoder {
    /// Decodes one packet into the bounded canonical arenas exposed by `sink`.
    ///
    /// Returning an error rolls back every layer, field, child reference,
    /// diagnostic, and string created by this invocation.
    ///
    /// # Errors
    ///
    /// Returns a redacted import, resource, arithmetic, or model error.
    fn decode(
        &mut self,
        input: PacketDecodeInput<'_>,
        sink: &mut PacketDecodeSink<'_>,
    ) -> Result<(), ImportError>;
}

/// Bounded append-only view of the canonical decode arenas for one packet.
///
/// Field parents must be appended before their children. Add a parent with
/// [`Self::add_field`], append its descendants, then establish its consecutive
/// child span with [`Self::set_field_children`].
pub struct PacketDecodeSink<'a> {
    builder: &'a mut DatasetBuilder,
    packet_id: PacketId,
    packet_range: ByteRange,
    layer_start: usize,
    field_start: usize,
    child_start: usize,
}

impl PacketDecodeSink<'_> {
    /// Interns a protocol identifier, field label, value, or safe diagnostic message.
    ///
    /// # Errors
    ///
    /// Returns a string resource-limit or arithmetic error.
    pub fn intern(&mut self, value: &str) -> Result<StringId, ImportError> {
        self.builder.intern(value)
    }

    /// Appends one initially childless field owned by this packet decode.
    ///
    /// The evidence range and any byte-reference value must remain within the
    /// packet range. `name` and string values must already be interned.
    ///
    /// # Errors
    ///
    /// Returns a field resource-limit, range, string, or arithmetic error.
    pub fn add_field(
        &mut self,
        name: StringId,
        value: FieldValue,
        byte_range: ByteRange,
    ) -> Result<FieldId, ImportError> {
        self.validate_string_id(name)?;
        if let FieldValue::String(id) = value {
            self.validate_string_id(id)?;
        }
        if !range_contains(self.packet_range, byte_range)
            || matches!(value, FieldValue::Bytes(range) if !range_contains(self.packet_range, range))
        {
            return Err(ImportError::Model(ModelError::ByteRange));
        }
        self.ensure_per_packet_capacity(
            self.builder.fields.len(),
            self.field_start,
            self.builder.limits.max_fields_per_packet,
            ImportLimitKind::FieldsPerPacket,
        )?;
        Self::ensure_total_additional_capacity(
            self.builder.fields.len(),
            1,
            self.builder.limits.max_fields,
            ImportLimitKind::Fields,
            byte_range.start(),
        )?;
        reserve_arena(
            &mut self.builder.fields,
            1,
            ImportLimitKind::Fields,
            self.builder.limits.max_fields,
            byte_range.start(),
        )?;
        let id =
            FieldId(u32::try_from(self.builder.fields.len()).map_err(|_| ImportError::Arithmetic)?);
        self.builder.fields.push(DecodedField {
            name,
            value,
            byte_range,
            children: IndexRange::default(),
        });
        Ok(id)
    }

    /// Assigns the consecutive children of a parent created by this decode.
    ///
    /// Every child must have been appended after `parent`, remain inside the
    /// parent's byte range, and not already belong to another parent or layer.
    ///
    /// # Errors
    ///
    /// Returns a hierarchy, resource-limit, or arithmetic error.
    pub fn set_field_children(
        &mut self,
        parent: FieldId,
        children: &[FieldId],
    ) -> Result<(), ImportError> {
        let parent_index = self.local_field_index(parent)?;
        let parent_field = self.builder.fields[parent_index];
        if parent_field.children.length() != 0 {
            return Err(ImportError::Model(ModelError::FieldHierarchy));
        }
        let child_count = u32::try_from(children.len()).map_err(|_| ImportError::Arithmetic)?;
        self.ensure_per_packet_additional_capacity(
            self.builder.field_children.len(),
            self.child_start,
            child_count,
            self.builder.limits.max_field_children_per_packet,
            ImportLimitKind::FieldChildrenPerPacket,
        )?;
        Self::ensure_total_additional_capacity(
            self.builder.field_children.len(),
            child_count,
            self.builder.limits.max_field_children,
            ImportLimitKind::FieldChildren,
            parent_field.byte_range.start(),
        )?;
        let start = u32::try_from(self.builder.field_children.len())
            .map_err(|_| ImportError::Arithmetic)?;
        let assigned_children = &self.builder.field_children[self.child_start..];
        let packet_layers = &self.builder.layers[self.layer_start..];
        for (position, child) in children.iter().copied().enumerate() {
            let child_index = self.local_field_index(child)?;
            if child.0 <= parent.0
                || children[..position].contains(&child)
                || assigned_children.contains(&child)
                || packet_layers
                    .iter()
                    .any(|layer| layer.root_field == Some(child))
                || !range_contains(
                    parent_field.byte_range,
                    self.builder.fields[child_index].byte_range,
                )
            {
                return Err(ImportError::Model(ModelError::FieldHierarchy));
            }
        }
        reserve_arena(
            &mut self.builder.field_children,
            children.len(),
            ImportLimitKind::FieldChildren,
            self.builder.limits.max_field_children,
            parent_field.byte_range.start(),
        )?;
        self.builder.field_children.extend_from_slice(children);
        self.builder.fields[parent_index].children =
            IndexRange::new(start, child_count).ok_or(ImportError::Arithmetic)?;
        Ok(())
    }

    /// Appends one protocol layer owned by this packet.
    ///
    /// # Errors
    ///
    /// Returns a layer resource-limit, hierarchy, range, string, or arithmetic error.
    pub fn add_layer(
        &mut self,
        protocol: StringId,
        byte_range: ByteRange,
        root_field: Option<FieldId>,
    ) -> Result<(), ImportError> {
        self.validate_string_id(protocol)?;
        if !range_contains(self.packet_range, byte_range) {
            return Err(ImportError::Model(ModelError::ByteRange));
        }
        if let Some(root) = root_field {
            let root_index = self.local_field_index(root)?;
            if !range_contains(byte_range, self.builder.fields[root_index].byte_range)
                || self.builder.field_children[self.child_start..].contains(&root)
                || self.builder.layers[self.layer_start..]
                    .iter()
                    .any(|layer| layer.root_field == Some(root))
            {
                return Err(ImportError::Model(ModelError::FieldHierarchy));
            }
        }
        self.ensure_per_packet_capacity(
            self.builder.layers.len(),
            self.layer_start,
            self.builder.limits.max_layers_per_packet,
            ImportLimitKind::LayersPerPacket,
        )?;
        Self::ensure_total_additional_capacity(
            self.builder.layers.len(),
            1,
            self.builder.limits.max_layers,
            ImportLimitKind::Layers,
            byte_range.start(),
        )?;
        reserve_arena(
            &mut self.builder.layers,
            1,
            ImportLimitKind::Layers,
            self.builder.limits.max_layers,
            byte_range.start(),
        )?;
        self.builder.layers.push(LayerFact {
            protocol,
            byte_range,
            root_field,
        });
        Ok(())
    }

    /// Appends one packet-scoped structured diagnostic.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic resource-limit, range, string, or arithmetic error.
    pub fn add_diagnostic(
        &mut self,
        code: DiagnosticCode,
        severity: Severity,
        recovery: Recovery,
        byte_range: Option<ByteRange>,
        message: StringId,
    ) -> Result<(), ImportError> {
        self.validate_string_id(message)?;
        if byte_range.is_some_and(|range| !range_contains(self.packet_range, range)) {
            return Err(ImportError::Model(ModelError::ByteRange));
        }
        self.builder.ensure_diagnostic_capacity(
            byte_range.map_or(self.packet_range.start(), ByteRange::start),
        )?;
        self.builder.diagnostics.push(Diagnostic {
            code,
            severity,
            scope: DiagnosticScope::Packet(self.packet_id),
            byte_range,
            message,
            recovery,
        });
        Ok(())
    }

    fn validate_string_id(&self, id: StringId) -> Result<(), ImportError> {
        if (id.0 as usize) < self.builder.strings.len() {
            Ok(())
        } else {
            Err(ImportError::Model(ModelError::StringId))
        }
    }

    fn local_field_index(&self, id: FieldId) -> Result<usize, ImportError> {
        let index = id.0 as usize;
        if index >= self.field_start && index < self.builder.fields.len() {
            Ok(index)
        } else {
            Err(ImportError::Model(ModelError::FieldHierarchy))
        }
    }

    fn ensure_per_packet_capacity(
        &self,
        current: usize,
        start: usize,
        limit: u32,
        kind: ImportLimitKind,
    ) -> Result<(), ImportError> {
        self.ensure_per_packet_additional_capacity(current, start, 1, limit, kind)
    }

    fn ensure_per_packet_additional_capacity(
        &self,
        current: usize,
        start: usize,
        additional: u32,
        limit: u32,
        kind: ImportLimitKind,
    ) -> Result<(), ImportError> {
        let retained = current.checked_sub(start).ok_or(ImportError::Arithmetic)?;
        let projected = u64::try_from(retained)
            .map_err(|_| ImportError::Arithmetic)?
            .checked_add(u64::from(additional))
            .ok_or(ImportError::Arithmetic)?;
        if projected > u64::from(limit) {
            return Err(ImportError::ResourceLimit {
                kind,
                limit: u64::from(limit),
                offset: self.packet_range.start(),
            });
        }
        Ok(())
    }

    fn ensure_total_additional_capacity(
        current: usize,
        additional: u32,
        limit: u32,
        kind: ImportLimitKind,
        offset: u64,
    ) -> Result<(), ImportError> {
        let projected = u64::try_from(current)
            .map_err(|_| ImportError::Arithmetic)?
            .checked_add(u64::from(additional))
            .ok_or(ImportError::Arithmetic)?;
        if projected > u64::from(limit) {
            return Err(ImportError::ResourceLimit {
                kind,
                limit: u64::from(limit),
                offset,
            });
        }
        Ok(())
    }

    fn validate_complete(&self) -> Result<(), ImportError> {
        for field_index in self.field_start..self.builder.fields.len() {
            let id = FieldId(u32::try_from(field_index).map_err(|_| ImportError::Arithmetic)?);
            let parent_count = self.builder.field_children[self.child_start..]
                .iter()
                .filter(|candidate| **candidate == id)
                .count();
            let root_count = self.builder.layers[self.layer_start..]
                .iter()
                .filter(|layer| layer.root_field == Some(id))
                .count();
            if parent_count > 1 || root_count > 1 || (parent_count == 0) != (root_count == 1) {
                return Err(ImportError::Model(ModelError::FieldHierarchy));
            }
        }
        Ok(())
    }
}

/// Incremental importer whose temporary parser views never escape a step.
pub struct CaptureImporter {
    source: Arc<Box<[u8]>>,
    reader: Option<CaptureReader>,
    read_limit: Arc<AtomicUsize>,
    builder: DatasetBuilder,
    decoder: Option<Box<dyn PacketDecoder + Send>>,
    limits: ImportLimits,
    complete: bool,
    consumed_bytes: u64,
    records_processed: u64,
}

impl fmt::Debug for CaptureImporter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CaptureImporter")
            .field("progress", &self.progress())
            .field("complete", &self.complete)
            .finish_non_exhaustive()
    }
}

impl CaptureImporter {
    /// Creates an importer around the exact allocation supplied by its caller.
    ///
    /// The allocation is shared only with the buffered reader while import is
    /// active. [`finish`](Self::finish) recovers the same `Box<[u8]>` without a
    /// capture-sized clone.
    ///
    /// # Errors
    ///
    /// Returns a redacted header, truncation, limit, or arithmetic error before
    /// retaining any parser view.
    pub fn new(bytes: Box<[u8]>, limits: ImportLimits) -> Result<Self, ImportError> {
        Self::new_internal(bytes, limits, None)
    }

    /// Creates an importer that invokes `decoder` for every retained packet.
    ///
    /// Packet bytes remain borrowed from the active parser step and cannot
    /// escape [`PacketDecoder::decode`].
    ///
    /// # Errors
    ///
    /// Returns a redacted header, truncation, limit, or arithmetic error before
    /// retaining any parser view.
    pub fn new_with_decoder(
        bytes: Box<[u8]>,
        limits: ImportLimits,
        decoder: Box<dyn PacketDecoder + Send>,
    ) -> Result<Self, ImportError> {
        Self::new_internal(bytes, limits, Some(decoder))
    }

    fn new_internal(
        bytes: Box<[u8]>,
        limits: ImportLimits,
        decoder: Option<Box<dyn PacketDecoder + Send>>,
    ) -> Result<Self, ImportError> {
        validate_limits(limits)?;
        let byte_length = u64::try_from(bytes.len()).map_err(|_| ImportError::Arithmetic)?;
        if byte_length > limits.max_capture_bytes || byte_length > u64::from(u32::MAX) {
            return Err(ImportError::ResourceLimit {
                kind: ImportLimitKind::CaptureBytes,
                limit: limits.max_capture_bytes.min(u64::from(u32::MAX)),
                offset: 0,
            });
        }

        let preflight = preflight(&bytes, limits)?;
        let source = Arc::new(bytes);
        let read_limit = Arc::new(AtomicUsize::new(preflight.initial_capacity));
        let cursor = SharedCursor::new(Arc::clone(&source), Arc::clone(&read_limit));
        let reader = match preflight.format {
            CaptureFormat::Pcap => LegacyPcapReader::new(preflight.initial_capacity, cursor)
                .map(CaptureReader::Legacy)
                .map_err(|_| ImportError::InvalidHeader)?,
            CaptureFormat::PcapNg => PcapNGReader::new(preflight.initial_capacity, cursor)
                .map(CaptureReader::PcapNg)
                .map_err(|_| ImportError::InvalidHeader)?,
        };
        let builder = DatasetBuilder::new(preflight, byte_length, limits);
        read_limit.store(DEFAULT_BUFFER_BYTES, Ordering::Relaxed);

        Ok(Self {
            source,
            reader: Some(reader),
            read_limit,
            builder,
            decoder,
            limits,
            complete: false,
            consumed_bytes: 0,
            records_processed: 0,
        })
    }

    /// Returns current monotonic progress without exposing parser buffers.
    #[must_use]
    pub fn progress(&self) -> ImportProgress {
        ImportProgress {
            consumed_bytes: self.consumed_bytes,
            total_bytes: self.builder.byte_length,
            records_processed: self.records_processed,
            packets_retained: self.builder.packets.len() as u64,
            diagnostics: u32::try_from(self.builder.diagnostics.len()).unwrap_or(u32::MAX),
        }
    }

    /// Returns whether the importer can be consumed by [`finish`](Self::finish).
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        self.complete
    }

    /// Processes at most `max_records` and `max_bytes` of complete framing.
    ///
    /// A record larger than `max_bytes` is left unconsumed and reported through
    /// [`ImportStep::NeedsBudget`]. Internal reader allocation remains bounded
    /// by [`ImportLimits::max_block_bytes`].
    ///
    /// # Errors
    ///
    /// Returns a structured resource, ownership, or arithmetic failure. Parse
    /// damage that can safely yield a partial dataset becomes a diagnostic and
    /// [`ImportStep::Ready`].
    #[allow(clippy::too_many_lines)] // Keeping the reader transition loop together makes its bounds auditable.
    pub fn step(&mut self, max_records: u32, max_bytes: u64) -> Result<ImportStep, ImportError> {
        if max_records == 0 || max_bytes == 0 {
            return Err(ImportError::InvalidStepBudget);
        }
        if self.complete {
            return Ok(ImportStep::Ready(self.progress()));
        }

        let mut records_this_step = 0_u32;
        let mut bytes_this_step = 0_u64;
        let mut decoded_items_this_step = 0_u32;
        loop {
            if records_this_step >= max_records {
                return Ok(ImportStep::Progress(self.progress()));
            }

            let remaining_budget = max_bytes
                .checked_sub(bytes_this_step)
                .ok_or(ImportError::Arithmetic)?;
            let (next_length_result, available_header_bytes) = {
                let data = self
                    .reader
                    .as_ref()
                    .ok_or(ImportError::OwnershipInvariant)?
                    .data();
                (self.builder.next_length_hint(data), data.len())
            };
            let mut next_decoded_items = 0_u32;
            let next_length = match next_length_result {
                Ok(length) => length,
                Err(ImportError::InvalidHeader) => {
                    self.stop_malformed(self.consumed_bytes, available_header_bytes.min(12))?;
                    return Ok(ImportStep::Ready(self.progress()));
                }
                Err(error) => return Err(error),
            };
            if let Some(next_length) = next_length {
                let is_global_header = self.format_is_unconsumed_legacy_header();
                if !is_global_header && next_length > u64::from(self.limits.max_block_bytes) {
                    return Err(ImportError::ResourceLimit {
                        kind: ImportLimitKind::BlockBytes,
                        limit: u64::from(self.limits.max_block_bytes),
                        offset: self.consumed_bytes,
                    });
                }
                if self.builder.format == CaptureFormat::PcapNg {
                    let respects_section = {
                        let data = self
                            .reader
                            .as_ref()
                            .ok_or(ImportError::OwnershipInvariant)?
                            .data();
                        self.builder.next_block_respects_section(
                            data,
                            self.consumed_bytes,
                            next_length,
                        )
                    };
                    if !respects_section {
                        self.stop_malformed(self.consumed_bytes, available_header_bytes.min(12))?;
                        return Ok(ImportStep::Ready(self.progress()));
                    }
                }
                if next_length > self.builder.byte_length.saturating_sub(self.consumed_bytes) {
                    self.stop_truncated()?;
                    return Ok(ImportStep::Ready(self.progress()));
                }
                if next_length > remaining_budget {
                    if records_this_step == 0 {
                        return Ok(ImportStep::NeedsBudget {
                            progress: self.progress(),
                            minimum_bytes: next_length,
                        });
                    }
                    return Ok(ImportStep::Progress(self.progress()));
                }

                if self.builder.format == CaptureFormat::PcapNg {
                    let length =
                        usize::try_from(next_length).map_err(|_| ImportError::Arithmetic)?;
                    let scan_result = {
                        let data = self
                            .reader
                            .as_ref()
                            .ok_or(ImportError::OwnershipInvariant)?
                            .data();
                        if data.len() >= length {
                            self.builder
                                .prevalidate_pcapng_block(&data[..length], self.consumed_bytes)
                        } else {
                            Ok(0)
                        }
                    };
                    match scan_result {
                        Ok(decoded_items) => {
                            let projected = decoded_items_this_step
                                .checked_add(decoded_items)
                                .ok_or(ImportError::Arithmetic)?;
                            if projected > self.limits.max_decoded_items_per_step {
                                return Ok(ImportStep::Progress(self.progress()));
                            }
                            next_decoded_items = decoded_items;
                        }
                        Err(ImportError::InvalidHeader) => {
                            self.stop_malformed(self.consumed_bytes, length)?;
                            return Ok(ImportStep::Ready(self.progress()));
                        }
                        Err(error) => return Err(error),
                    }
                }
            }
            let refill_limit = usize::try_from(remaining_budget)
                .unwrap_or(usize::MAX)
                .clamp(24, DEFAULT_BUFFER_BYTES);
            self.read_limit.store(refill_limit, Ordering::Relaxed);

            let next = self
                .reader
                .as_mut()
                .ok_or(ImportError::OwnershipInvariant)?
                .next();
            match next {
                Ok((offset, block)) => {
                    let offset_u64 = u64::try_from(offset).map_err(|_| ImportError::Arithmetic)?;
                    if offset == 0 {
                        drop(block);
                        self.stop_malformed(self.consumed_bytes, 0)?;
                        return Ok(ImportStep::Ready(self.progress()));
                    }
                    if bytes_this_step
                        .checked_add(offset_u64)
                        .is_none_or(|total| total > max_bytes)
                    {
                        drop(block);
                        if records_this_step == 0 {
                            return Ok(ImportStep::NeedsBudget {
                                progress: self.progress(),
                                minimum_bytes: offset_u64,
                            });
                        }
                        return Ok(ImportStep::Progress(self.progress()));
                    }

                    let block_start = self.consumed_bytes;
                    let outcome = self.builder.process(
                        block_start,
                        offset,
                        block,
                        self.decoder.as_deref_mut(),
                    )?;
                    if matches!(outcome, ProcessOutcome::StopMalformed) {
                        self.stop_malformed(block_start, offset)?;
                        return Ok(ImportStep::Ready(self.progress()));
                    }

                    self.reader
                        .as_mut()
                        .ok_or(ImportError::OwnershipInvariant)?
                        .consume(offset);
                    self.consumed_bytes = self
                        .consumed_bytes
                        .checked_add(offset_u64)
                        .ok_or(ImportError::Arithmetic)?;
                    self.records_processed = self
                        .records_processed
                        .checked_add(1)
                        .ok_or(ImportError::Arithmetic)?;
                    records_this_step += 1;
                    bytes_this_step += offset_u64;
                    decoded_items_this_step = decoded_items_this_step
                        .checked_add(next_decoded_items)
                        .ok_or(ImportError::Arithmetic)?;
                    if decoded_items_this_step >= self.limits.max_decoded_items_per_step {
                        return Ok(ImportStep::Progress(self.progress()));
                    }
                }
                Err(PcapError::Incomplete(_)) => {
                    self.reader
                        .as_mut()
                        .ok_or(ImportError::OwnershipInvariant)?
                        .refill()
                        .map_err(|error| map_reader_error(&error))?;
                }
                Err(PcapError::BufferTooSmall) => match self.required_buffer_size()? {
                    RequiredBuffer::Grow(required) => {
                        let grown = self
                            .reader
                            .as_mut()
                            .ok_or(ImportError::OwnershipInvariant)?
                            .grow(required);
                        if !grown {
                            return Err(ImportError::OwnershipInvariant);
                        }
                        self.reader
                            .as_mut()
                            .ok_or(ImportError::OwnershipInvariant)?
                            .refill()
                            .map_err(|error| map_reader_error(&error))?;
                    }
                    RequiredBuffer::Truncated => {
                        self.stop_truncated()?;
                        return Ok(ImportStep::Ready(self.progress()));
                    }
                },
                Err(PcapError::Eof) => {
                    if !self
                        .builder
                        .section_boundary_matches(self.builder.byte_length)
                    {
                        self.stop_malformed(self.consumed_bytes, 0)?;
                        return Ok(ImportStep::Ready(self.progress()));
                    }
                    if self.consumed_bytes < self.builder.byte_length {
                        self.stop_truncated()?;
                        return Ok(ImportStep::Ready(self.progress()));
                    }
                    self.complete = true;
                    self.builder.close_last_section()?;
                    return Ok(ImportStep::Ready(self.progress()));
                }
                Err(PcapError::UnexpectedEof) => {
                    if self
                        .builder
                        .section_boundary_matches(self.builder.byte_length)
                    {
                        self.stop_truncated()?;
                    } else {
                        self.stop_malformed(self.consumed_bytes, 0)?;
                    }
                    return Ok(ImportStep::Ready(self.progress()));
                }
                Err(
                    PcapError::NomError(_, _)
                    | PcapError::OwnedNomError(_, _)
                    | PcapError::HeaderNotRecognized,
                ) => {
                    self.stop_malformed(self.consumed_bytes, 0)?;
                    return Ok(ImportStep::Ready(self.progress()));
                }
                Err(PcapError::ReadError) => return Err(ImportError::OwnershipInvariant),
            }
        }
    }

    /// Consumes a terminal importer and validates its canonical dataset.
    ///
    /// # Errors
    ///
    /// Returns [`ImportError::NotReady`] before a terminal step, or a redacted
    /// ownership/model error if internal finalization invariants fail.
    pub fn finish(self) -> Result<CaptureDataset, ImportError> {
        if !self.complete {
            return Err(ImportError::NotReady);
        }
        let Self {
            source,
            reader,
            builder,
            ..
        } = self;
        drop(reader);
        let bytes = Arc::try_unwrap(source).map_err(|_| ImportError::OwnershipInvariant)?;
        builder.finish(bytes)
    }

    /// Consumes the importer, releasing source and temporary allocations.
    #[must_use]
    pub fn cancel(self) -> ImportProgress {
        self.progress()
    }

    fn stop_truncated(&mut self) -> Result<(), ImportError> {
        self.builder.add_capture_diagnostic(
            DiagnosticCode::TRUNCATED_RECORD,
            Severity::Error,
            Recovery::RecordSkipped,
            range_to_end(self.consumed_bytes, self.builder.byte_length)?,
            MESSAGE_TRUNCATED,
        )?;
        self.complete = true;
        self.builder.close_last_section()
    }

    fn stop_malformed(&mut self, start: u64, parsed_length: usize) -> Result<(), ImportError> {
        let available = self.builder.byte_length.saturating_sub(start);
        let evidence_length = u64::try_from(parsed_length)
            .unwrap_or(u64::MAX)
            .min(available);
        self.builder.add_capture_diagnostic(
            DiagnosticCode::INVALID_CAPTURE_HEADER,
            Severity::Error,
            Recovery::RecordSkipped,
            checked_range(start, evidence_length)?,
            MESSAGE_MALFORMED,
        )?;
        self.complete = true;
        self.builder.close_section_at(start)
    }

    fn required_buffer_size(&self) -> Result<RequiredBuffer, ImportError> {
        let reader = self
            .reader
            .as_ref()
            .ok_or(ImportError::OwnershipInvariant)?;
        let data = reader.data();
        let declared = self.builder.next_declared_length(data)?;
        let remaining = self.builder.byte_length.saturating_sub(self.consumed_bytes);
        if declared > u64::from(self.limits.max_block_bytes) {
            return Err(ImportError::ResourceLimit {
                kind: ImportLimitKind::BlockBytes,
                limit: u64::from(self.limits.max_block_bytes),
                offset: self.consumed_bytes,
            });
        }
        if declared > remaining {
            return Ok(RequiredBuffer::Truncated);
        }
        let required = usize::try_from(declared)
            .ok()
            .and_then(|size| size.checked_add(1))
            .ok_or(ImportError::Arithmetic)?;
        Ok(RequiredBuffer::Grow(required))
    }

    fn format_is_unconsumed_legacy_header(&self) -> bool {
        self.builder.format == CaptureFormat::Pcap && !self.builder.legacy_initialized
    }
}

enum RequiredBuffer {
    Grow(usize),
    Truncated,
}

fn validate_limits(limits: ImportLimits) -> Result<(), ImportError> {
    if limits.max_capture_bytes == 0
        || limits.max_block_bytes < 32
        || limits.max_decoded_items_per_block == 0
        || limits.max_decoded_items_per_step < limits.max_decoded_items_per_block
        || limits.max_packets == 0
        || limits.max_sections == 0
        || limits.max_interfaces == 0
        || limits.max_diagnostics == 0
        || limits.max_layers_per_packet == 0
        || limits.max_layers < limits.max_layers_per_packet
        || limits.max_fields_per_packet == 0
        || limits.max_fields < limits.max_fields_per_packet
        || limits.max_field_children_per_packet == 0
        || limits.max_field_children < limits.max_field_children_per_packet
        || usize::try_from(limits.max_string_bytes)
            .ok()
            .is_none_or(|bytes| bytes < MIN_DIAGNOSTIC_STRING_BYTES)
    {
        return Err(ImportError::InvalidLimits);
    }
    Ok(())
}

fn map_reader_error(error: &PcapError<&[u8]>) -> ImportError {
    match error {
        PcapError::ReadError => ImportError::OwnershipInvariant,
        PcapError::BufferTooSmall
        | PcapError::UnexpectedEof
        | PcapError::Incomplete(_)
        | PcapError::NomError(_, _)
        | PcapError::OwnedNomError(_, _)
        | PcapError::HeaderNotRecognized
        | PcapError::Eof => ImportError::InvalidHeader,
    }
}

struct SharedCursor {
    source: Arc<Box<[u8]>>,
    position: usize,
    read_limit: Arc<AtomicUsize>,
}

impl SharedCursor {
    fn new(source: Arc<Box<[u8]>>, read_limit: Arc<AtomicUsize>) -> Self {
        Self {
            source,
            position: 0,
            read_limit,
        }
    }
}

impl Read for SharedCursor {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        let remaining = &self.source[self.position..];
        let count = remaining
            .len()
            .min(destination.len())
            .min(self.read_limit.load(Ordering::Relaxed));
        destination[..count].copy_from_slice(&remaining[..count]);
        self.position += count;
        Ok(count)
    }
}

enum CaptureReader {
    Legacy(LegacyPcapReader<SharedCursor>),
    PcapNg(PcapNGReader<SharedCursor>),
}

impl CaptureReader {
    fn next(&mut self) -> Result<(usize, PcapBlockOwned<'_>), PcapError<&[u8]>> {
        match self {
            Self::Legacy(reader) => reader.next(),
            Self::PcapNg(reader) => reader.next(),
        }
    }

    fn consume(&mut self, offset: usize) {
        match self {
            Self::Legacy(reader) => reader.consume(offset),
            Self::PcapNg(reader) => reader.consume(offset),
        }
    }

    fn refill(&mut self) -> Result<(), PcapError<&[u8]>> {
        match self {
            Self::Legacy(reader) => reader.refill(),
            Self::PcapNg(reader) => reader.refill(),
        }
    }

    fn grow(&mut self, size: usize) -> bool {
        match self {
            Self::Legacy(reader) => reader.grow(size),
            Self::PcapNg(reader) => reader.grow(size),
        }
    }

    fn data(&self) -> &[u8] {
        match self {
            Self::Legacy(reader) => reader.data(),
            Self::PcapNg(reader) => reader.data(),
        }
    }
}

#[derive(Clone, Copy)]
struct Preflight {
    format: CaptureFormat,
    byte_order: ByteOrder,
    initial_capacity: usize,
    legacy_modified: bool,
    legacy_nanosecond: bool,
}

fn preflight(bytes: &[u8], limits: ImportLimits) -> Result<Preflight, ImportError> {
    if bytes.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]) {
        preflight_pcapng(bytes, limits)
    } else {
        preflight_legacy(bytes, limits)
    }
}

fn preflight_legacy(bytes: &[u8], limits: ImportLimits) -> Result<Preflight, ImportError> {
    let (_, header) = match parse_pcap_header(bytes) {
        Ok(parsed) => parsed,
        Err(pcap_parser::nom::Err::Incomplete(_)) => {
            return Err(ImportError::TruncatedInput { offset: 0 });
        }
        Err(pcap_parser::nom::Err::Error(_) | pcap_parser::nom::Err::Failure(_)) => {
            return Err(ImportError::InvalidHeader);
        }
    };
    validate_legacy_header(&header)?;
    let initial_capacity = bounded_initial_capacity(bytes.len(), 24, limits.max_block_bytes)?;
    Ok(Preflight {
        format: CaptureFormat::Pcap,
        byte_order: if header.is_bigendian() {
            ByteOrder::BigEndian
        } else {
            ByteOrder::LittleEndian
        },
        initial_capacity,
        legacy_modified: header.is_modified_format(),
        legacy_nanosecond: header.is_nanosecond_precision(),
    })
}

fn validate_legacy_header(header: &PcapHeader) -> Result<(), ImportError> {
    if header.version_major != 2 || header.version_minor != 4 || header.snaplen == 0 {
        return Err(ImportError::InvalidHeader);
    }
    Ok(())
}

fn preflight_pcapng(bytes: &[u8], limits: ImportLimits) -> Result<Preflight, ImportError> {
    if bytes.len() < 12 {
        return Err(ImportError::TruncatedInput { offset: 0 });
    }
    let order = match &bytes[8..12] {
        [0x4d, 0x3c, 0x2b, 0x1a] => ByteOrder::LittleEndian,
        [0x1a, 0x2b, 0x3c, 0x4d] => ByteOrder::BigEndian,
        _ => return Err(ImportError::InvalidHeader),
    };
    let raw_length: [u8; 4] = bytes[4..8]
        .try_into()
        .map_err(|_| ImportError::Arithmetic)?;
    let declared_from_header = match order {
        ByteOrder::LittleEndian => u32::from_le_bytes(raw_length),
        ByteOrder::BigEndian => u32::from_be_bytes(raw_length),
    };
    if declared_from_header > limits.max_block_bytes {
        return Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::BlockBytes,
            limit: u64::from(limits.max_block_bytes),
            offset: 0,
        });
    }
    if declared_from_header as usize > bytes.len() {
        return Err(ImportError::TruncatedInput { offset: 0 });
    }
    let _ = prevalidate_pcapng_block_bytes(
        &bytes[..declared_from_header as usize],
        order,
        limits.max_decoded_items_per_block,
        0,
    )?;
    let (_, section) = match parse_sectionheaderblock(bytes) {
        Ok(parsed) => parsed,
        Err(pcap_parser::nom::Err::Incomplete(_)) => {
            return Err(ImportError::TruncatedInput { offset: 0 });
        }
        Err(pcap_parser::nom::Err::Error(_) | pcap_parser::nom::Err::Failure(_)) => {
            return Err(ImportError::InvalidHeader);
        }
    };
    let declared = section.block_len1;
    if declared < 28
        || declared % 4 != 0
        || declared != section.block_len2
        || section.major_version != 1
        || !matches!(section.minor_version, 0 | 2)
        || section.section_len < -1
        || (section.section_len >= 0 && section.section_len % 4 != 0)
    {
        return Err(ImportError::InvalidHeader);
    }
    if declared > limits.max_block_bytes {
        return Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::BlockBytes,
            limit: u64::from(limits.max_block_bytes),
            offset: 0,
        });
    }
    let initial_capacity = bounded_initial_capacity(
        bytes.len(),
        usize::try_from(declared).map_err(|_| ImportError::Arithmetic)?,
        limits.max_block_bytes,
    )?;
    Ok(Preflight {
        format: CaptureFormat::PcapNg,
        byte_order: order,
        initial_capacity,
        legacy_modified: false,
        legacy_nanosecond: false,
    })
}

fn bounded_initial_capacity(
    capture_length: usize,
    required: usize,
    max_block_bytes: u32,
) -> Result<usize, ImportError> {
    let capture_plus_one = capture_length
        .checked_add(1)
        .ok_or(ImportError::Arithmetic)?;
    let maximum = usize::try_from(max_block_bytes)
        .ok()
        .and_then(|value| value.checked_add(1))
        .ok_or(ImportError::Arithmetic)?;
    let baseline = capture_plus_one.min(DEFAULT_BUFFER_BYTES.min(maximum));
    required
        .checked_add(1)
        .map(|needed| baseline.max(needed))
        .filter(|capacity| *capacity <= maximum)
        .ok_or(ImportError::ResourceLimit {
            kind: ImportLimitKind::BlockBytes,
            limit: u64::from(max_block_bytes),
            offset: 0,
        })
}

/// Validates allocation-driving PCAPNG lists directly from one complete block.
///
/// `pcap-parser` represents options and name records as `Vec` entries. This
/// allocation-free pass rejects malformed list framing and excessive item
/// counts before the dependency is allowed to construct either vector.
fn prevalidate_pcapng_block_bytes(
    block: &[u8],
    section_order: ByteOrder,
    max_items: u32,
    block_start: u64,
) -> Result<u32, ImportError> {
    if block.len() < 12 {
        return Err(ImportError::InvalidHeader);
    }
    let is_section = block[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
    let order = if is_section {
        match &block[8..12] {
            [0x4d, 0x3c, 0x2b, 0x1a] => ByteOrder::LittleEndian,
            [0x1a, 0x2b, 0x3c, 0x4d] => ByteOrder::BigEndian,
            _ => return Err(ImportError::InvalidHeader),
        }
    } else {
        section_order
    };
    let declared = read_ng_u32(block, 4, order)?;
    let trailing_offset = block.len().checked_sub(4).ok_or(ImportError::Arithmetic)?;
    let trailing = read_ng_u32(block, trailing_offset, order)?;
    if declared < 12
        || declared % 4 != 0
        || usize::try_from(declared).ok() != Some(block.len())
        || trailing != declared
    {
        return Err(ImportError::InvalidHeader);
    }

    let block_type = read_ng_u32(block, 0, order)?;
    let options_start = match block_type {
        PCAPNG_SHB_TYPE => {
            if block.len() < 28 {
                return Err(ImportError::InvalidHeader);
            }
            let section_length = read_ng_i64(block, 16, order)?;
            if section_length < -1 || (section_length >= 0 && section_length % 4 != 0) {
                return Err(ImportError::InvalidHeader);
            }
            Some(24)
        }
        PCAPNG_IDB_TYPE => checked_options_start(block, 16)?,
        PCAPNG_EPB_TYPE => {
            if block.len() < 32 {
                return Err(ImportError::InvalidHeader);
            }
            let captured_length = read_ng_u32(block, 20, order)?;
            Some(padded_payload_options_start(
                28,
                captured_length,
                trailing_offset,
            )?)
        }
        PCAPNG_NRB_TYPE => {
            return prevalidate_name_records(block, order, trailing_offset, max_items, block_start);
        }
        PCAPNG_ISB_TYPE => checked_options_start(block, 20)?,
        PCAPNG_DSB_TYPE => {
            if block.len() < 20 {
                return Err(ImportError::InvalidHeader);
            }
            let secrets_length = read_ng_u32(block, 12, order)?;
            Some(padded_payload_options_start(
                16,
                secrets_length,
                trailing_offset,
            )?)
        }
        PCAPNG_PIB_TYPE => checked_options_start(block, 12)?,
        _ => None,
    };
    if let Some(options_start) = options_start {
        return prevalidate_options(
            block,
            order,
            options_start,
            trailing_offset,
            0,
            max_items,
            block_start,
        );
    }
    Ok(0)
}

fn checked_options_start(block: &[u8], start: usize) -> Result<Option<usize>, ImportError> {
    if start > block.len().saturating_sub(4) {
        return Err(ImportError::InvalidHeader);
    }
    Ok(Some(start))
}

fn padded_payload_options_start(
    payload_start: usize,
    payload_length: u32,
    trailing_offset: usize,
) -> Result<usize, ImportError> {
    let padded = usize::try_from(align4(payload_length).ok_or(ImportError::InvalidHeader)?)
        .map_err(|_| ImportError::Arithmetic)?;
    let start = payload_start
        .checked_add(padded)
        .ok_or(ImportError::InvalidHeader)?;
    if start > trailing_offset {
        return Err(ImportError::InvalidHeader);
    }
    Ok(start)
}

fn prevalidate_name_records(
    block: &[u8],
    order: ByteOrder,
    end: usize,
    max_items: u32,
    block_start: u64,
) -> Result<u32, ImportError> {
    let mut cursor = 8_usize;
    let mut decoded_items = 0_u32;
    loop {
        let header_end = cursor.checked_add(4).ok_or(ImportError::InvalidHeader)?;
        if header_end > end {
            return Err(ImportError::InvalidHeader);
        }
        let record_type = read_ng_u16(block, cursor, order)?;
        let record_length = read_ng_u16(block, cursor + 2, order)?;
        decoded_items = checked_decoded_item(decoded_items, max_items, block_start)?;
        cursor = header_end;
        if record_type == 0 {
            if record_length != 0 {
                return Err(ImportError::InvalidHeader);
            }
            break;
        }
        let padded = usize::from(record_length)
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or(ImportError::InvalidHeader)?;
        cursor = cursor
            .checked_add(padded)
            .ok_or(ImportError::InvalidHeader)?;
        if cursor > end {
            return Err(ImportError::InvalidHeader);
        }
    }
    prevalidate_options(
        block,
        order,
        cursor,
        end,
        decoded_items,
        max_items,
        block_start,
    )
}

#[allow(clippy::too_many_arguments)]
fn prevalidate_options(
    block: &[u8],
    order: ByteOrder,
    mut cursor: usize,
    end: usize,
    mut decoded_items: u32,
    max_items: u32,
    block_start: u64,
) -> Result<u32, ImportError> {
    while cursor < end {
        let header_end = cursor.checked_add(4).ok_or(ImportError::InvalidHeader)?;
        if header_end > end {
            return Err(ImportError::InvalidHeader);
        }
        let value_length = read_ng_u16(block, cursor + 2, order)?;
        decoded_items = checked_decoded_item(decoded_items, max_items, block_start)?;
        let padded = usize::from(value_length)
            .checked_add(3)
            .map(|length| length & !3)
            .ok_or(ImportError::InvalidHeader)?;
        cursor = header_end
            .checked_add(padded)
            .ok_or(ImportError::InvalidHeader)?;
        if cursor > end {
            return Err(ImportError::InvalidHeader);
        }
    }
    Ok(decoded_items)
}

fn checked_decoded_item(current: u32, maximum: u32, offset: u64) -> Result<u32, ImportError> {
    if current >= maximum {
        return Err(ImportError::ResourceLimit {
            kind: ImportLimitKind::DecodedItemsPerBlock,
            limit: u64::from(maximum),
            offset,
        });
    }
    Ok(current + 1)
}

fn read_ng_u16(bytes: &[u8], offset: usize, order: ByteOrder) -> Result<u16, ImportError> {
    let end = offset.checked_add(2).ok_or(ImportError::Arithmetic)?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or(ImportError::InvalidHeader)?
        .try_into()
        .map_err(|_| ImportError::Arithmetic)?;
    Ok(match order {
        ByteOrder::LittleEndian => u16::from_le_bytes(raw),
        ByteOrder::BigEndian => u16::from_be_bytes(raw),
    })
}

fn read_ng_u32(bytes: &[u8], offset: usize, order: ByteOrder) -> Result<u32, ImportError> {
    let end = offset.checked_add(4).ok_or(ImportError::Arithmetic)?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(ImportError::InvalidHeader)?
        .try_into()
        .map_err(|_| ImportError::Arithmetic)?;
    Ok(match order {
        ByteOrder::LittleEndian => u32::from_le_bytes(raw),
        ByteOrder::BigEndian => u32::from_be_bytes(raw),
    })
}

fn read_ng_i64(bytes: &[u8], offset: usize, order: ByteOrder) -> Result<i64, ImportError> {
    let end = offset.checked_add(8).ok_or(ImportError::Arithmetic)?;
    let raw: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(ImportError::InvalidHeader)?
        .try_into()
        .map_err(|_| ImportError::Arithmetic)?;
    Ok(match order {
        ByteOrder::LittleEndian => i64::from_le_bytes(raw),
        ByteOrder::BigEndian => i64::from_be_bytes(raw),
    })
}

struct DatasetBuilder {
    format: CaptureFormat,
    byte_length: u64,
    sections: Vec<SectionMetadata>,
    interfaces: Vec<InterfaceMetadata>,
    interface_offsets: Vec<i64>,
    packets: Vec<PacketRecord>,
    layers: Vec<LayerFact>,
    fields: Vec<DecodedField>,
    field_children: Vec<FieldId>,
    diagnostics: Vec<Diagnostic>,
    strings: BTreeMap<Box<str>, StringId>,
    string_bytes: usize,
    current_section: Option<OpenSection>,
    legacy_order: ByteOrder,
    legacy_modified: bool,
    legacy_nanosecond: bool,
    legacy_initialized: bool,
    started_at: Option<CaptureTimestamp>,
    ended_at: Option<CaptureTimestamp>,
    limits: ImportLimits,
}

#[derive(Clone, Copy)]
struct OpenSection {
    metadata_index: usize,
    start: u64,
    interface_start: u32,
    byte_order: ByteOrder,
    declared_end: Option<u64>,
}

#[derive(Clone, Copy)]
struct DecodeCheckpoint {
    layers: usize,
    fields: usize,
    field_children: usize,
    diagnostics: usize,
    strings: usize,
    string_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessOutcome {
    Continue,
    StopMalformed,
}

impl DatasetBuilder {
    fn new(preflight: Preflight, byte_length: u64, limits: ImportLimits) -> Self {
        Self {
            format: preflight.format,
            byte_length,
            sections: Vec::new(),
            interfaces: Vec::new(),
            interface_offsets: Vec::new(),
            packets: Vec::new(),
            layers: Vec::new(),
            fields: Vec::new(),
            field_children: Vec::new(),
            diagnostics: Vec::new(),
            strings: BTreeMap::new(),
            string_bytes: 0,
            current_section: None,
            legacy_order: preflight.byte_order,
            legacy_modified: preflight.legacy_modified,
            legacy_nanosecond: preflight.legacy_nanosecond,
            legacy_initialized: false,
            started_at: None,
            ended_at: None,
            limits,
        }
    }

    fn process(
        &mut self,
        block_start: u64,
        parsed_length: usize,
        block: PcapBlockOwned<'_>,
        decoder: Option<&mut (dyn PacketDecoder + Send + '_)>,
    ) -> Result<ProcessOutcome, ImportError> {
        match block {
            PcapBlockOwned::LegacyHeader(header) => {
                self.process_legacy_header(&header)?;
                Ok(ProcessOutcome::Continue)
            }
            PcapBlockOwned::Legacy(packet) => {
                self.process_legacy_packet(block_start, parsed_length, &packet, decoder)
            }
            PcapBlockOwned::NG(block) => {
                self.process_pcapng(block_start, parsed_length, block, decoder)
            }
        }
    }

    fn prevalidate_pcapng_block(&self, block: &[u8], block_start: u64) -> Result<u32, ImportError> {
        let order = self
            .current_section
            .map_or(self.legacy_order, |section| section.byte_order);
        prevalidate_pcapng_block_bytes(
            block,
            order,
            self.limits.max_decoded_items_per_block,
            block_start,
        )
    }

    fn section_boundary_matches(&self, end: u64) -> bool {
        self.current_section
            .and_then(|section| section.declared_end)
            .is_none_or(|declared_end| declared_end == end)
    }

    fn next_block_respects_section(&self, data: &[u8], start: u64, length: u64) -> bool {
        let Some(declared_end) = self
            .current_section
            .and_then(|section| section.declared_end)
        else {
            return true;
        };
        let is_section = data.starts_with(&[0x0a, 0x0d, 0x0d, 0x0a]);
        if is_section {
            return start == declared_end;
        }
        start < declared_end
            && start
                .checked_add(length)
                .is_some_and(|block_end| block_end <= declared_end)
    }

    fn process_legacy_header(&mut self, header: &PcapHeader) -> Result<(), ImportError> {
        if self.format != CaptureFormat::Pcap || self.legacy_initialized {
            return Err(ImportError::InvalidHeader);
        }
        validate_legacy_header(header)?;
        reserve_arena(
            &mut self.sections,
            1,
            ImportLimitKind::Sections,
            self.limits.max_sections,
            0,
        )?;
        reserve_arena(
            &mut self.interfaces,
            1,
            ImportLimitKind::Interfaces,
            self.limits.max_interfaces,
            0,
        )?;
        reserve_arena(
            &mut self.interface_offsets,
            1,
            ImportLimitKind::Interfaces,
            self.limits.max_interfaces,
            0,
        )?;
        let section_range = checked_range(0, self.byte_length)?.ok_or(ImportError::Arithmetic)?;
        let section_id = SectionId(0);
        self.sections.push(SectionMetadata {
            id: section_id,
            byte_range: section_range,
            byte_order: self.legacy_order,
            interfaces: IndexRange::new(0, 1).ok_or(ImportError::Arithmetic)?,
        });
        self.interfaces.push(InterfaceMetadata {
            id: InterfaceId(0),
            section_id,
            byte_range: ByteRange::new(0, 24).ok_or(ImportError::Arithmetic)?,
            section_index: 0,
            link_type: LinkType(u32::from_ne_bytes(header.network.0.to_ne_bytes())),
            snap_length: header.snaplen,
            timestamp_resolution: if self.legacy_nanosecond {
                TimestampResolution::Decimal(9)
            } else {
                TimestampResolution::Decimal(6)
            },
            name: None,
        });
        self.interface_offsets.push(0);
        self.legacy_initialized = true;
        Ok(())
    }

    fn process_legacy_packet(
        &mut self,
        block_start: u64,
        parsed_length: usize,
        packet: &pcap_parser::LegacyPcapBlock<'_>,
        decoder: Option<&mut (dyn PacketDecoder + Send + '_)>,
    ) -> Result<ProcessOutcome, ImportError> {
        if !self.legacy_initialized {
            return Ok(ProcessOutcome::StopMalformed);
        }
        let header_length = if self.legacy_modified { 24_u64 } else { 16_u64 };
        let expected = header_length
            .checked_add(u64::from(packet.caplen))
            .ok_or(ImportError::Arithmetic)?;
        if expected != parsed_length as u64 || packet.data.len() != packet.caplen as usize {
            return Ok(ProcessOutcome::StopMalformed);
        }
        self.ensure_packet_capacity(block_start)?;
        let packet_id =
            PacketId(u32::try_from(self.packets.len()).map_err(|_| ImportError::Arithmetic)?);
        let data_start = block_start
            .checked_add(header_length)
            .ok_or(ImportError::Arithmetic)?;
        let data = ByteRange::new(data_start, packet.caplen).ok_or(ImportError::Arithmetic)?;
        let layer_start = u32::try_from(self.layers.len()).map_err(|_| ImportError::Arithmetic)?;
        let (diagnostic_start, retrying_packet) = self.packet_diagnostic_start(packet_id)?;
        if !retrying_packet
            && (packet.caplen > self.interfaces[0].snap_length || packet.caplen > packet.origlen)
        {
            self.add_packet_diagnostic(
                packet_id,
                DiagnosticCode::INCONSISTENT_LENGTH,
                data,
                MESSAGE_INCONSISTENT_LENGTH,
            )?;
        }
        let resolution = self.interfaces[0].timestamp_resolution;
        let timestamp = CaptureTimestamp::new(
            i64::from(packet.ts_sec),
            u64::from(packet.ts_usec),
            resolution,
        )
        .ok();
        if !retrying_packet && timestamp.is_none() {
            self.add_packet_diagnostic(
                packet_id,
                DiagnosticCode::INVALID_TIMESTAMP,
                data,
                MESSAGE_INVALID_TIMESTAMP,
            )?;
        }
        self.decode_packet(
            packet_id,
            self.interfaces[0].link_type,
            data,
            packet.data,
            decoder,
        )?;
        let layer_count = u32::try_from(self.layers.len())
            .map_err(|_| ImportError::Arithmetic)?
            .checked_sub(layer_start)
            .ok_or(ImportError::Arithmetic)?;
        let diagnostic_count = u32::try_from(self.diagnostics.len())
            .map_err(|_| ImportError::Arithmetic)?
            .checked_sub(diagnostic_start)
            .ok_or(ImportError::Arithmetic)?;
        self.push_packet(PacketRecord {
            id: packet_id,
            section_id: SectionId(0),
            interface_id: InterfaceId(0),
            timestamp,
            captured_length: packet.caplen,
            original_length: packet.origlen,
            data,
            layers: IndexRange::new(layer_start, layer_count).ok_or(ImportError::Arithmetic)?,
            diagnostics: IndexRange::new(diagnostic_start, diagnostic_count)
                .ok_or(ImportError::Arithmetic)?,
        });
        Ok(ProcessOutcome::Continue)
    }

    fn process_pcapng(
        &mut self,
        block_start: u64,
        parsed_length: usize,
        block: Block<'_>,
        decoder: Option<&mut (dyn PacketDecoder + Send + '_)>,
    ) -> Result<ProcessOutcome, ImportError> {
        let (declared, trailing) = ng_block_lengths(&block);
        if declared < 12
            || declared % 4 != 0
            || declared != trailing
            || usize::try_from(declared).ok() != Some(parsed_length)
            || declared > self.limits.max_block_bytes
        {
            return Ok(ProcessOutcome::StopMalformed);
        }

        let block_end = block_start
            .checked_add(u64::from(declared))
            .ok_or(ImportError::Arithmetic)?;
        if !matches!(&block, Block::SectionHeader(_))
            && self
                .current_section
                .and_then(|section| section.declared_end)
                .is_some_and(|declared_end| block_start >= declared_end || block_end > declared_end)
        {
            return Ok(ProcessOutcome::StopMalformed);
        }

        match block {
            Block::SectionHeader(section) => self.process_section_header(block_start, &section),
            Block::InterfaceDescription(interface) => {
                self.process_interface(block_start, declared, &interface)
            }
            Block::EnhancedPacket(packet) => {
                self.process_enhanced_packet(block_start, declared, &packet, decoder)
            }
            Block::SimplePacket(packet) => {
                self.process_simple_packet(block_start, declared, &packet, decoder)
            }
            Block::NameResolution(_)
            | Block::InterfaceStatistics(_)
            | Block::SystemdJournalExport(_)
            | Block::DecryptionSecrets(_)
            | Block::ProcessInformation(_)
            | Block::Custom(_)
            | Block::Unknown(_) => {
                self.add_capture_diagnostic(
                    DiagnosticCode::UNSUPPORTED_BLOCK,
                    Severity::Info,
                    Recovery::RecordSkipped,
                    Some(ByteRange::new(block_start, declared).ok_or(ImportError::Arithmetic)?),
                    MESSAGE_UNSUPPORTED_BLOCK,
                )?;
                Ok(ProcessOutcome::Continue)
            }
        }
    }

    fn process_section_header(
        &mut self,
        block_start: u64,
        section: &pcap_parser::SectionHeaderBlock<'_>,
    ) -> Result<ProcessOutcome, ImportError> {
        if section.major_version != 1
            || !matches!(section.minor_version, 0 | 2)
            || section.section_len < -1
            || (section.section_len >= 0 && section.section_len % 4 != 0)
        {
            return Ok(ProcessOutcome::StopMalformed);
        }
        if !self.section_boundary_matches(block_start) {
            return Ok(ProcessOutcome::StopMalformed);
        }
        self.close_section_at(block_start)?;
        if self.sections.len() >= self.limits.max_sections as usize {
            return Err(Self::limit_error(
                ImportLimitKind::Sections,
                self.limits.max_sections,
                block_start,
            ));
        }
        reserve_arena(
            &mut self.sections,
            1,
            ImportLimitKind::Sections,
            self.limits.max_sections,
            block_start,
        )?;
        let id =
            SectionId(u32::try_from(self.sections.len()).map_err(|_| ImportError::Arithmetic)?);
        let interface_start =
            u32::try_from(self.interfaces.len()).map_err(|_| ImportError::Arithmetic)?;
        let byte_order = if section.big_endian() {
            ByteOrder::BigEndian
        } else {
            ByteOrder::LittleEndian
        };
        let declared_end = if section.section_len < 0 {
            None
        } else {
            let body_length =
                u64::try_from(section.section_len).map_err(|_| ImportError::Arithmetic)?;
            block_start
                .checked_add(u64::from(section.block_len1))
                .and_then(|after_header| after_header.checked_add(body_length))
        };
        if section.section_len >= 0 && declared_end.is_none() {
            return Ok(ProcessOutcome::StopMalformed);
        }
        self.sections.push(SectionMetadata {
            id,
            byte_range: ByteRange::new(block_start, 0).ok_or(ImportError::Arithmetic)?,
            byte_order,
            interfaces: IndexRange::new(interface_start, 0).ok_or(ImportError::Arithmetic)?,
        });
        self.current_section = Some(OpenSection {
            metadata_index: id.0 as usize,
            start: block_start,
            interface_start,
            byte_order,
            declared_end,
        });
        Ok(ProcessOutcome::Continue)
    }

    fn process_interface(
        &mut self,
        block_start: u64,
        block_length: u32,
        interface: &pcap_parser::InterfaceDescriptionBlock<'_>,
    ) -> Result<ProcessOutcome, ImportError> {
        let Some(section) = self.current_section else {
            return Ok(ProcessOutcome::StopMalformed);
        };
        if self.interfaces.len() >= self.limits.max_interfaces as usize {
            return Err(Self::limit_error(
                ImportLimitKind::Interfaces,
                self.limits.max_interfaces,
                block_start,
            ));
        }
        reserve_arena(
            &mut self.interfaces,
            1,
            ImportLimitKind::Interfaces,
            self.limits.max_interfaces,
            block_start,
        )?;
        reserve_arena(
            &mut self.interface_offsets,
            1,
            ImportLimitKind::Interfaces,
            self.limits.max_interfaces,
            block_start,
        )?;
        let (resolution, timestamp_offset, name, malformed_option) =
            self.interface_options(&interface.options, section.byte_order)?;
        if malformed_option {
            self.add_capture_diagnostic(
                DiagnosticCode::INVALID_TIMESTAMP,
                Severity::Warning,
                Recovery::Continued,
                Some(ByteRange::new(block_start, block_length).ok_or(ImportError::Arithmetic)?),
                MESSAGE_INVALID_OPTION,
            )?;
        }
        let id =
            InterfaceId(u32::try_from(self.interfaces.len()).map_err(|_| ImportError::Arithmetic)?);
        let section_index =
            id.0.checked_sub(section.interface_start)
                .ok_or(ImportError::Arithmetic)?;
        self.interfaces.push(InterfaceMetadata {
            id,
            section_id: SectionId(
                u32::try_from(section.metadata_index).map_err(|_| ImportError::Arithmetic)?,
            ),
            byte_range: ByteRange::new(block_start, block_length).ok_or(ImportError::Arithmetic)?,
            section_index,
            link_type: LinkType(u32::from_ne_bytes(interface.linktype.0.to_ne_bytes())),
            snap_length: interface.snaplen,
            timestamp_resolution: resolution,
            name,
        });
        self.interface_offsets.push(timestamp_offset);
        Ok(ProcessOutcome::Continue)
    }

    fn process_enhanced_packet(
        &mut self,
        block_start: u64,
        block_length: u32,
        packet: &pcap_parser::EnhancedPacketBlock<'_>,
        decoder: Option<&mut (dyn PacketDecoder + Send + '_)>,
    ) -> Result<ProcessOutcome, ImportError> {
        let Some(section) = self.current_section else {
            return Ok(ProcessOutcome::StopMalformed);
        };
        let Some(global_index) = section
            .interface_start
            .checked_add(packet.if_id)
            .and_then(|id| usize::try_from(id).ok())
            .filter(|index| *index < self.interfaces.len())
        else {
            self.add_capture_diagnostic(
                DiagnosticCode::INCONSISTENT_LENGTH,
                Severity::Error,
                Recovery::RecordSkipped,
                Some(ByteRange::new(block_start, block_length).ok_or(ImportError::Arithmetic)?),
                MESSAGE_MISSING_INTERFACE,
            )?;
            return Ok(ProcessOutcome::Continue);
        };
        if self.interfaces[global_index].section_id.0 as usize != section.metadata_index {
            return Ok(ProcessOutcome::StopMalformed);
        }
        let padded = align4(packet.caplen).ok_or(ImportError::Arithmetic)?;
        let minimum = 32_u32.checked_add(padded).ok_or(ImportError::Arithmetic)?;
        if block_length < minimum || packet.data.len() != padded as usize {
            return Ok(ProcessOutcome::StopMalformed);
        }
        self.ensure_packet_capacity(block_start)?;
        let packet_id =
            PacketId(u32::try_from(self.packets.len()).map_err(|_| ImportError::Arithmetic)?);
        let data_start = block_start.checked_add(28).ok_or(ImportError::Arithmetic)?;
        let data = ByteRange::new(data_start, packet.caplen).ok_or(ImportError::Arithmetic)?;
        let layer_start = u32::try_from(self.layers.len()).map_err(|_| ImportError::Arithmetic)?;
        let (diagnostic_start, retrying_packet) = self.packet_diagnostic_start(packet_id)?;
        let interface = self.interfaces[global_index];
        if !retrying_packet
            && ((interface.snap_length != 0 && packet.caplen > interface.snap_length)
                || packet.caplen > packet.origlen)
        {
            self.add_packet_diagnostic(
                packet_id,
                DiagnosticCode::INCONSISTENT_LENGTH,
                data,
                MESSAGE_INCONSISTENT_LENGTH,
            )?;
        }
        let timestamp = decode_pcapng_timestamp(
            packet.ts_high,
            packet.ts_low,
            interface.timestamp_resolution,
            self.interface_offsets[global_index],
        );
        if !retrying_packet && timestamp.is_none() {
            self.add_packet_diagnostic(
                packet_id,
                DiagnosticCode::INVALID_TIMESTAMP,
                data,
                MESSAGE_INVALID_TIMESTAMP,
            )?;
        }
        let captured = packet
            .data
            .get(..packet.caplen as usize)
            .ok_or(ImportError::Arithmetic)?;
        self.decode_packet(packet_id, interface.link_type, data, captured, decoder)?;
        let layer_count = u32::try_from(self.layers.len())
            .map_err(|_| ImportError::Arithmetic)?
            .checked_sub(layer_start)
            .ok_or(ImportError::Arithmetic)?;
        let diagnostic_count = u32::try_from(self.diagnostics.len())
            .map_err(|_| ImportError::Arithmetic)?
            .checked_sub(diagnostic_start)
            .ok_or(ImportError::Arithmetic)?;
        self.push_packet(PacketRecord {
            id: packet_id,
            section_id: interface.section_id,
            interface_id: interface.id,
            timestamp,
            captured_length: packet.caplen,
            original_length: packet.origlen,
            data,
            layers: IndexRange::new(layer_start, layer_count).ok_or(ImportError::Arithmetic)?,
            diagnostics: IndexRange::new(diagnostic_start, diagnostic_count)
                .ok_or(ImportError::Arithmetic)?,
        });
        Ok(ProcessOutcome::Continue)
    }

    fn process_simple_packet(
        &mut self,
        block_start: u64,
        block_length: u32,
        packet: &pcap_parser::SimplePacketBlock<'_>,
        decoder: Option<&mut (dyn PacketDecoder + Send + '_)>,
    ) -> Result<ProcessOutcome, ImportError> {
        let Some(section) = self.current_section else {
            return Ok(ProcessOutcome::StopMalformed);
        };
        let interface_index = section.interface_start as usize;
        let Some(interface) = self.interfaces.get(interface_index).copied() else {
            self.add_capture_diagnostic(
                DiagnosticCode::INCONSISTENT_LENGTH,
                Severity::Error,
                Recovery::RecordSkipped,
                Some(ByteRange::new(block_start, block_length).ok_or(ImportError::Arithmetic)?),
                MESSAGE_MISSING_INTERFACE,
            )?;
            return Ok(ProcessOutcome::Continue);
        };
        if interface.section_id.0 as usize != section.metadata_index || block_length < 16 {
            return Ok(ProcessOutcome::StopMalformed);
        }
        let captured_length = if interface.snap_length == 0 {
            packet.origlen
        } else {
            packet.origlen.min(interface.snap_length)
        };
        let padded = align4(captured_length).ok_or(ImportError::Arithmetic)?;
        let available_padded = block_length
            .checked_sub(16)
            .ok_or(ImportError::Arithmetic)?;
        if padded != available_padded || packet.data.len() != available_padded as usize {
            return Ok(ProcessOutcome::StopMalformed);
        }
        self.ensure_packet_capacity(block_start)?;
        let packet_id =
            PacketId(u32::try_from(self.packets.len()).map_err(|_| ImportError::Arithmetic)?);
        let data = ByteRange::new(
            block_start.checked_add(12).ok_or(ImportError::Arithmetic)?,
            captured_length,
        )
        .ok_or(ImportError::Arithmetic)?;
        let layer_start = u32::try_from(self.layers.len()).map_err(|_| ImportError::Arithmetic)?;
        let (diagnostic_start, _) = self.packet_diagnostic_start(packet_id)?;
        let captured = packet
            .data
            .get(..captured_length as usize)
            .ok_or(ImportError::Arithmetic)?;
        self.decode_packet(packet_id, interface.link_type, data, captured, decoder)?;
        let layer_count = u32::try_from(self.layers.len())
            .map_err(|_| ImportError::Arithmetic)?
            .checked_sub(layer_start)
            .ok_or(ImportError::Arithmetic)?;
        let diagnostic_count = u32::try_from(self.diagnostics.len())
            .map_err(|_| ImportError::Arithmetic)?
            .checked_sub(diagnostic_start)
            .ok_or(ImportError::Arithmetic)?;
        self.push_packet(PacketRecord {
            id: packet_id,
            section_id: interface.section_id,
            interface_id: interface.id,
            timestamp: None,
            captured_length,
            original_length: packet.origlen,
            data,
            layers: IndexRange::new(layer_start, layer_count).ok_or(ImportError::Arithmetic)?,
            diagnostics: IndexRange::new(diagnostic_start, diagnostic_count)
                .ok_or(ImportError::Arithmetic)?,
        });
        Ok(ProcessOutcome::Continue)
    }

    fn interface_options(
        &mut self,
        options: &[PcapNGOption<'_>],
        byte_order: ByteOrder,
    ) -> Result<(TimestampResolution, i64, Option<StringId>, bool), ImportError> {
        let mut resolution = TimestampResolution::Decimal(6);
        let mut timestamp_offset = 0_i64;
        let mut name = None;
        let mut seen_resolution = false;
        let mut seen_offset = false;
        let mut malformed = false;
        for option in options {
            if option.code == OptionCode::IfTsresol && !seen_resolution {
                seen_resolution = true;
                match option.as_bytes() {
                    Ok([raw]) => {
                        resolution = if raw & 0x80 == 0 {
                            TimestampResolution::Decimal(raw & 0x7f)
                        } else {
                            TimestampResolution::Binary(raw & 0x7f)
                        };
                    }
                    Ok(_) | Err(_) => malformed = true,
                }
            } else if option.code == OptionCode::IfTsoffset && !seen_offset {
                seen_offset = true;
                match option.as_bytes() {
                    Ok(value) if value.len() == 8 => {
                        let bytes: [u8; 8] =
                            value.try_into().map_err(|_| ImportError::Arithmetic)?;
                        timestamp_offset = match byte_order {
                            ByteOrder::LittleEndian => i64::from_le_bytes(bytes),
                            ByteOrder::BigEndian => i64::from_be_bytes(bytes),
                        };
                    }
                    Ok(_) | Err(_) => malformed = true,
                }
            } else if option.code == OptionCode::IfName && name.is_none() {
                match option
                    .as_bytes()
                    .ok()
                    .and_then(|value| std::str::from_utf8(value).ok())
                {
                    Some(value) => name = Some(self.intern(value)?),
                    None => malformed = true,
                }
            }
        }
        Ok((resolution, timestamp_offset, name, malformed))
    }

    fn next_length_hint(&self, data: &[u8]) -> Result<Option<u64>, ImportError> {
        match self.format {
            CaptureFormat::Pcap => {
                if !self.legacy_initialized {
                    return Ok(Some(24));
                }
                let header_length = if self.legacy_modified {
                    24_usize
                } else {
                    16_usize
                };
                if data.len() < header_length {
                    return Ok(None);
                }
                let raw: [u8; 4] = data[8..12]
                    .try_into()
                    .map_err(|_| ImportError::Arithmetic)?;
                let captured = match self.legacy_order {
                    ByteOrder::LittleEndian => u32::from_le_bytes(raw),
                    ByteOrder::BigEndian => u32::from_be_bytes(raw),
                };
                (header_length as u64)
                    .checked_add(u64::from(captured))
                    .map(Some)
                    .ok_or(ImportError::Arithmetic)
            }
            CaptureFormat::PcapNg => {
                if data.len() < 12 {
                    return Ok(None);
                }
                let is_section = data[..4] == [0x0a, 0x0d, 0x0d, 0x0a];
                let order = if is_section {
                    match &data[8..12] {
                        [0x4d, 0x3c, 0x2b, 0x1a] => ByteOrder::LittleEndian,
                        [0x1a, 0x2b, 0x3c, 0x4d] => ByteOrder::BigEndian,
                        _ => return Err(ImportError::InvalidHeader),
                    }
                } else {
                    self.current_section
                        .map_or(self.legacy_order, |section| section.byte_order)
                };
                let raw: [u8; 4] = data[4..8].try_into().map_err(|_| ImportError::Arithmetic)?;
                let declared = match order {
                    ByteOrder::LittleEndian => u32::from_le_bytes(raw),
                    ByteOrder::BigEndian => u32::from_be_bytes(raw),
                };
                if declared < 12 || declared % 4 != 0 {
                    return Err(ImportError::InvalidHeader);
                }
                Ok(Some(u64::from(declared)))
            }
        }
    }

    fn next_declared_length(&self, data: &[u8]) -> Result<u64, ImportError> {
        self.next_length_hint(data)?
            .ok_or(ImportError::InvalidHeader)
    }

    fn ensure_packet_capacity(&mut self, offset: u64) -> Result<(), ImportError> {
        if self.packets.len() >= self.limits.max_packets as usize {
            return Err(Self::limit_error(
                ImportLimitKind::Packets,
                self.limits.max_packets,
                offset,
            ));
        }
        reserve_arena(
            &mut self.packets,
            1,
            ImportLimitKind::Packets,
            self.limits.max_packets,
            offset,
        )
    }

    fn packet_diagnostic_start(&self, packet_id: PacketId) -> Result<(u32, bool), ImportError> {
        let mut start = self.diagnostics.len();
        while start > 0 && self.diagnostics[start - 1].scope == DiagnosticScope::Packet(packet_id) {
            start -= 1;
        }
        Ok((
            u32::try_from(start).map_err(|_| ImportError::Arithmetic)?,
            start != self.diagnostics.len(),
        ))
    }

    fn decode_packet(
        &mut self,
        packet_id: PacketId,
        link_type: LinkType,
        data_range: ByteRange,
        bytes: &[u8],
        decoder: Option<&mut (dyn PacketDecoder + Send + '_)>,
    ) -> Result<(), ImportError> {
        let Some(decoder) = decoder else {
            return Ok(());
        };
        if usize::try_from(data_range.length()).ok() != Some(bytes.len()) {
            return Err(ImportError::Model(ModelError::ByteRange));
        }
        let checkpoint = DecodeCheckpoint {
            layers: self.layers.len(),
            fields: self.fields.len(),
            field_children: self.field_children.len(),
            diagnostics: self.diagnostics.len(),
            strings: self.strings.len(),
            string_bytes: self.string_bytes,
        };
        let input = PacketDecodeInput {
            packet_id,
            link_type,
            data_range,
            bytes,
        };
        let result = {
            let mut sink = PacketDecodeSink {
                builder: self,
                packet_id,
                packet_range: data_range,
                layer_start: checkpoint.layers,
                field_start: checkpoint.fields,
                child_start: checkpoint.field_children,
            };
            decoder
                .decode(input, &mut sink)
                .and_then(|()| sink.validate_complete())
        };
        if let Err(error) = result {
            self.rollback_decode(checkpoint);
            return Err(error);
        }
        Ok(())
    }

    fn rollback_decode(&mut self, checkpoint: DecodeCheckpoint) {
        self.layers.truncate(checkpoint.layers);
        self.fields.truncate(checkpoint.fields);
        self.field_children.truncate(checkpoint.field_children);
        self.diagnostics.truncate(checkpoint.diagnostics);
        self.strings
            .retain(|_, id| (id.0 as usize) < checkpoint.strings);
        self.string_bytes = checkpoint.string_bytes;
    }

    fn push_packet(&mut self, packet: PacketRecord) {
        if let Some(timestamp) = packet.timestamp {
            if self
                .started_at
                .is_none_or(|current| timestamp.cmp_instant(current).is_lt())
            {
                self.started_at = Some(timestamp);
            }
            if self
                .ended_at
                .is_none_or(|current| timestamp.cmp_instant(current).is_gt())
            {
                self.ended_at = Some(timestamp);
            }
        }
        self.packets.push(packet);
    }

    fn add_packet_diagnostic(
        &mut self,
        packet_id: PacketId,
        code: DiagnosticCode,
        evidence: ByteRange,
        message: &str,
    ) -> Result<(), ImportError> {
        self.ensure_diagnostic_capacity(evidence.start())?;
        let message = self.intern(message)?;
        self.diagnostics.push(Diagnostic {
            code,
            severity: Severity::Warning,
            scope: DiagnosticScope::Packet(packet_id),
            byte_range: Some(evidence),
            message,
            recovery: Recovery::Continued,
        });
        Ok(())
    }

    fn add_capture_diagnostic(
        &mut self,
        code: DiagnosticCode,
        severity: Severity,
        recovery: Recovery,
        evidence: Option<ByteRange>,
        message: &str,
    ) -> Result<(), ImportError> {
        self.ensure_diagnostic_capacity(evidence.map_or(0, ByteRange::start))?;
        let message = self.intern(message)?;
        self.diagnostics.push(Diagnostic {
            code,
            severity,
            scope: DiagnosticScope::Capture,
            byte_range: evidence,
            message,
            recovery,
        });
        Ok(())
    }

    fn ensure_diagnostic_capacity(&mut self, offset: u64) -> Result<(), ImportError> {
        if self.diagnostics.len() >= self.limits.max_diagnostics as usize {
            return Err(Self::limit_error(
                ImportLimitKind::Diagnostics,
                self.limits.max_diagnostics,
                offset,
            ));
        }
        reserve_arena(
            &mut self.diagnostics,
            1,
            ImportLimitKind::Diagnostics,
            self.limits.max_diagnostics,
            offset,
        )
    }

    fn intern(&mut self, value: &str) -> Result<StringId, ImportError> {
        if let Some(id) = self.strings.get(value) {
            return Ok(*id);
        }
        let new_total = self
            .string_bytes
            .checked_add(value.len())
            .ok_or(ImportError::Arithmetic)?;
        if new_total > self.limits.max_string_bytes as usize {
            return Err(Self::limit_error(
                ImportLimitKind::StringBytes,
                self.limits.max_string_bytes,
                0,
            ));
        }
        let id = StringId(u32::try_from(self.strings.len()).map_err(|_| ImportError::Arithmetic)?);
        let mut owned = Vec::new();
        owned.try_reserve_exact(value.len()).map_err(|_| {
            Self::limit_error(
                ImportLimitKind::StringBytes,
                self.limits.max_string_bytes,
                0,
            )
        })?;
        owned.extend_from_slice(value.as_bytes());
        let owned = String::from_utf8(owned)
            .map_err(|_| ImportError::Arithmetic)?
            .into_boxed_str();
        self.strings.insert(owned, id);
        self.string_bytes = new_total;
        Ok(id)
    }

    fn close_last_section(&mut self) -> Result<(), ImportError> {
        self.close_section_at(self.byte_length)
    }

    fn close_section_at(&mut self, end: u64) -> Result<(), ImportError> {
        let Some(open) = self.current_section.take() else {
            return Ok(());
        };
        let length = end.checked_sub(open.start).ok_or(ImportError::Arithmetic)?;
        let interface_end =
            u32::try_from(self.interfaces.len()).map_err(|_| ImportError::Arithmetic)?;
        let interface_count = interface_end
            .checked_sub(open.interface_start)
            .ok_or(ImportError::Arithmetic)?;
        let metadata = self
            .sections
            .get_mut(open.metadata_index)
            .ok_or(ImportError::Arithmetic)?;
        metadata.byte_range = checked_range(open.start, length)?.ok_or(ImportError::Arithmetic)?;
        metadata.interfaces = IndexRange::new(open.interface_start, interface_count)
            .ok_or(ImportError::Arithmetic)?;
        Ok(())
    }

    fn finish(mut self, bytes: Box<[u8]>) -> Result<CaptureDataset, ImportError> {
        self.close_last_section()?;
        let string_count = self.strings.len();
        let mut ordered_strings: Vec<Option<Box<str>>> = Vec::new();
        ordered_strings
            .try_reserve_exact(string_count)
            .map_err(|_| {
                Self::limit_error(
                    ImportLimitKind::StringBytes,
                    self.limits.max_string_bytes,
                    0,
                )
            })?;
        ordered_strings.resize_with(string_count, || None);
        for (value, id) in self.strings {
            let slot = ordered_strings
                .get_mut(id.0 as usize)
                .ok_or(ImportError::Arithmetic)?;
            *slot = Some(value);
        }
        let mut strings = Vec::new();
        strings.try_reserve_exact(string_count).map_err(|_| {
            Self::limit_error(
                ImportLimitKind::StringBytes,
                self.limits.max_string_bytes,
                0,
            )
        })?;
        for value in ordered_strings {
            strings.push(value.ok_or(ImportError::Arithmetic)?);
        }
        let metadata = CaptureMetadata {
            format: self.format,
            byte_length: self.byte_length,
            packet_count: self.packets.len() as u64,
            started_at: self.started_at,
            ended_at: self.ended_at,
        };
        CaptureDataset::from_vec_parts(CaptureDatasetVecParts {
            metadata,
            bytes,
            sections: self.sections,
            interfaces: self.interfaces,
            packets: self.packets,
            layers: self.layers,
            fields: self.fields,
            field_children: self.field_children,
            diagnostics: self.diagnostics,
            strings,
        })
        .map_err(ImportError::Model)
    }

    fn limit_error(kind: ImportLimitKind, limit: u32, offset: u64) -> ImportError {
        ImportError::ResourceLimit {
            kind,
            limit: u64::from(limit),
            offset,
        }
    }
}

fn ng_block_lengths(block: &Block<'_>) -> (u32, u32) {
    match block {
        Block::SectionHeader(block) => (block.block_len1, block.block_len2),
        Block::InterfaceDescription(block) => (block.block_len1, block.block_len2),
        Block::EnhancedPacket(block) => (block.block_len1, block.block_len2),
        Block::SimplePacket(block) => (block.block_len1, block.block_len2),
        Block::NameResolution(block) => (block.block_len1, block.block_len2),
        Block::InterfaceStatistics(block) => (block.block_len1, block.block_len2),
        Block::SystemdJournalExport(block) => (block.block_len1, block.block_len2),
        Block::DecryptionSecrets(block) => (block.block_len1, block.block_len2),
        Block::ProcessInformation(block) => (block.block_len1, block.block_len2),
        Block::Custom(block) => (block.block_len1, block.block_len2),
        Block::Unknown(block) => (block.block_len1, block.block_len2),
    }
}

fn decode_pcapng_timestamp(
    high: u32,
    low: u32,
    resolution: TimestampResolution,
    offset: i64,
) -> Option<CaptureTimestamp> {
    let ticks = (u64::from(high) << 32) | u64::from(low);
    let (whole, fraction) = match resolution.ticks_per_second() {
        Some(per_second) => (ticks / per_second, ticks % per_second),
        None => (0, ticks),
    };
    let seconds = i64::try_from(whole).ok()?.checked_add(offset)?;
    CaptureTimestamp::new(seconds, fraction, resolution).ok()
}

fn align4(value: u32) -> Option<u32> {
    value.checked_add(3).map(|padded| padded & !3)
}

fn reserve_arena<T>(
    arena: &mut Vec<T>,
    additional: usize,
    kind: ImportLimitKind,
    limit: u32,
    offset: u64,
) -> Result<(), ImportError> {
    let resource_limit = || ImportError::ResourceLimit {
        kind,
        limit: u64::from(limit),
        offset,
    };
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let required = arena
        .len()
        .checked_add(additional)
        .ok_or(ImportError::Arithmetic)?;
    if arena.capacity() > limit {
        return Err(ImportError::OwnershipInvariant);
    }
    if required > limit {
        return Err(resource_limit());
    }
    if required <= arena.capacity() {
        return Ok(());
    }

    // Grow geometrically so repeated single-item appends remain amortized,
    // but clamp the requested capacity to the caller's hard arena ceiling.
    // `try_reserve_exact` avoids `Vec` applying a second geometric growth
    // policy after this cap-aware target has been selected.
    let target = required
        .max(arena.capacity().saturating_mul(2))
        .max(MIN_ARENA_CAPACITY)
        .min(limit);
    let reservation = target
        .checked_sub(arena.len())
        .ok_or(ImportError::Arithmetic)?;
    arena
        .try_reserve_exact(reservation)
        .map_err(|_| resource_limit())?;
    if arena.capacity() > limit {
        // Allocators may legally satisfy an exact request with more storage.
        // Refuse to publish an arena whose retained capacity exceeds its cap.
        return Err(ImportError::OwnershipInvariant);
    }
    Ok(())
}

fn checked_range(start: u64, length: u64) -> Result<Option<ByteRange>, ImportError> {
    let length = u32::try_from(length).map_err(|_| ImportError::Arithmetic)?;
    Ok(ByteRange::new(start, length))
}

fn range_to_end(start: u64, end: u64) -> Result<Option<ByteRange>, ImportError> {
    checked_range(start, end.saturating_sub(start))
}

fn range_contains(container: ByteRange, child: ByteRange) -> bool {
    child.start() >= container.start() && child.end() <= container.end()
}

#[cfg(test)]
mod tests {
    use super::{ImportError, ImportLimitKind, reserve_arena};

    #[test]
    fn arena_growth_is_geometric_and_clamped_to_a_non_power_of_two_limit() {
        const LIMIT: u32 = 13;
        let mut arena = Vec::<u64>::new();
        let mut capacity_changes = 0;

        for value in 0..LIMIT {
            let prior_capacity = arena.capacity();
            reserve_arena(
                &mut arena,
                1,
                ImportLimitKind::Packets,
                LIMIT,
                u64::from(value),
            )
            .expect("an item within the configured arena limit is admitted");
            if arena.capacity() != prior_capacity {
                capacity_changes += 1;
            }
            assert!(arena.capacity() <= LIMIT as usize);
            arena.push(u64::from(value));
        }

        assert_eq!(arena.len(), LIMIT as usize);
        assert_eq!(arena.capacity(), LIMIT as usize);
        assert!(
            capacity_changes <= 3,
            "geometric reservation must not grow once per append"
        );
    }

    #[test]
    fn arena_growth_reports_the_original_hostile_input_limit_error() {
        let mut arena = Vec::<u64>::new();
        let error = reserve_arena(&mut arena, 14, ImportLimitKind::Packets, 13, 99)
            .expect_err("a reservation beyond the hard total is rejected");

        assert_eq!(
            error,
            ImportError::ResourceLimit {
                kind: ImportLimitKind::Packets,
                limit: 13,
                offset: 99,
            }
        );
        assert!(arena.is_empty());
        assert_eq!(arena.capacity(), 0);
    }
}
