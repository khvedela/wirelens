//! Explicit packet-detail wire encoding.

use core::fmt;

use packet_core::{
    ByteRange, CaptureDataset, CorrelationError, DiagnosticCode, FieldValue, PacketFieldPath,
    PacketId, PacketRecord, PacketRelativeRange, StringId,
};

use crate::{BoundaryError, BoundaryErrorCode};

/// Current packet-detail binary schema.
pub const PACKET_DETAIL_SCHEMA_VERSION: u16 = 1;

pub(crate) const DETAIL_HEADER_BYTES: usize = 80;
pub(crate) const DETAIL_DESCRIPTOR_BYTES: usize = 24;
pub(crate) const DETAIL_COLUMN_COUNT: usize = 20;
const DETAIL_MAGIC: [u8; 8] = *b"WLPKDT01";
const FLAG_WIRE_TRUNCATED: u32 = 1;
const FLAG_PROTOCOL_TRUNCATED: u32 = 1 << 1;
const ABSENT_U32: u32 = u32::MAX;

const VALUE_NONE: u8 = 0;
const VALUE_UNSIGNED: u8 = 1;
const VALUE_SIGNED: u8 = 2;
const VALUE_BOOLEAN: u8 = 3;
const VALUE_STRING: u8 = 4;
const VALUE_BYTES: u8 = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DetailElementType {
    U8,
    U32,
    U64,
}

impl DetailElementType {
    const fn id(self) -> u8 {
        match self {
            Self::U8 => 1,
            Self::U32 => 2,
            Self::U64 => 3,
        }
    }

    const fn width(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U32 => 4,
            Self::U64 => 8,
        }
    }
}

#[derive(Clone, Copy)]
struct DetailColumnSpec {
    id: u16,
    element_type: DetailElementType,
    rows: DetailRows,
}

#[derive(Clone, Copy)]
enum DetailRows {
    Layers,
    Fields,
    Strings,
    Blob,
}

const DETAIL_COLUMN_SPECS: [DetailColumnSpec; DETAIL_COLUMN_COUNT] = [
    layer_column(1),
    layer_column(2),
    layer_column(3),
    layer_column(4),
    field_column(5, DetailElementType::U32),
    field_column(6, DetailElementType::U32),
    field_column(7, DetailElementType::U32),
    field_column(8, DetailElementType::U32),
    field_column(9, DetailElementType::U32),
    field_column(10, DetailElementType::U32),
    field_column(11, DetailElementType::U32),
    field_column(12, DetailElementType::U32),
    field_column(13, DetailElementType::U32),
    field_column(14, DetailElementType::U32),
    string_column(15),
    string_column(16),
    string_column(17),
    field_column(18, DetailElementType::U64),
    field_column(19, DetailElementType::U8),
    DetailColumnSpec {
        id: 20,
        element_type: DetailElementType::U8,
        rows: DetailRows::Blob,
    },
];

const fn layer_column(id: u16) -> DetailColumnSpec {
    DetailColumnSpec {
        id,
        element_type: DetailElementType::U32,
        rows: DetailRows::Layers,
    }
}

const fn field_column(id: u16, element_type: DetailElementType) -> DetailColumnSpec {
    DetailColumnSpec {
        id,
        element_type,
        rows: DetailRows::Fields,
    }
}

const fn string_column(id: u16) -> DetailColumnSpec {
    DetailColumnSpec {
        id,
        element_type: DetailElementType::U32,
        rows: DetailRows::Strings,
    }
}

#[derive(Clone, Copy, Debug)]
struct DetailColumnDescriptor {
    id: u16,
    element_type: DetailElementType,
    byte_offset: u32,
    element_count: u32,
    byte_length: u32,
}

#[derive(Clone, Copy)]
struct StringLayout {
    id: StringId,
    offset: u32,
    length: u32,
}

/// Owned, self-describing packet-detail response.
///
/// Raw packet bytes are deliberately excluded. Callers request bounded,
/// packet-relative evidence pages separately.
pub struct PacketDetailBatch {
    bytes: Box<[u8]>,
    packet_id: PacketId,
    layer_count: u32,
    field_count: u32,
    string_count: u32,
}

impl PacketDetailBatch {
    /// Returns the complete versioned binary payload.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the stable packet represented by this response.
    #[must_use]
    pub const fn packet_id(&self) -> PacketId {
        self.packet_id
    }

    /// Returns the number of encoded protocol layers.
    #[must_use]
    pub const fn layer_count(&self) -> u32 {
        self.layer_count
    }

    /// Returns the number of encoded decoded fields.
    #[must_use]
    pub const fn field_count(&self) -> u32 {
        self.field_count
    }

    /// Returns the number of referenced strings in the compact dictionary.
    #[must_use]
    pub const fn string_count(&self) -> u32 {
        self.string_count
    }
}

impl fmt::Debug for PacketDetailBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketDetailBatch")
            .field("byte_length", &self.bytes.len())
            .field("packet_id", &self.packet_id)
            .field("layer_count", &self.layer_count)
            .field("field_count", &self.field_count)
            .field("string_count", &self.string_count)
            .finish_non_exhaustive()
    }
}

pub(crate) fn encode_packet_detail(
    dataset: &CaptureDataset,
    packet_id: PacketId,
    api_version: u32,
    max_layers: u32,
    max_fields: u32,
    max_bytes: usize,
) -> Result<PacketDetailBatch, BoundaryError> {
    let packet = dataset.packet(packet_id).ok_or_else(packet_not_found)?;
    let layers = packet_layers(dataset, packet)?;
    let layer_count = u32::try_from(layers.len()).map_err(|_| arithmetic_error())?;
    if layer_count > max_layers {
        return Err(resource_error(
            "packet detail exceeds the protocol-layer limit",
            u64::from(max_layers),
        ));
    }
    let paths = dataset
        .packet_field_paths(packet_id, max_fields)
        .map_err(|error| correlation_error(error, max_fields))?;
    let field_count = u32::try_from(paths.len()).map_err(|_| arithmetic_error())?;
    let string_ids = referenced_strings(dataset, layers, &paths)?;
    let string_count = u32::try_from(string_ids.len()).map_err(|_| arithmetic_error())?;
    let (strings, blob_bytes) = string_layouts(dataset, &string_ids)?;
    let plan = plan_detail(
        layer_count,
        field_count,
        string_count,
        blob_bytes,
        max_bytes,
    )?;
    let mut bytes = allocate_detail_buffer(plan.total_bytes)?;

    let diagnostic_start = packet.diagnostics.start() as usize;
    let diagnostic_end = packet.diagnostics.end() as usize;
    let diagnostics = dataset
        .diagnostics()
        .get(diagnostic_start..diagnostic_end)
        .ok_or_else(internal_invariant)?;
    let protocol_truncated = diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::TRUNCATED_PROTOCOL);
    let flags = (u32::from(packet.original_length > packet.captured_length) * FLAG_WIRE_TRUNCATED)
        | (u32::from(protocol_truncated) * FLAG_PROTOCOL_TRUNCATED);

    bytes[0..DETAIL_MAGIC.len()].copy_from_slice(&DETAIL_MAGIC);
    write_u16(&mut bytes, 8, PACKET_DETAIL_SCHEMA_VERSION)?;
    write_u16(&mut bytes, 10, usize_to_u16(DETAIL_HEADER_BYTES)?)?;
    write_u32(&mut bytes, 12, api_version)?;
    write_u16(&mut bytes, 16, usize_to_u16(DETAIL_DESCRIPTOR_BYTES)?)?;
    write_u16(&mut bytes, 18, usize_to_u16(DETAIL_COLUMN_COUNT)?)?;
    write_u32(&mut bytes, 20, flags)?;
    write_u32(&mut bytes, 24, packet.id.0)?;
    write_u32(&mut bytes, 28, packet.captured_length)?;
    write_u32(&mut bytes, 32, packet.original_length)?;
    write_u32(&mut bytes, 36, layer_count)?;
    write_u32(&mut bytes, 40, field_count)?;
    write_u32(&mut bytes, 44, string_count)?;
    write_u32(&mut bytes, 48, usize_to_u32(DETAIL_HEADER_BYTES)?)?;
    write_u32(&mut bytes, 52, plan.data_offset)?;
    write_u32(&mut bytes, 56, usize_to_u32(plan.total_bytes)?)?;
    write_u32(&mut bytes, 60, blob_bytes)?;
    write_u64(&mut bytes, 64, packet.data.start())?;
    write_u32(&mut bytes, 72, packet.data.length())?;
    write_u32(&mut bytes, 76, 0)?;

    write_descriptors(&mut bytes, &plan.descriptors)?;
    write_layers(&mut bytes, &plan.descriptors, packet, layers)?;
    write_fields(dataset, &mut bytes, &plan.descriptors, packet, &paths)?;
    write_strings(dataset, &mut bytes, &plan.descriptors, &strings, blob_bytes)?;

    Ok(PacketDetailBatch {
        bytes: bytes.into_boxed_slice(),
        packet_id,
        layer_count,
        field_count,
        string_count,
    })
}

fn packet_layers<'a>(
    dataset: &'a CaptureDataset,
    packet: &PacketRecord,
) -> Result<&'a [packet_core::LayerFact], BoundaryError> {
    let start = packet.layers.start() as usize;
    let end = packet.layers.end() as usize;
    dataset
        .layers()
        .get(start..end)
        .ok_or_else(internal_invariant)
}

fn referenced_strings(
    dataset: &CaptureDataset,
    layers: &[packet_core::LayerFact],
    paths: &[PacketFieldPath],
) -> Result<Vec<StringId>, BoundaryError> {
    let capacity = layers
        .len()
        .checked_add(paths.len().checked_mul(2).ok_or_else(arithmetic_error)?)
        .ok_or_else(arithmetic_error)?;
    let mut ids = Vec::new();
    ids.try_reserve_exact(capacity)
        .map_err(|_| resource_error("packet detail string dictionary allocation failed", 0))?;
    ids.extend(layers.iter().map(|layer| layer.protocol));
    for path in paths {
        let field = dataset
            .fields()
            .get(path.field_id.0 as usize)
            .ok_or_else(internal_invariant)?;
        ids.push(field.name);
        if let FieldValue::String(id) = field.value {
            ids.push(id);
        }
    }
    ids.sort_unstable_by_key(|id| id.0);
    ids.dedup();
    for id in &ids {
        if dataset.string(*id).is_none() {
            return Err(internal_invariant());
        }
    }
    Ok(ids)
}

fn string_layouts(
    dataset: &CaptureDataset,
    ids: &[StringId],
) -> Result<(Vec<StringLayout>, u32), BoundaryError> {
    let mut layouts = Vec::new();
    layouts
        .try_reserve_exact(ids.len())
        .map_err(|_| resource_error("packet detail string layout allocation failed", 0))?;
    let mut cursor = 0_u32;
    for id in ids {
        let value = dataset.string(*id).ok_or_else(internal_invariant)?;
        let length = u32::try_from(value.len()).map_err(|_| arithmetic_error())?;
        layouts.push(StringLayout {
            id: *id,
            offset: cursor,
            length,
        });
        cursor = cursor.checked_add(length).ok_or_else(arithmetic_error)?;
    }
    Ok((layouts, cursor))
}

fn write_layers(
    output: &mut [u8],
    descriptors: &[DetailColumnDescriptor],
    packet: &PacketRecord,
    layers: &[packet_core::LayerFact],
) -> Result<(), BoundaryError> {
    for (row, layer) in layers.iter().enumerate() {
        let range = relative_range(packet, layer.byte_range)?;
        write_column_u32(output, &descriptors[0], row, layer.protocol.0)?;
        write_column_u32(output, &descriptors[1], row, range.start())?;
        write_column_u32(output, &descriptors[2], row, range.length())?;
        write_column_u32(
            output,
            &descriptors[3],
            row,
            layer.root_field.map_or(ABSENT_U32, |field| field.0),
        )?;
    }
    Ok(())
}

fn write_fields(
    dataset: &CaptureDataset,
    output: &mut [u8],
    descriptors: &[DetailColumnDescriptor],
    packet: &PacketRecord,
    paths: &[PacketFieldPath],
) -> Result<(), BoundaryError> {
    for (row, path) in paths.iter().enumerate() {
        let field = dataset
            .fields()
            .get(path.field_id.0 as usize)
            .ok_or_else(internal_invariant)?;
        let (kind, bits, string_id, bytes_start, bytes_length) = match field.value {
            FieldValue::None => (VALUE_NONE, 0, ABSENT_U32, 0, 0),
            FieldValue::Unsigned(value) => (VALUE_UNSIGNED, value, ABSENT_U32, 0, 0),
            FieldValue::Signed(value) => (
                VALUE_SIGNED,
                u64::from_le_bytes(value.to_le_bytes()),
                ABSENT_U32,
                0,
                0,
            ),
            FieldValue::Boolean(value) => (VALUE_BOOLEAN, u64::from(value), ABSENT_U32, 0, 0),
            FieldValue::String(value) => (VALUE_STRING, 0, value.0, 0, 0),
            FieldValue::Bytes(value) => {
                let range = relative_range(packet, value)?;
                if range.start() < path.byte_range.start() || range.end() > path.byte_range.end() {
                    return Err(internal_invariant());
                }
                (VALUE_BYTES, 0, ABSENT_U32, range.start(), range.length())
            }
        };
        write_column_u32(output, &descriptors[4], row, path.field_id.0)?;
        write_column_u32(
            output,
            &descriptors[5],
            row,
            path.parent_field_id.map_or(ABSENT_U32, |field| field.0),
        )?;
        write_column_u32(output, &descriptors[6], row, path.layer_index)?;
        write_column_u32(output, &descriptors[7], row, path.depth)?;
        write_column_u32(output, &descriptors[8], row, field.name.0)?;
        write_column_u32(output, &descriptors[9], row, path.byte_range.start())?;
        write_column_u32(output, &descriptors[10], row, path.byte_range.length())?;
        write_column_u32(output, &descriptors[11], row, string_id)?;
        write_column_u32(output, &descriptors[12], row, bytes_start)?;
        write_column_u32(output, &descriptors[13], row, bytes_length)?;
        write_column_u64(output, &descriptors[17], row, bits)?;
        write_column_u8(output, &descriptors[18], row, kind)?;
    }
    Ok(())
}

fn write_strings(
    dataset: &CaptureDataset,
    output: &mut [u8],
    descriptors: &[DetailColumnDescriptor],
    strings: &[StringLayout],
    blob_bytes: u32,
) -> Result<(), BoundaryError> {
    for (row, layout) in strings.iter().enumerate() {
        write_column_u32(output, &descriptors[14], row, layout.id.0)?;
        write_column_u32(output, &descriptors[15], row, layout.offset)?;
        write_column_u32(output, &descriptors[16], row, layout.length)?;
        let value = dataset.string(layout.id).ok_or_else(internal_invariant)?;
        let start = descriptors[19]
            .byte_offset
            .checked_add(layout.offset)
            .ok_or_else(arithmetic_error)?;
        write_at(output, start as usize, value.as_bytes())?;
    }
    if descriptors[19].element_count != blob_bytes {
        return Err(internal_invariant());
    }
    Ok(())
}

fn relative_range(
    packet: &PacketRecord,
    range: ByteRange,
) -> Result<PacketRelativeRange, BoundaryError> {
    let start = range
        .start()
        .checked_sub(packet.data.start())
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(internal_invariant)?;
    PacketRelativeRange::new(start, range.length())
        .filter(|relative| relative.end() <= packet.captured_length)
        .ok_or_else(internal_invariant)
}

#[derive(Debug)]
struct DetailPlan {
    descriptors: Vec<DetailColumnDescriptor>,
    data_offset: u32,
    total_bytes: usize,
}

fn plan_detail(
    layer_count: u32,
    field_count: u32,
    string_count: u32,
    blob_bytes: u32,
    max_bytes: usize,
) -> Result<DetailPlan, BoundaryError> {
    let descriptor_bytes = DETAIL_COLUMN_COUNT
        .checked_mul(DETAIL_DESCRIPTOR_BYTES)
        .ok_or_else(arithmetic_error)?;
    let data_offset = DETAIL_HEADER_BYTES
        .checked_add(descriptor_bytes)
        .ok_or_else(arithmetic_error)?;
    if data_offset > max_bytes {
        return Err(byte_limit_error());
    }
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve_exact(DETAIL_COLUMN_COUNT)
        .map_err(|_| resource_error("packet detail descriptor allocation failed", 0))?;
    let mut cursor = data_offset;
    for spec in DETAIL_COLUMN_SPECS {
        cursor = align_up(cursor, spec.element_type.width())?;
        let element_count = match spec.rows {
            DetailRows::Layers => layer_count,
            DetailRows::Fields => field_count,
            DetailRows::Strings => string_count,
            DetailRows::Blob => blob_bytes,
        };
        let byte_length = (element_count as usize)
            .checked_mul(spec.element_type.width())
            .ok_or_else(arithmetic_error)?;
        let end = cursor
            .checked_add(byte_length)
            .ok_or_else(arithmetic_error)?;
        if end > max_bytes {
            return Err(byte_limit_error());
        }
        descriptors.push(DetailColumnDescriptor {
            id: spec.id,
            element_type: spec.element_type,
            byte_offset: usize_to_u32(cursor)?,
            element_count,
            byte_length: usize_to_u32(byte_length)?,
        });
        cursor = end;
    }
    Ok(DetailPlan {
        descriptors,
        data_offset: usize_to_u32(data_offset)?,
        total_bytes: cursor,
    })
}

fn write_descriptors(
    output: &mut [u8],
    descriptors: &[DetailColumnDescriptor],
) -> Result<(), BoundaryError> {
    for (index, descriptor) in descriptors.iter().enumerate() {
        let offset = DETAIL_HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(DETAIL_DESCRIPTOR_BYTES)
                    .ok_or_else(arithmetic_error)?,
            )
            .ok_or_else(arithmetic_error)?;
        write_u16(output, offset, descriptor.id)?;
        write_u8(output, offset + 2, descriptor.element_type.id())?;
        write_u8(output, offset + 3, 0)?;
        write_u32(
            output,
            offset + 4,
            usize_to_u32(descriptor.element_type.width())?,
        )?;
        write_u32(output, offset + 8, descriptor.byte_offset)?;
        write_u32(output, offset + 12, descriptor.element_count)?;
        write_u32(output, offset + 16, descriptor.byte_length)?;
        write_u32(output, offset + 20, 0)?;
    }
    Ok(())
}

fn allocate_detail_buffer(total_bytes: usize) -> Result<Vec<u8>, BoundaryError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total_bytes).map_err(|_| {
        resource_error(
            "packet detail allocation reached the resource limit",
            u64::try_from(total_bytes).unwrap_or(u64::MAX),
        )
    })?;
    bytes.resize(total_bytes, 0);
    Ok(bytes)
}

fn row_offset(descriptor: &DetailColumnDescriptor, row: usize) -> Result<usize, BoundaryError> {
    let relative = row
        .checked_mul(descriptor.element_type.width())
        .ok_or_else(arithmetic_error)?;
    (descriptor.byte_offset as usize)
        .checked_add(relative)
        .ok_or_else(arithmetic_error)
}

fn write_column_u8(
    output: &mut [u8],
    descriptor: &DetailColumnDescriptor,
    row: usize,
    value: u8,
) -> Result<(), BoundaryError> {
    write_u8(output, row_offset(descriptor, row)?, value)
}

fn write_column_u32(
    output: &mut [u8],
    descriptor: &DetailColumnDescriptor,
    row: usize,
    value: u32,
) -> Result<(), BoundaryError> {
    write_u32(output, row_offset(descriptor, row)?, value)
}

fn write_column_u64(
    output: &mut [u8],
    descriptor: &DetailColumnDescriptor,
    row: usize,
    value: u64,
) -> Result<(), BoundaryError> {
    write_u64(output, row_offset(descriptor, row)?, value)
}

fn write_u8(output: &mut [u8], offset: usize, value: u8) -> Result<(), BoundaryError> {
    write_at(output, offset, &[value])
}

fn write_u16(output: &mut [u8], offset: usize, value: u16) -> Result<(), BoundaryError> {
    write_at(output, offset, &value.to_le_bytes())
}

fn write_u32(output: &mut [u8], offset: usize, value: u32) -> Result<(), BoundaryError> {
    write_at(output, offset, &value.to_le_bytes())
}

fn write_u64(output: &mut [u8], offset: usize, value: u64) -> Result<(), BoundaryError> {
    write_at(output, offset, &value.to_le_bytes())
}

fn write_at(output: &mut [u8], offset: usize, value: &[u8]) -> Result<(), BoundaryError> {
    let end = offset
        .checked_add(value.len())
        .ok_or_else(arithmetic_error)?;
    let destination = output.get_mut(offset..end).ok_or_else(internal_invariant)?;
    destination.copy_from_slice(value);
    Ok(())
}

fn align_up(value: usize, alignment: usize) -> Result<usize, BoundaryError> {
    let mask = alignment.checked_sub(1).ok_or_else(arithmetic_error)?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(arithmetic_error)
}

fn usize_to_u16(value: usize) -> Result<u16, BoundaryError> {
    u16::try_from(value).map_err(|_| arithmetic_error())
}

fn usize_to_u32(value: usize) -> Result<u32, BoundaryError> {
    u32::try_from(value).map_err(|_| arithmetic_error())
}

fn correlation_error(error: CorrelationError, max_fields: u32) -> BoundaryError {
    match error {
        CorrelationError::PacketNotFound => packet_not_found(),
        CorrelationError::SelectionOutOfBounds => BoundaryError::new(
            BoundaryErrorCode::EVIDENCE_OUT_OF_RANGE,
            "packet-relative detail range is outside captured bytes",
        ),
        CorrelationError::FieldLimitExceeded | CorrelationError::AllocationFailed => {
            resource_error(
                "packet detail field traversal reached the resource limit",
                u64::from(max_fields),
            )
        }
        CorrelationError::DatasetInvariant => internal_invariant(),
    }
}

fn packet_not_found() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::INVALID_ARGUMENT,
        "packet identity is outside the dataset",
    )
}

fn byte_limit_error() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::BATCH_BYTE_LIMIT,
        "packet detail exceeds the byte limit",
    )
}

fn resource_error(message: &'static str, limit: u64) -> BoundaryError {
    BoundaryError::new(BoundaryErrorCode::RESOURCE_LIMIT, message).with_resource_limit(limit)
}

fn arithmetic_error() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::ARITHMETIC_OVERFLOW,
        "packet detail offset arithmetic overflowed",
    )
}

fn internal_invariant() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::INTERNAL_INVARIANT,
        "canonical packet detail invariant is inconsistent",
    )
}

#[cfg(test)]
mod tests {
    use super::{align_up, allocate_detail_buffer, plan_detail};
    use crate::BoundaryErrorCode;

    #[test]
    fn planner_rejects_byte_and_arithmetic_limits() {
        assert_eq!(
            plan_detail(1, 1, 1, 1, 80)
                .expect_err("descriptor envelope exceeds the byte limit")
                .code(),
            BoundaryErrorCode::BATCH_BYTE_LIMIT
        );
        assert_eq!(
            align_up(usize::MAX, 8)
                .expect_err("alignment addition is checked")
                .code(),
            BoundaryErrorCode::ARITHMETIC_OVERFLOW
        );
    }

    #[test]
    fn allocation_failure_is_a_structured_resource_error() {
        let error = allocate_detail_buffer(usize::MAX)
            .expect_err("an impossible detail allocation fails without panicking");
        assert_eq!(error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
    }
}
