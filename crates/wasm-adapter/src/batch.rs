//! Explicit packet-batch wire encoding.

use core::fmt;

use packet_core::{PacketRecord, TimestampResolution};

use crate::{BoundaryError, BoundaryErrorCode};

/// Current packet-batch binary schema.
pub const BATCH_SCHEMA_VERSION: u16 = 1;

pub(crate) const HEADER_BYTES: usize = 64;
const DESCRIPTOR_BYTES: usize = 24;
const BATCH_MAGIC: [u8; 8] = *b"WLPKTB01";
const FLAG_DONE: u32 = 1;
const COLUMN_FLAG_NULLABLE: u8 = 1;
pub(crate) const COLUMN_COUNT: usize = 12;

/// Stable packet batch column identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PacketBatchColumn {
    /// Stable dataset-local packet ID (`u32`).
    PacketId,
    /// Dataset-local section ID (`u32`).
    SectionId,
    /// Dataset-local interface ID (`u32`).
    InterfaceId,
    /// Captured packet length (`u32`).
    CapturedLength,
    /// Original on-wire packet length (`u32`).
    OriginalLength,
    /// Evidence byte-range length (`u32`).
    EvidenceLength,
    /// Exact evidence byte-range start (`u64`).
    EvidenceOffset,
    /// Exact whole Unix seconds (`i64`, nullable by `TimestampPresent`).
    TimestampSeconds,
    /// Exact source-resolution fractional ticks (`u64`, nullable).
    TimestampFraction,
    /// `1` when timestamp columns contain a value, otherwise `0` (`u8`).
    TimestampPresent,
    /// `0` for decimal and `1` for binary resolution (`u8`, nullable).
    TimestampResolutionKind,
    /// Exact timestamp-resolution exponent (`u8`, nullable).
    TimestampResolutionExponent,
}

impl PacketBatchColumn {
    /// Returns the stable numeric column identifier.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::PacketId => 1,
            Self::SectionId => 2,
            Self::InterfaceId => 3,
            Self::CapturedLength => 4,
            Self::OriginalLength => 5,
            Self::EvidenceLength => 6,
            Self::EvidenceOffset => 7,
            Self::TimestampSeconds => 8,
            Self::TimestampFraction => 9,
            Self::TimestampPresent => 10,
            Self::TimestampResolutionKind => 11,
            Self::TimestampResolutionExponent => 12,
        }
    }
}

/// Stable scalar encoding used by one structure-of-arrays column.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchElementType {
    /// Unsigned 8-bit integer.
    U8,
    /// Unsigned little-endian 32-bit integer.
    U32,
    /// Unsigned little-endian 64-bit integer.
    U64,
    /// Signed two's-complement little-endian 64-bit integer.
    I64,
}

impl BatchElementType {
    /// Returns the stable numeric element-type identifier.
    #[must_use]
    pub const fn id(self) -> u8 {
        match self {
            Self::U8 => 1,
            Self::U32 => 2,
            Self::U64 => 3,
            Self::I64 => 4,
        }
    }

    const fn width(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U32 => 4,
            Self::U64 | Self::I64 => 8,
        }
    }
}

/// Parsed description of one column embedded in a packet batch.
///
/// This Rust type is convenience metadata only; its memory layout is not the
/// wire format.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColumnDescriptor {
    /// Stable semantic column.
    pub column: PacketBatchColumn,
    /// Explicit scalar representation.
    pub element_type: BatchElementType,
    /// Whether validity is controlled by `TimestampPresent`.
    pub nullable: bool,
    /// Byte offset from the beginning of the batch.
    pub byte_offset: u32,
    /// Number of scalar elements.
    pub element_count: u32,
    /// Total byte length of this column.
    pub byte_length: u32,
}

#[derive(Clone, Copy)]
struct ColumnSpec {
    column: PacketBatchColumn,
    element_type: BatchElementType,
    nullable: bool,
}

const COLUMN_SPECS: [ColumnSpec; COLUMN_COUNT] = [
    ColumnSpec {
        column: PacketBatchColumn::PacketId,
        element_type: BatchElementType::U32,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::SectionId,
        element_type: BatchElementType::U32,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::InterfaceId,
        element_type: BatchElementType::U32,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::CapturedLength,
        element_type: BatchElementType::U32,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::OriginalLength,
        element_type: BatchElementType::U32,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::EvidenceLength,
        element_type: BatchElementType::U32,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::EvidenceOffset,
        element_type: BatchElementType::U64,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::TimestampSeconds,
        element_type: BatchElementType::I64,
        nullable: true,
    },
    ColumnSpec {
        column: PacketBatchColumn::TimestampFraction,
        element_type: BatchElementType::U64,
        nullable: true,
    },
    ColumnSpec {
        column: PacketBatchColumn::TimestampPresent,
        element_type: BatchElementType::U8,
        nullable: false,
    },
    ColumnSpec {
        column: PacketBatchColumn::TimestampResolutionKind,
        element_type: BatchElementType::U8,
        nullable: true,
    },
    ColumnSpec {
        column: PacketBatchColumn::TimestampResolutionExponent,
        element_type: BatchElementType::U8,
        nullable: true,
    },
];

/// Owned, self-describing packet batch.
///
/// The byte buffer starts with a 64-byte header, followed by 24-byte column
/// descriptors and aligned structure-of-arrays column data. Every multibyte
/// value is written explicitly in little-endian order.
pub struct PacketBatch {
    bytes: Box<[u8]>,
    descriptors: Box<[ColumnDescriptor]>,
    row_count: u32,
    start_row: u64,
    next_row: u64,
    total_rows: u64,
    done: bool,
}

impl PacketBatch {
    /// Returns the complete versioned binary payload.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the number of packet rows in this batch.
    #[must_use]
    pub const fn row_count(&self) -> u32 {
        self.row_count
    }

    /// Returns the dataset row where this batch begins.
    #[must_use]
    pub const fn start_row(&self) -> u64 {
        self.start_row
    }

    /// Returns the first dataset row not represented by this batch.
    #[must_use]
    pub const fn next_row(&self) -> u64 {
        self.next_row
    }

    /// Returns the total packet-row count observed when this batch was built.
    #[must_use]
    pub const fn total_rows(&self) -> u64 {
        self.total_rows
    }

    /// Returns whether the cursor reached the end of the dataset.
    #[must_use]
    pub const fn is_done(&self) -> bool {
        self.done
    }

    /// Returns the embedded descriptor for a semantic column.
    #[must_use]
    pub fn descriptor(&self, column: PacketBatchColumn) -> Option<ColumnDescriptor> {
        self.descriptors
            .iter()
            .copied()
            .find(|descriptor| descriptor.column == column)
    }
}

impl fmt::Debug for PacketBatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PacketBatch")
            .field("byte_length", &self.bytes.len())
            .field("row_count", &self.row_count)
            .field("start_row", &self.start_row)
            .field("next_row", &self.next_row)
            .field("total_rows", &self.total_rows)
            .field("done", &self.done)
            .finish_non_exhaustive()
    }
}

pub(crate) fn encode_packet_batch(
    packets: &[PacketRecord],
    start_row: u64,
    next_row: u64,
    total_rows: u64,
    api_version: u32,
    max_rows: u32,
    max_bytes: usize,
) -> Result<PacketBatch, BoundaryError> {
    let row_count = u32::try_from(packets.len()).map_err(|_| row_limit_error())?;
    let plan = plan_batch(row_count, max_rows, max_bytes)?;
    let done = next_row >= total_rows;
    let mut bytes = allocate_batch_buffer(plan.total_bytes)?;

    bytes[0..BATCH_MAGIC.len()].copy_from_slice(&BATCH_MAGIC);
    write_u16(&mut bytes, 8, BATCH_SCHEMA_VERSION)?;
    write_u16(
        &mut bytes,
        10,
        u16::try_from(HEADER_BYTES).map_err(|_| arithmetic_error())?,
    )?;
    write_u32(&mut bytes, 12, api_version)?;
    write_u16(
        &mut bytes,
        16,
        u16::try_from(DESCRIPTOR_BYTES).map_err(|_| arithmetic_error())?,
    )?;
    write_u16(
        &mut bytes,
        18,
        u16::try_from(plan.descriptors.len()).map_err(|_| arithmetic_error())?,
    )?;
    write_u32(&mut bytes, 20, u32::from(done) * FLAG_DONE)?;
    write_u32(&mut bytes, 24, row_count)?;
    write_u32(&mut bytes, 28, u32_from_usize(HEADER_BYTES)?)?;
    write_u32(&mut bytes, 32, plan.data_offset)?;
    write_u32(&mut bytes, 36, u32_from_usize(plan.total_bytes)?)?;
    write_u64(&mut bytes, 40, start_row)?;
    write_u64(&mut bytes, 48, next_row)?;
    write_u64(&mut bytes, 56, total_rows)?;

    for (index, descriptor) in plan.descriptors.iter().enumerate() {
        let descriptor_offset = HEADER_BYTES
            .checked_add(
                index
                    .checked_mul(DESCRIPTOR_BYTES)
                    .ok_or_else(arithmetic_error)?,
            )
            .ok_or_else(arithmetic_error)?;
        write_u16(&mut bytes, descriptor_offset, descriptor.column.id())?;
        write_u8(
            &mut bytes,
            descriptor_offset + 2,
            descriptor.element_type.id(),
        )?;
        write_u8(
            &mut bytes,
            descriptor_offset + 3,
            u8::from(descriptor.nullable) * COLUMN_FLAG_NULLABLE,
        )?;
        write_u32(
            &mut bytes,
            descriptor_offset + 4,
            u32_from_usize(descriptor.element_type.width())?,
        )?;
        write_u32(&mut bytes, descriptor_offset + 8, descriptor.byte_offset)?;
        write_u32(&mut bytes, descriptor_offset + 12, descriptor.element_count)?;
        write_u32(&mut bytes, descriptor_offset + 16, descriptor.byte_length)?;
        write_u32(&mut bytes, descriptor_offset + 20, 0)?;
    }

    for (row, packet) in packets.iter().enumerate() {
        write_column_u32(&mut bytes, &plan.descriptors[0], row, packet.id.0)?;
        write_column_u32(&mut bytes, &plan.descriptors[1], row, packet.section_id.0)?;
        write_column_u32(&mut bytes, &plan.descriptors[2], row, packet.interface_id.0)?;
        write_column_u32(
            &mut bytes,
            &plan.descriptors[3],
            row,
            packet.captured_length,
        )?;
        write_column_u32(
            &mut bytes,
            &plan.descriptors[4],
            row,
            packet.original_length,
        )?;
        write_column_u32(&mut bytes, &plan.descriptors[5], row, packet.data.length())?;
        write_column_u64(&mut bytes, &plan.descriptors[6], row, packet.data.start())?;

        if let Some(timestamp) = packet.timestamp {
            write_column_i64(&mut bytes, &plan.descriptors[7], row, timestamp.seconds())?;
            write_column_u64(&mut bytes, &plan.descriptors[8], row, timestamp.fraction())?;
            write_column_u8(&mut bytes, &plan.descriptors[9], row, 1)?;
            let (resolution_kind, exponent) = match timestamp.resolution() {
                TimestampResolution::Decimal(exponent) => (0, exponent),
                TimestampResolution::Binary(exponent) => (1, exponent),
            };
            write_column_u8(&mut bytes, &plan.descriptors[10], row, resolution_kind)?;
            write_column_u8(&mut bytes, &plan.descriptors[11], row, exponent)?;
        }
    }

    Ok(PacketBatch {
        bytes: bytes.into_boxed_slice(),
        descriptors: plan.descriptors.into_boxed_slice(),
        row_count,
        start_row,
        next_row,
        total_rows,
        done,
    })
}

fn allocate_batch_buffer(total_bytes: usize) -> Result<Vec<u8>, BoundaryError> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total_bytes).map_err(|_| {
        BoundaryError::new(
            BoundaryErrorCode::RESOURCE_LIMIT,
            "packet batch allocation reached the resource limit",
        )
        .with_resource_limit(u64::try_from(total_bytes).unwrap_or(u64::MAX))
    })?;
    bytes.resize(total_bytes, 0);
    Ok(bytes)
}

pub(crate) fn fitting_row_count(
    requested_rows: u32,
    max_rows: u32,
    max_bytes: usize,
) -> Result<u32, BoundaryError> {
    if requested_rows > max_rows {
        return Err(row_limit_error());
    }
    plan_batch(0, max_rows, max_bytes)?;
    if requested_rows == 0 {
        return Ok(0);
    }

    let mut low = 0_u32;
    let mut high = requested_rows;
    while low < high {
        let distance = high - low;
        let middle = low + distance / 2 + distance % 2;
        match plan_batch(middle, max_rows, max_bytes) {
            Ok(_) => low = middle,
            Err(error) if error.code() == BoundaryErrorCode::BATCH_BYTE_LIMIT => {
                high = middle - 1;
            }
            Err(error) => return Err(error),
        }
    }
    if low == 0 {
        return Err(BoundaryError::new(
            BoundaryErrorCode::BATCH_BYTE_LIMIT,
            "packet batch byte budget cannot fit one row",
        ));
    }
    Ok(low)
}

#[derive(Debug)]
struct BatchPlan {
    descriptors: Vec<ColumnDescriptor>,
    data_offset: u32,
    total_bytes: usize,
}

fn plan_batch(row_count: u32, max_rows: u32, max_bytes: usize) -> Result<BatchPlan, BoundaryError> {
    if row_count > max_rows {
        return Err(row_limit_error());
    }
    let descriptor_table_bytes = COLUMN_SPECS
        .len()
        .checked_mul(DESCRIPTOR_BYTES)
        .ok_or_else(arithmetic_error)?;
    let data_offset = HEADER_BYTES
        .checked_add(descriptor_table_bytes)
        .ok_or_else(arithmetic_error)?;
    let mut cursor = data_offset;
    let mut descriptors = Vec::new();
    reserve_descriptor_capacity(&mut descriptors, COLUMN_SPECS.len())?;
    for spec in COLUMN_SPECS {
        cursor = align_up(cursor, spec.element_type.width())?;
        let byte_length = (row_count as usize)
            .checked_mul(spec.element_type.width())
            .ok_or_else(arithmetic_error)?;
        let end = cursor
            .checked_add(byte_length)
            .ok_or_else(arithmetic_error)?;
        if end > max_bytes {
            return Err(BoundaryError::new(
                BoundaryErrorCode::BATCH_BYTE_LIMIT,
                "packet batch exceeds the byte limit",
            ));
        }
        descriptors.push(ColumnDescriptor {
            column: spec.column,
            element_type: spec.element_type,
            nullable: spec.nullable,
            byte_offset: u32_from_usize(cursor)?,
            element_count: row_count,
            byte_length: u32_from_usize(byte_length)?,
        });
        cursor = end;
    }
    if cursor > max_bytes {
        return Err(BoundaryError::new(
            BoundaryErrorCode::BATCH_BYTE_LIMIT,
            "packet batch exceeds the byte limit",
        ));
    }
    Ok(BatchPlan {
        descriptors,
        data_offset: u32_from_usize(data_offset)?,
        total_bytes: cursor,
    })
}

fn reserve_descriptor_capacity(
    descriptors: &mut Vec<ColumnDescriptor>,
    additional: usize,
) -> Result<(), BoundaryError> {
    descriptors.try_reserve_exact(additional).map_err(|_| {
        BoundaryError::new(
            BoundaryErrorCode::RESOURCE_LIMIT,
            "packet batch descriptor allocation reached the resource limit",
        )
        .with_resource_limit(u64::try_from(COLUMN_COUNT).unwrap_or(u64::MAX))
    })
}

fn align_up(value: usize, alignment: usize) -> Result<usize, BoundaryError> {
    let mask = alignment.checked_sub(1).ok_or_else(arithmetic_error)?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or_else(arithmetic_error)
}

fn u32_from_usize(value: usize) -> Result<u32, BoundaryError> {
    u32::try_from(value).map_err(|_| arithmetic_error())
}

fn row_offset(descriptor: &ColumnDescriptor, row: usize) -> Result<usize, BoundaryError> {
    let width = descriptor.element_type.width();
    let relative = row.checked_mul(width).ok_or_else(arithmetic_error)?;
    (descriptor.byte_offset as usize)
        .checked_add(relative)
        .ok_or_else(arithmetic_error)
}

fn write_column_u8(
    output: &mut [u8],
    descriptor: &ColumnDescriptor,
    row: usize,
    value: u8,
) -> Result<(), BoundaryError> {
    write_u8(output, row_offset(descriptor, row)?, value)
}

fn write_column_u32(
    output: &mut [u8],
    descriptor: &ColumnDescriptor,
    row: usize,
    value: u32,
) -> Result<(), BoundaryError> {
    write_u32(output, row_offset(descriptor, row)?, value)
}

fn write_column_u64(
    output: &mut [u8],
    descriptor: &ColumnDescriptor,
    row: usize,
    value: u64,
) -> Result<(), BoundaryError> {
    write_u64(output, row_offset(descriptor, row)?, value)
}

fn write_column_i64(
    output: &mut [u8],
    descriptor: &ColumnDescriptor,
    row: usize,
    value: i64,
) -> Result<(), BoundaryError> {
    write_at(output, row_offset(descriptor, row)?, &value.to_le_bytes())
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
    let Some(destination) = output.get_mut(offset..end) else {
        return Err(BoundaryError::new(
            BoundaryErrorCode::INTERNAL_INVARIANT,
            "packet batch write is outside the planned buffer",
        ));
    };
    destination.copy_from_slice(value);
    Ok(())
}

fn arithmetic_error() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::ARITHMETIC_OVERFLOW,
        "boundary offset arithmetic overflowed",
    )
}

fn row_limit_error() -> BoundaryError {
    BoundaryError::new(
        BoundaryErrorCode::BATCH_ROW_LIMIT,
        "packet batch exceeds the row limit",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        align_up, allocate_batch_buffer, fitting_row_count, plan_batch, reserve_descriptor_capacity,
    };
    use crate::BoundaryErrorCode;

    #[test]
    fn planner_rejects_row_byte_and_arithmetic_limits() {
        assert_eq!(
            plan_batch(2, 1, usize::MAX)
                .expect_err("row cap must be enforced")
                .code(),
            BoundaryErrorCode::BATCH_ROW_LIMIT
        );
        assert_eq!(
            plan_batch(1, 1, 64)
                .expect_err("descriptor and data bytes exceed the limit")
                .code(),
            BoundaryErrorCode::BATCH_BYTE_LIMIT
        );
        assert_eq!(
            align_up(usize::MAX, 8)
                .expect_err("alignment addition must be checked")
                .code(),
            BoundaryErrorCode::ARITHMETIC_OVERFLOW
        );
    }

    #[test]
    fn row_fitting_uses_the_largest_prefix_within_budget() {
        let one_row = plan_batch(1, 10, usize::MAX)
            .expect("one-row plan succeeds")
            .total_bytes;
        let two_rows = plan_batch(2, 10, usize::MAX)
            .expect("two-row plan succeeds")
            .total_bytes;
        assert_eq!(fitting_row_count(10, 10, one_row), Ok(1));
        assert_eq!(fitting_row_count(10, 10, two_rows), Ok(2));
        assert_eq!(
            fitting_row_count(1, 10, one_row - 1)
                .expect_err("budget below one row is rejected")
                .code(),
            BoundaryErrorCode::BATCH_BYTE_LIMIT
        );
    }

    #[test]
    fn batch_allocation_failure_is_a_structured_resource_error() {
        let error = allocate_batch_buffer(usize::MAX)
            .expect_err("an impossible batch allocation must fail without panicking");
        assert_eq!(error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert_eq!(error.resource_limit(), Some(u64::MAX));
    }

    #[test]
    fn descriptor_allocation_failure_is_a_structured_resource_error() {
        let mut descriptors = Vec::new();
        let error = reserve_descriptor_capacity(&mut descriptors, usize::MAX)
            .expect_err("an impossible descriptor reservation must fail without mutation");
        assert_eq!(error.code(), BoundaryErrorCode::RESOURCE_LIMIT);
        assert_eq!(error.resource_limit(), Some(12));
        assert!(descriptors.is_empty());
    }
}
