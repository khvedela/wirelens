//! Bounded classic DNS message decoding.

use core::str;

use packet_core::{
    ByteRange, DiagnosticCode, FieldId, FieldValue, ImportError, PacketDecodeInput,
    PacketDecodeSink, Severity,
};

use crate::{
    ChildIds, ProtocolFinding, add_named_field, finish_layer, packet_slice, read_u16, read_u32,
};

const HEADER_LENGTH: usize = 12;
const MAX_QUESTIONS: u16 = 16;
const MAX_RECORDS: u32 = 16;
const MAX_POINTER_HOPS: u8 = 16;
const MAX_TXT_STRINGS: u8 = 16;
const MAX_EXPANDED_NAME_WIRE_BYTES: usize = 255;
const MAX_RENDERED_NAME_BYTES: usize = 1_004;
const MAX_NAME_COMPONENTS: usize = 128;
const NAME_BOUNDARY_WORDS: usize = 1_024;

const TYPE_A: u16 = 1;
const TYPE_NS: u16 = 2;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_PTR: u16 = 12;
const TYPE_MX: u16 = 15;
const TYPE_TXT: u16 = 16;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

const PRIORITY_TRUNCATED: u8 = 100;
const PRIORITY_RESOURCE: u8 = 110;
const PRIORITY_MALFORMED: u8 = 120;

const MESSAGE_TRUNCATED_HEADER: &str =
    "DNS message ends before all twelve fixed-header bytes are available";
const MESSAGE_TRUNCATED_QUESTION: &str =
    "DNS question ends before its complete name, type, and class are available";
const MESSAGE_TRUNCATED_RECORD: &str =
    "DNS resource record ends before its complete fixed fields are available";
const MESSAGE_TRUNCATED_RDATA: &str =
    "DNS resource record data ends before its declared length is available";
const MESSAGE_MALFORMED_NAME: &str =
    "DNS name encoding contains an invalid label or compression pointer";
const MESSAGE_NAME_TOO_LONG: &str = "DNS expanded name exceeds the 255-byte wire-format limit";
const MESSAGE_POINTER_LIMIT: &str =
    "DNS compressed name exceeds the bounded compression-pointer traversal limit";
const MESSAGE_QUESTION_LIMIT: &str = "DNS question count exceeds the bounded decoder limit";
const MESSAGE_RECORD_LIMIT: &str =
    "DNS aggregate resource-record count exceeds the bounded decoder limit";
const MESSAGE_NAME_LIMIT: &str = "DNS decoded-name count exceeds the bounded decoder limit";
const MESSAGE_TXT_LIMIT: &str = "DNS TXT string count exceeds the bounded decoder limit";
const MESSAGE_MALFORMED_RDATA: &str =
    "DNS record data contradicts the recognized resource-record format";
const MESSAGE_TRAILING_DATA: &str =
    "DNS message contains bytes beyond its declared questions and resource records";

/// Maximum decoded DNS name occurrences retained from one packet.
pub const MAX_DNS_NAMES_PER_PACKET: u32 = 64;

#[derive(Clone, Copy)]
enum FaultKind {
    Truncated,
    Malformed,
    Resource,
}

#[derive(Clone, Copy)]
struct DnsFault {
    kind: FaultKind,
    offset: usize,
    length: usize,
    message: &'static str,
}

impl DnsFault {
    const fn truncated(offset: usize, length: usize, message: &'static str) -> Self {
        Self {
            kind: FaultKind::Truncated,
            offset,
            length,
            message,
        }
    }

    const fn malformed(offset: usize, length: usize, message: &'static str) -> Self {
        Self {
            kind: FaultKind::Malformed,
            offset,
            length,
            message,
        }
    }

    const fn resource(offset: usize, length: usize, message: &'static str) -> Self {
        Self {
            kind: FaultKind::Resource,
            offset,
            length,
            message,
        }
    }

    fn finding(self, message_range: ByteRange) -> Result<ProtocolFinding, ImportError> {
        let offset = u32::try_from(self.offset).map_err(|_| ImportError::Arithmetic)?;
        let length = u32::try_from(self.length).map_err(|_| ImportError::Arithmetic)?;
        let evidence = message_range
            .child(offset, length)
            .ok_or(ImportError::Arithmetic)?;
        let (priority, code, severity) = match self.kind {
            FaultKind::Truncated => (
                PRIORITY_TRUNCATED,
                DiagnosticCode::TRUNCATED_PROTOCOL,
                Severity::Error,
            ),
            FaultKind::Malformed => (
                PRIORITY_MALFORMED,
                DiagnosticCode::MALFORMED_PROTOCOL,
                Severity::Warning,
            ),
            FaultKind::Resource => (
                PRIORITY_RESOURCE,
                DiagnosticCode::RESOURCE_LIMIT,
                Severity::Warning,
            ),
        };
        Ok(ProtocolFinding {
            priority,
            code,
            severity,
            evidence,
            message: self.message,
        })
    }

    fn as_malformed_rdata(self, length_offset: usize) -> Self {
        if matches!(self.kind, FaultKind::Truncated) {
            Self::malformed(length_offset, 2, MESSAGE_MALFORMED_RDATA)
        } else {
            self
        }
    }
}

struct NameState {
    boundaries: [u64; NAME_BOUNDARY_WORDS],
    names: u32,
    txt_strings: u8,
}

impl NameState {
    const fn new() -> Self {
        Self {
            boundaries: [0; NAME_BOUNDARY_WORDS],
            names: 0,
            txt_strings: 0,
        }
    }

    fn contains_boundary(&self, offset: usize) -> bool {
        let word = offset / 64;
        let bit = offset % 64;
        self.boundaries
            .get(word)
            .is_some_and(|value| (value & (1_u64 << bit)) != 0)
    }

    fn insert_boundary(&mut self, offset: usize) -> Result<(), ImportError> {
        let word = offset / 64;
        let bit = offset % 64;
        let value = self
            .boundaries
            .get_mut(word)
            .ok_or(ImportError::Arithmetic)?;
        *value |= 1_u64 << bit;
        Ok(())
    }
}

struct ParsedName {
    rendered: [u8; MAX_RENDERED_NAME_BYTES],
    rendered_length: usize,
    start: usize,
    end: usize,
}

impl ParsedName {
    fn as_str(&self) -> Result<&str, ImportError> {
        str::from_utf8(&self.rendered[..self.rendered_length]).map_err(|_| ImportError::Arithmetic)
    }

    fn range(&self, message_range: ByteRange) -> Result<ByteRange, ImportError> {
        relative_range(
            message_range,
            self.start,
            self.end
                .checked_sub(self.start)
                .ok_or(ImportError::Arithmetic)?,
        )
    }
}

#[derive(Clone, Copy)]
struct TextRange {
    start: usize,
    length: usize,
}

// Keeping the bounded name buffers inline avoids one attacker-directed heap
// allocation per recognized record. The enum is short-lived parse scratch.
#[allow(clippy::large_enum_variant)]
enum ParsedRdata {
    Address {
        start: usize,
        length: usize,
    },
    Name {
        field_name: &'static str,
        name: ParsedName,
    },
    Soa {
        primary: ParsedName,
        mailbox: ParsedName,
        integers_start: usize,
    },
    Mx {
        preference_start: usize,
        exchange: ParsedName,
    },
    Txt {
        ranges: [TextRange; MAX_TXT_STRINGS as usize],
        count: usize,
    },
    Opaque {
        start: usize,
        length: usize,
    },
}

struct ParsedRecord {
    owner: ParsedName,
    fixed_start: usize,
    data_length_offset: usize,
    data_start: usize,
    end: usize,
    rdata: ParsedRdata,
}

/// Decodes one already-framed DNS message and returns at most one prioritized finding.
pub(crate) fn decode(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    message_range: ByteRange,
) -> Result<Option<ProtocolFinding>, ImportError> {
    let bytes = packet_slice(input, message_range)?;
    let root = add_named_field(sink, "dns", FieldValue::None, message_range)?;
    let mut root_children = ChildIds::new();
    let header_length = bytes.len().min(HEADER_LENGTH);
    let header_range = relative_range(message_range, 0, header_length)?;
    let header = add_named_field(sink, "dns_header", FieldValue::None, header_range)?;
    let mut header_children = ChildIds::new();
    add_partial_header_fields(sink, &mut header_children, bytes, message_range)?;
    sink.set_field_children(header, header_children.as_slice())?;
    root_children.push(header)?;

    if bytes.len() < HEADER_LENGTH {
        finish_layer(sink, "dns", message_range, root, &root_children)?;
        return DnsFault::truncated(bytes.len(), 0, MESSAGE_TRUNCATED_HEADER)
            .finding(message_range)
            .map(Some);
    }

    let question_count = read_u16(bytes, 4).ok_or(ImportError::Arithmetic)?;
    let answer_count = read_u16(bytes, 6).ok_or(ImportError::Arithmetic)?;
    let authority_count = read_u16(bytes, 8).ok_or(ImportError::Arithmetic)?;
    let additional_count = read_u16(bytes, 10).ok_or(ImportError::Arithmetic)?;
    if question_count > MAX_QUESTIONS {
        return finish_with_fault(
            sink,
            message_range,
            root,
            &root_children,
            DnsFault::resource(4, 2, MESSAGE_QUESTION_LIMIT),
        );
    }
    let record_count = u32::from(answer_count)
        .checked_add(u32::from(authority_count))
        .and_then(|count| count.checked_add(u32::from(additional_count)))
        .ok_or(ImportError::Arithmetic)?;
    if record_count > MAX_RECORDS {
        let offset = if u32::from(answer_count) > MAX_RECORDS {
            6
        } else if u32::from(answer_count) + u32::from(authority_count) > MAX_RECORDS {
            8
        } else {
            10
        };
        return finish_with_fault(
            sink,
            message_range,
            root,
            &root_children,
            DnsFault::resource(offset, 2, MESSAGE_RECORD_LIMIT),
        );
    }

    let mut state = NameState::new();
    let mut cursor = HEADER_LENGTH;
    for _ in 0..question_count {
        match parse_question(bytes, cursor, &mut state) {
            Ok((name, next)) => {
                emit_question(sink, message_range, &mut root_children, bytes, &name, next)?;
                cursor = next;
            }
            Err(fault) => {
                return finish_with_fault(sink, message_range, root, &root_children, fault);
            }
        }
    }

    for (section_name, count) in [
        ("dns_answer", answer_count),
        ("dns_authority", authority_count),
        ("dns_additional", additional_count),
    ] {
        for _ in 0..count {
            match parse_record(bytes, cursor, &mut state) {
                Ok(record) => {
                    cursor = record.end;
                    emit_record(
                        sink,
                        message_range,
                        &mut root_children,
                        section_name,
                        bytes,
                        &record,
                    )?;
                }
                Err(fault) => {
                    return finish_with_fault(sink, message_range, root, &root_children, fault);
                }
            }
        }
    }

    if cursor != bytes.len() {
        let fault = DnsFault::malformed(
            cursor,
            bytes.len().saturating_sub(cursor),
            MESSAGE_TRAILING_DATA,
        );
        return finish_with_fault(sink, message_range, root, &root_children, fault);
    }

    finish_layer(sink, "dns", message_range, root, &root_children)?;
    Ok(None)
}

fn finish_with_fault(
    sink: &mut PacketDecodeSink<'_>,
    message_range: ByteRange,
    root: FieldId,
    root_children: &ChildIds,
    fault: DnsFault,
) -> Result<Option<ProtocolFinding>, ImportError> {
    finish_layer(sink, "dns", message_range, root, root_children)?;
    fault.finding(message_range).map(Some)
}

fn add_partial_header_fields(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    bytes: &[u8],
    message_range: ByteRange,
) -> Result<(), ImportError> {
    for (name, offset) in [
        ("transaction_id", 0),
        ("flags", 2),
        ("question_count", 4),
        ("answer_count", 6),
        ("authority_count", 8),
        ("additional_count", 10),
    ] {
        if let Some(value) = read_u16(bytes, offset) {
            children.push(add_unsigned(
                sink,
                name,
                u64::from(value),
                relative_range(message_range, offset, 2)?,
            )?)?;
        }
    }
    let Some(flags) = read_u16(bytes, 2) else {
        return Ok(());
    };
    let range = relative_range(message_range, 2, 2)?;
    for (name, value) in [
        ("is_response", (flags & 0x8000) != 0),
        ("authoritative_answer", (flags & 0x0400) != 0),
        ("truncated", (flags & 0x0200) != 0),
        ("recursion_desired", (flags & 0x0100) != 0),
        ("recursion_available", (flags & 0x0080) != 0),
        ("authenticated_data", (flags & 0x0020) != 0),
        ("checking_disabled", (flags & 0x0010) != 0),
    ] {
        children.push(add_named_field(
            sink,
            name,
            FieldValue::Boolean(value),
            range,
        )?)?;
    }
    for (name, value) in [
        ("opcode", u64::from((flags >> 11) & 0x0f)),
        ("reserved", u64::from((flags >> 6) & 0x01)),
        ("response_code", u64::from(flags & 0x0f)),
    ] {
        children.push(add_unsigned(sink, name, value, range)?)?;
    }
    Ok(())
}

fn parse_question(
    bytes: &[u8],
    start: usize,
    state: &mut NameState,
) -> Result<(ParsedName, usize), DnsFault> {
    let name = parse_name(bytes, start, bytes.len(), state)?;
    let end = name
        .end
        .checked_add(4)
        .ok_or_else(|| DnsFault::truncated(name.end, 0, MESSAGE_TRUNCATED_QUESTION))?;
    if end > bytes.len() {
        return Err(DnsFault::truncated(
            name.end,
            bytes.len().saturating_sub(name.end),
            MESSAGE_TRUNCATED_QUESTION,
        ));
    }
    Ok((name, end))
}

fn emit_question(
    sink: &mut PacketDecodeSink<'_>,
    message_range: ByteRange,
    root_children: &mut ChildIds,
    bytes: &[u8],
    name: &ParsedName,
    end: usize,
) -> Result<(), ImportError> {
    let class_offset = name.end.checked_add(2).ok_or(ImportError::Arithmetic)?;
    let question_range = relative_range(
        message_range,
        name.start,
        end.checked_sub(name.start).ok_or(ImportError::Arithmetic)?,
    )?;
    let root = add_named_field(sink, "dns_question", FieldValue::None, question_range)?;
    let mut children = ChildIds::new();
    children.push(add_name_field(sink, "name", name, message_range)?)?;
    children.push(add_unsigned(
        sink,
        "type",
        u64::from(read_u16(bytes, name.end).ok_or(ImportError::Arithmetic)?),
        relative_range(message_range, name.end, 2)?,
    )?)?;
    children.push(add_unsigned(
        sink,
        "class",
        u64::from(read_u16(bytes, class_offset).ok_or(ImportError::Arithmetic)?),
        relative_range(message_range, class_offset, 2)?,
    )?)?;
    sink.set_field_children(root, children.as_slice())?;
    root_children.push(root)
}

fn parse_record(
    bytes: &[u8],
    start: usize,
    state: &mut NameState,
) -> Result<ParsedRecord, DnsFault> {
    let owner = parse_name(bytes, start, bytes.len(), state).map_err(|fault| {
        if matches!(fault.kind, FaultKind::Truncated) {
            DnsFault {
                message: MESSAGE_TRUNCATED_RECORD,
                ..fault
            }
        } else {
            fault
        }
    })?;
    let fixed_end = owner
        .end
        .checked_add(10)
        .ok_or_else(|| DnsFault::truncated(owner.end, 0, MESSAGE_TRUNCATED_RECORD))?;
    if fixed_end > bytes.len() {
        return Err(DnsFault::truncated(
            owner.end,
            bytes.len().saturating_sub(owner.end),
            MESSAGE_TRUNCATED_RECORD,
        ));
    }
    let record_type = read_u16(bytes, owner.end)
        .ok_or_else(|| DnsFault::truncated(owner.end, 0, MESSAGE_TRUNCATED_RECORD))?;
    let record_class = read_u16(bytes, owner.end + 2)
        .ok_or_else(|| DnsFault::truncated(owner.end + 2, 0, MESSAGE_TRUNCATED_RECORD))?;
    let data_length_offset = owner.end + 8;
    let data_length = usize::from(
        read_u16(bytes, data_length_offset)
            .ok_or_else(|| DnsFault::truncated(data_length_offset, 0, MESSAGE_TRUNCATED_RECORD))?,
    );
    let data_start = fixed_end;
    let end = data_start
        .checked_add(data_length)
        .ok_or_else(|| DnsFault::truncated(data_length_offset, 2, MESSAGE_TRUNCATED_RDATA))?;
    if end > bytes.len() {
        return Err(DnsFault::truncated(
            data_length_offset,
            2,
            MESSAGE_TRUNCATED_RDATA,
        ));
    }
    let rdata = parse_rdata(
        bytes,
        record_type,
        record_class,
        data_start,
        end,
        data_length_offset,
        state,
    )?;
    Ok(ParsedRecord {
        owner,
        fixed_start: fixed_end - 10,
        data_length_offset,
        data_start,
        end,
        rdata,
    })
}

fn parse_rdata(
    bytes: &[u8],
    record_type: u16,
    record_class: u16,
    start: usize,
    end: usize,
    length_offset: usize,
    state: &mut NameState,
) -> Result<ParsedRdata, DnsFault> {
    let length = end.saturating_sub(start);
    // TYPE alone does not define RDATA semantics across DNS classes. The
    // bounded v0.1 interpretations below are Internet-class formats; other
    // classes retain one exact opaque RDATA reference.
    if record_class != CLASS_IN {
        return Ok(ParsedRdata::Opaque { start, length });
    }
    match record_type {
        TYPE_A if length == 4 => Ok(ParsedRdata::Address { start, length }),
        TYPE_AAAA if length == 16 => Ok(ParsedRdata::Address { start, length }),
        TYPE_A | TYPE_AAAA => Err(DnsFault::malformed(
            length_offset,
            2,
            MESSAGE_MALFORMED_RDATA,
        )),
        TYPE_NS | TYPE_CNAME | TYPE_PTR => {
            let name = parse_name(bytes, start, end, state)
                .map_err(|fault| fault.as_malformed_rdata(length_offset))?;
            if name.end != end {
                return Err(DnsFault::malformed(
                    name.end,
                    end.saturating_sub(name.end),
                    MESSAGE_MALFORMED_RDATA,
                ));
            }
            let field_name = match record_type {
                TYPE_NS => "name_server",
                TYPE_CNAME => "canonical_name",
                TYPE_PTR => "domain_name",
                _ => return Err(DnsFault::malformed(start, length, MESSAGE_MALFORMED_RDATA)),
            };
            Ok(ParsedRdata::Name { field_name, name })
        }
        TYPE_SOA => {
            let primary = parse_name(bytes, start, end, state)
                .map_err(|fault| fault.as_malformed_rdata(length_offset))?;
            let mailbox = parse_name(bytes, primary.end, end, state)
                .map_err(|fault| fault.as_malformed_rdata(length_offset))?;
            let integers_end = mailbox
                .end
                .checked_add(20)
                .ok_or_else(|| DnsFault::malformed(length_offset, 2, MESSAGE_MALFORMED_RDATA))?;
            if integers_end != end {
                return Err(DnsFault::malformed(
                    length_offset,
                    2,
                    MESSAGE_MALFORMED_RDATA,
                ));
            }
            let integers_start = mailbox.end;
            Ok(ParsedRdata::Soa {
                primary,
                mailbox,
                integers_start,
            })
        }
        TYPE_MX => {
            let exchange_start = start
                .checked_add(2)
                .ok_or_else(|| DnsFault::malformed(length_offset, 2, MESSAGE_MALFORMED_RDATA))?;
            if exchange_start > end {
                return Err(DnsFault::malformed(
                    length_offset,
                    2,
                    MESSAGE_MALFORMED_RDATA,
                ));
            }
            let exchange = parse_name(bytes, exchange_start, end, state)
                .map_err(|fault| fault.as_malformed_rdata(length_offset))?;
            if exchange.end != end {
                return Err(DnsFault::malformed(
                    exchange.end,
                    end.saturating_sub(exchange.end),
                    MESSAGE_MALFORMED_RDATA,
                ));
            }
            Ok(ParsedRdata::Mx {
                preference_start: start,
                exchange,
            })
        }
        TYPE_TXT => parse_txt(bytes, start, end, length_offset, state),
        _ => Ok(ParsedRdata::Opaque { start, length }),
    }
}

fn parse_txt(
    bytes: &[u8],
    start: usize,
    end: usize,
    length_offset: usize,
    state: &mut NameState,
) -> Result<ParsedRdata, DnsFault> {
    if start == end {
        return Err(DnsFault::malformed(
            length_offset,
            2,
            MESSAGE_MALFORMED_RDATA,
        ));
    }
    let mut ranges = [TextRange {
        start: 0,
        length: 0,
    }; MAX_TXT_STRINGS as usize];
    let mut count = 0_usize;
    let mut cursor = start;
    while cursor < end {
        if state.txt_strings >= MAX_TXT_STRINGS {
            return Err(DnsFault::resource(cursor, 1, MESSAGE_TXT_LIMIT));
        }
        let length = usize::from(bytes[cursor]);
        let data_start = cursor + 1;
        let next = data_start
            .checked_add(length)
            .ok_or_else(|| DnsFault::malformed(cursor, 1, MESSAGE_MALFORMED_RDATA))?;
        if next > end {
            return Err(DnsFault::malformed(cursor, 1, MESSAGE_MALFORMED_RDATA));
        }
        let Some(slot) = ranges.get_mut(count) else {
            return Err(DnsFault::resource(cursor, 1, MESSAGE_TXT_LIMIT));
        };
        *slot = TextRange {
            start: data_start,
            length,
        };
        count += 1;
        state.txt_strings += 1;
        cursor = next;
    }
    Ok(ParsedRdata::Txt { ranges, count })
}

#[allow(clippy::too_many_lines)]
fn emit_record(
    sink: &mut PacketDecodeSink<'_>,
    message_range: ByteRange,
    root_children: &mut ChildIds,
    section_name: &str,
    bytes: &[u8],
    record: &ParsedRecord,
) -> Result<(), ImportError> {
    let record_range = relative_range(
        message_range,
        record.owner.start,
        record
            .end
            .checked_sub(record.owner.start)
            .ok_or(ImportError::Arithmetic)?,
    )?;
    let root = add_named_field(sink, section_name, FieldValue::None, record_range)?;
    let mut children = ChildIds::new();
    children.push(add_name_field(sink, "name", &record.owner, message_range)?)?;
    for (name, offset, length) in [
        ("type", record.fixed_start, 2),
        ("class", record.fixed_start + 2, 2),
        ("ttl", record.fixed_start + 4, 4),
        ("rdata_length", record.data_length_offset, 2),
    ] {
        let value = if length == 2 {
            u64::from(read_u16(bytes, offset).ok_or(ImportError::Arithmetic)?)
        } else {
            u64::from(read_u32(bytes, offset).ok_or(ImportError::Arithmetic)?)
        };
        children.push(add_unsigned(
            sink,
            name,
            value,
            relative_range(message_range, offset, length)?,
        )?)?;
    }

    match &record.rdata {
        ParsedRdata::Address { start, length } => {
            let range = relative_range(message_range, *start, *length)?;
            children.push(add_named_field(
                sink,
                "address",
                FieldValue::Bytes(range),
                range,
            )?)?;
        }
        ParsedRdata::Name { field_name, name } => {
            children.push(add_name_field(sink, field_name, name, message_range)?)?;
        }
        ParsedRdata::Soa {
            primary,
            mailbox,
            integers_start,
        } => {
            let rdata_range = relative_range(
                message_range,
                record.data_start,
                record.end - record.data_start,
            )?;
            let rdata_root = add_named_field(sink, "rdata", FieldValue::None, rdata_range)?;
            let mut rdata_children = ChildIds::new();
            rdata_children.push(add_name_field(
                sink,
                "primary_name_server",
                primary,
                message_range,
            )?)?;
            rdata_children.push(add_name_field(
                sink,
                "responsible_mailbox",
                mailbox,
                message_range,
            )?)?;
            for (index, name) in ["serial", "refresh", "retry", "expire", "minimum"]
                .into_iter()
                .enumerate()
            {
                let offset = integers_start
                    .checked_add(index * 4)
                    .ok_or(ImportError::Arithmetic)?;
                rdata_children.push(add_unsigned(
                    sink,
                    name,
                    u64::from(read_u32(bytes, offset).ok_or(ImportError::Arithmetic)?),
                    relative_range(message_range, offset, 4)?,
                )?)?;
            }
            sink.set_field_children(rdata_root, rdata_children.as_slice())?;
            children.push(rdata_root)?;
        }
        ParsedRdata::Mx {
            preference_start,
            exchange,
        } => {
            let rdata_range = relative_range(
                message_range,
                record.data_start,
                record.end - record.data_start,
            )?;
            let rdata_root = add_named_field(sink, "rdata", FieldValue::None, rdata_range)?;
            let mut rdata_children = ChildIds::new();
            rdata_children.push(add_unsigned(
                sink,
                "preference",
                u64::from(read_u16(bytes, *preference_start).ok_or(ImportError::Arithmetic)?),
                relative_range(message_range, *preference_start, 2)?,
            )?)?;
            rdata_children.push(add_name_field(sink, "exchange", exchange, message_range)?)?;
            sink.set_field_children(rdata_root, rdata_children.as_slice())?;
            children.push(rdata_root)?;
        }
        ParsedRdata::Txt { ranges, count } => {
            for text in &ranges[..*count] {
                let range = relative_range(message_range, text.start, text.length)?;
                children.push(add_named_field(
                    sink,
                    "text",
                    FieldValue::Bytes(range),
                    range,
                )?)?;
            }
        }
        ParsedRdata::Opaque { start, length } => {
            let range = relative_range(message_range, *start, *length)?;
            children.push(add_named_field(
                sink,
                "rdata",
                FieldValue::Bytes(range),
                range,
            )?)?;
        }
    }
    sink.set_field_children(root, children.as_slice())?;
    root_children.push(root)
}

// The ordered gates deliberately keep encoded consumption, expanded traversal,
// and transactional boundary publication auditable in one place.
#[allow(clippy::too_many_lines)]
fn parse_name(
    bytes: &[u8],
    start: usize,
    encoded_limit: usize,
    state: &mut NameState,
) -> Result<ParsedName, DnsFault> {
    if state.names >= MAX_DNS_NAMES_PER_PACKET {
        return Err(DnsFault::resource(start, 0, MESSAGE_NAME_LIMIT));
    }
    let mut rendered = [0_u8; MAX_RENDERED_NAME_BYTES];
    let mut rendered_length = 0_usize;
    let mut expanded_wire_length = 0_usize;
    let mut cursor = start;
    let mut encoded_end = None;
    let mut pointer_hops = 0_u8;
    let mut direct = true;
    let mut components = [0_u16; MAX_NAME_COMPONENTS];
    let mut component_count = 0_usize;

    loop {
        let limit = if direct { encoded_limit } else { bytes.len() };
        let Some(&length_octet) = bytes.get(cursor).filter(|_| cursor < limit) else {
            return Err(DnsFault::truncated(
                cursor.min(bytes.len()),
                0,
                MESSAGE_TRUNCATED_QUESTION,
            ));
        };
        match length_octet & 0xc0 {
            0x00 => {
                let label_length = usize::from(length_octet);
                if label_length == 0 {
                    expanded_wire_length = expanded_wire_length
                        .checked_add(1)
                        .ok_or_else(|| DnsFault::malformed(cursor, 1, MESSAGE_NAME_TOO_LONG))?;
                    if expanded_wire_length > MAX_EXPANDED_NAME_WIRE_BYTES {
                        return Err(DnsFault::malformed(cursor, 1, MESSAGE_NAME_TOO_LONG));
                    }
                    if direct {
                        push_component(&mut components, &mut component_count, cursor)?;
                        encoded_end = Some(cursor + 1);
                    }
                    if rendered_length == 0 {
                        rendered[0] = b'.';
                        rendered_length = 1;
                    }
                    break;
                }
                let label_start = cursor + 1;
                let label_end = label_start
                    .checked_add(label_length)
                    .ok_or_else(|| DnsFault::truncated(cursor, 1, MESSAGE_TRUNCATED_QUESTION))?;
                if label_end > limit || label_end > bytes.len() {
                    let available = limit.min(bytes.len()).saturating_sub(cursor);
                    return Err(DnsFault::truncated(
                        cursor,
                        available,
                        MESSAGE_TRUNCATED_QUESTION,
                    ));
                }
                let next_wire_length = expanded_wire_length
                    .checked_add(1 + label_length)
                    .ok_or_else(|| DnsFault::malformed(cursor, 1, MESSAGE_NAME_TOO_LONG))?;
                if next_wire_length >= MAX_EXPANDED_NAME_WIRE_BYTES {
                    return Err(DnsFault::malformed(cursor, 1, MESSAGE_NAME_TOO_LONG));
                }
                expanded_wire_length = next_wire_length;
                if direct {
                    push_component(&mut components, &mut component_count, cursor)?;
                }
                append_label(
                    &mut rendered,
                    &mut rendered_length,
                    &bytes[label_start..label_end],
                    cursor,
                )?;
                cursor = label_end;
            }
            0xc0 => {
                let pointer_end = cursor
                    .checked_add(2)
                    .ok_or_else(|| DnsFault::truncated(cursor, 1, MESSAGE_TRUNCATED_QUESTION))?;
                if pointer_end > limit || pointer_end > bytes.len() {
                    return Err(DnsFault::truncated(
                        cursor,
                        limit.min(bytes.len()).saturating_sub(cursor),
                        MESSAGE_TRUNCATED_QUESTION,
                    ));
                }
                let target =
                    ((usize::from(length_octet & 0x3f)) << 8) | usize::from(bytes[cursor + 1]);
                if target >= bytes.len() || target >= cursor || !state.contains_boundary(target) {
                    return Err(DnsFault::malformed(cursor, 2, MESSAGE_MALFORMED_NAME));
                }
                pointer_hops = pointer_hops
                    .checked_add(1)
                    .ok_or_else(|| DnsFault::resource(cursor, 2, MESSAGE_POINTER_LIMIT))?;
                if pointer_hops > MAX_POINTER_HOPS {
                    return Err(DnsFault::resource(cursor, 2, MESSAGE_POINTER_LIMIT));
                }
                if direct {
                    push_component(&mut components, &mut component_count, cursor)?;
                    encoded_end = Some(pointer_end);
                    direct = false;
                }
                cursor = target;
            }
            _ => return Err(DnsFault::malformed(cursor, 1, MESSAGE_MALFORMED_NAME)),
        }
    }

    let end =
        encoded_end.ok_or_else(|| DnsFault::truncated(start, 0, MESSAGE_TRUNCATED_QUESTION))?;
    for offset in &components[..component_count] {
        state
            .insert_boundary(usize::from(*offset))
            .map_err(|_| DnsFault::resource(start, 0, MESSAGE_NAME_LIMIT))?;
    }
    state.names += 1;
    Ok(ParsedName {
        rendered,
        rendered_length,
        start,
        end,
    })
}

fn push_component(
    components: &mut [u16; MAX_NAME_COMPONENTS],
    count: &mut usize,
    offset: usize,
) -> Result<(), DnsFault> {
    let Some(slot) = components.get_mut(*count) else {
        return Err(DnsFault::resource(offset, 1, MESSAGE_NAME_TOO_LONG));
    };
    *slot =
        u16::try_from(offset).map_err(|_| DnsFault::resource(offset, 1, MESSAGE_NAME_TOO_LONG))?;
    *count += 1;
    Ok(())
}

fn append_label(
    rendered: &mut [u8; MAX_RENDERED_NAME_BYTES],
    rendered_length: &mut usize,
    label: &[u8],
    evidence_offset: usize,
) -> Result<(), DnsFault> {
    for &byte in label {
        if byte.is_ascii_graphic() && !matches!(byte, b'.' | b'\\') {
            append_rendered(rendered, rendered_length, &[byte], evidence_offset)?;
        } else {
            let escaped = [
                b'\\',
                b'0' + (byte / 100),
                b'0' + ((byte / 10) % 10),
                b'0' + (byte % 10),
            ];
            append_rendered(rendered, rendered_length, &escaped, evidence_offset)?;
        }
    }
    append_rendered(rendered, rendered_length, b".", evidence_offset)
}

fn append_rendered(
    rendered: &mut [u8; MAX_RENDERED_NAME_BYTES],
    rendered_length: &mut usize,
    value: &[u8],
    evidence_offset: usize,
) -> Result<(), DnsFault> {
    let end = rendered_length
        .checked_add(value.len())
        .ok_or_else(|| DnsFault::resource(evidence_offset, 1, MESSAGE_NAME_TOO_LONG))?;
    let destination = rendered
        .get_mut(*rendered_length..end)
        .ok_or_else(|| DnsFault::resource(evidence_offset, 1, MESSAGE_NAME_TOO_LONG))?;
    destination.copy_from_slice(value);
    *rendered_length = end;
    Ok(())
}

fn add_name_field(
    sink: &mut PacketDecodeSink<'_>,
    field_name: &str,
    name: &ParsedName,
    message_range: ByteRange,
) -> Result<FieldId, ImportError> {
    let value = sink.intern(name.as_str()?)?;
    add_named_field(
        sink,
        field_name,
        FieldValue::String(value),
        name.range(message_range)?,
    )
}

fn add_unsigned(
    sink: &mut PacketDecodeSink<'_>,
    name: &str,
    value: u64,
    range: ByteRange,
) -> Result<FieldId, ImportError> {
    add_named_field(sink, name, FieldValue::Unsigned(value), range)
}

fn relative_range(
    message_range: ByteRange,
    offset: usize,
    length: usize,
) -> Result<ByteRange, ImportError> {
    let offset = u32::try_from(offset).map_err(|_| ImportError::Arithmetic)?;
    let length = u32::try_from(length).map_err(|_| ImportError::Arithmetic)?;
    message_range
        .child(offset, length)
        .ok_or(ImportError::Arithmetic)
}
