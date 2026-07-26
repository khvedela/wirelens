//! Bounded IPv4 decoding.

use packet_core::{
    ByteRange, DiagnosticCode, FieldId, FieldValue, ImportError, PacketDecodeInput,
    PacketDecodeSink, Severity,
};

use crate::{
    ChildIds, FragmentPosition, MAX_IPV4_OPTION_ITEMS, NetworkPayload, add_diagnostic,
    add_named_field, finish_layer, packet_range, read_u16,
};

const FIXED_HEADER_LENGTH: usize = 20;
const MAX_HEADER_LENGTH: usize = 60;

const MESSAGE_TRUNCATED_HEADER: &str =
    "IPv4 header ends before its declared header length is available";
const MESSAGE_TRUNCATED_PAYLOAD: &str =
    "IPv4 total length extends beyond the captured packet bytes";
const MESSAGE_INVALID_VERSION: &str = "IPv4 EtherType contains a non-IPv4 version value";
const MESSAGE_INVALID_HEADER_LENGTH: &str = "IPv4 header length is smaller than 20 bytes";
const MESSAGE_INVALID_TOTAL_LENGTH: &str =
    "IPv4 total length is smaller than the declared header length";
const MESSAGE_INVALID_OPTION_LENGTH: &str =
    "IPv4 option length does not advance within the declared header";
const MESSAGE_INVALID_FRAGMENT_FLAGS: &str =
    "IPv4 fragment flags or payload length are structurally contradictory";
const MESSAGE_INVALID_CHECKSUM: &str =
    "IPv4 header checksum does not validate; capture offload may explain the observed value";

#[derive(Clone, Copy)]
struct Finding {
    priority: u8,
    code: DiagnosticCode,
    severity: Severity,
    evidence: ByteRange,
    message: &'static str,
}

#[derive(Clone, Copy)]
struct FixedHeader {
    total_length: usize,
    flags_fragment: u16,
}

struct CompleteHeader {
    offset: usize,
    available: usize,
    declared_length: usize,
    layer_range: ByteRange,
    root: FieldId,
    children: ChildIds,
    fixed: FixedHeader,
}

pub(crate) fn decode(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    offset: usize,
) -> Result<Option<NetworkPayload>, ImportError> {
    let available = input.bytes().len().saturating_sub(offset);
    let first = input.bytes().get(offset).copied();
    let version = first.map_or(0, |value| value >> 4);
    let header_words = first.map_or(0, |value| value & 0x0f);
    let declared_header_length = usize::from(header_words) * 4;
    let structurally_sized = version == 4 && declared_header_length >= FIXED_HEADER_LENGTH;
    let layer_length = if structurally_sized {
        available.min(declared_header_length)
    } else {
        available.min(FIXED_HEADER_LENGTH)
    };
    let layer_range = packet_range(input, offset, layer_length)?;
    let root = add_named_field(sink, "ipv4", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();

    let Some(first) = first else {
        finish_layer(sink, "ipv4", layer_range, root, &children)?;
        add_diagnostic(
            sink,
            DiagnosticCode::TRUNCATED_PROTOCOL,
            Severity::Error,
            Some(layer_range),
            MESSAGE_TRUNCATED_HEADER,
        )?;
        return Ok(None);
    };
    let first_range = packet_range(input, offset, 1)?;
    add_unsigned(
        sink,
        &mut children,
        "version",
        u64::from(version),
        first_range,
    )?;
    add_unsigned(
        sink,
        &mut children,
        "header_length",
        u64::try_from(declared_header_length).map_err(|_| ImportError::Arithmetic)?,
        first_range,
    )?;

    if version != 4 {
        finish_layer(sink, "ipv4", layer_range, root, &children)?;
        add_diagnostic(
            sink,
            DiagnosticCode::MALFORMED_PROTOCOL,
            Severity::Warning,
            Some(first_range),
            MESSAGE_INVALID_VERSION,
        )?;
        return Ok(None);
    }
    if declared_header_length < FIXED_HEADER_LENGTH {
        finish_layer(sink, "ipv4", layer_range, root, &children)?;
        add_diagnostic(
            sink,
            DiagnosticCode::MALFORMED_PROTOCOL,
            Severity::Warning,
            Some(first_range),
            MESSAGE_INVALID_HEADER_LENGTH,
        )?;
        return Ok(None);
    }

    let fixed = add_fixed_fields(input, sink, offset, available, first, &mut children)?;
    let Some(fixed) = fixed else {
        finish_layer(sink, "ipv4", layer_range, root, &children)?;
        add_diagnostic(
            sink,
            DiagnosticCode::TRUNCATED_PROTOCOL,
            Severity::Error,
            Some(layer_range),
            MESSAGE_TRUNCATED_HEADER,
        )?;
        return Ok(None);
    };
    if available < declared_header_length {
        finish_layer(sink, "ipv4", layer_range, root, &children)?;
        add_diagnostic(
            sink,
            DiagnosticCode::TRUNCATED_PROTOCOL,
            Severity::Error,
            Some(layer_range),
            MESSAGE_TRUNCATED_HEADER,
        )?;
        return Ok(None);
    }

    decode_complete_header(
        input,
        sink,
        CompleteHeader {
            offset,
            available,
            declared_length: declared_header_length,
            layer_range,
            root,
            children,
            fixed,
        },
    )
}

fn decode_complete_header(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    mut header: CompleteHeader,
) -> Result<Option<NetworkPayload>, ImportError> {
    let header_end = header
        .offset
        .checked_add(header.declared_length)
        .ok_or(ImportError::Arithmetic)?;
    let header_range = packet_range(input, header.offset, header.declared_length)?;
    let header_bytes = input
        .bytes()
        .get(header.offset..header_end)
        .ok_or(ImportError::Arithmetic)?;
    let checksum_valid = checksum_valid(header_bytes);
    add_boolean(
        sink,
        &mut header.children,
        "header_checksum_valid",
        checksum_valid,
        header_range,
    )?;

    let mut finding = (!checksum_valid).then_some(Finding {
        priority: 10,
        code: DiagnosticCode::INVALID_PROTOCOL_CHECKSUM,
        severity: Severity::Warning,
        evidence: header_range,
        message: MESSAGE_INVALID_CHECKSUM,
    });
    let mut dispatch_safe = validate_lengths_and_fragments(
        input,
        header.offset,
        header.available,
        header.declared_length,
        header.fixed,
        &mut finding,
    )?;
    if header.declared_length > FIXED_HEADER_LENGTH {
        let options_start = header
            .offset
            .checked_add(FIXED_HEADER_LENGTH)
            .ok_or(ImportError::Arithmetic)?;
        let option_finding =
            decode_options(input, sink, options_start, header_end, &mut header.children)?;
        dispatch_safe &= option_finding.is_none();
        record_finding(&mut finding, option_finding);
    }

    let payload = dispatch_safe
        .then(|| network_payload(input, header.offset, header.declared_length, header.fixed))
        .transpose()?;

    debug_assert_eq!(header.layer_range, header_range);
    finish_layer(sink, "ipv4", header_range, header.root, &header.children)?;
    if let Some(finding) = finding {
        add_diagnostic(
            sink,
            finding.code,
            finding.severity,
            Some(finding.evidence),
            finding.message,
        )?;
    }
    Ok(payload)
}

fn network_payload(
    input: PacketDecodeInput<'_>,
    offset: usize,
    header_length: usize,
    fixed: FixedHeader,
) -> Result<NetworkPayload, ImportError> {
    let payload_start = offset
        .checked_add(header_length)
        .ok_or(ImportError::Arithmetic)?;
    let declared_length = fixed
        .total_length
        .checked_sub(header_length)
        .ok_or(ImportError::Arithmetic)?;
    let declared_end = payload_start
        .checked_add(declared_length)
        .ok_or(ImportError::Arithmetic)?;
    let captured_end = declared_end.min(input.bytes().len());
    let captured_length = captured_end
        .checked_sub(payload_start)
        .ok_or(ImportError::Arithmetic)?;
    let fragment_offset = fixed.flags_fragment & 0x1fff;
    let more_fragments = fixed.flags_fragment & 0x2000 != 0;
    let fragment = if fragment_offset != 0 {
        FragmentPosition::NonInitial {
            offset_bytes: u32::from(fragment_offset) * 8,
            more_fragments,
        }
    } else if more_fragments {
        FragmentPosition::Initial {
            more_fragments: true,
        }
    } else {
        FragmentPosition::Unfragmented
    };
    let selector_offset = offset.checked_add(9).ok_or(ImportError::Arithmetic)?;
    let next_header = input
        .bytes()
        .get(selector_offset)
        .copied()
        .ok_or(ImportError::Arithmetic)?;

    Ok(NetworkPayload {
        next_header,
        selector_range: packet_range(input, selector_offset, 1)?,
        payload_range: packet_range(input, payload_start, captured_length)?,
        declared_length: u32::try_from(declared_length).map_err(|_| ImportError::Arithmetic)?,
        fragment,
    })
}

fn add_fixed_fields(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    offset: usize,
    available: usize,
    first: u8,
    children: &mut ChildIds,
) -> Result<Option<FixedHeader>, ImportError> {
    let bytes = input.bytes();
    if available >= 2 {
        let range = packet_range(input, offset + 1, 1)?;
        add_unsigned(
            sink,
            children,
            "differentiated_services",
            u64::from(bytes[offset + 1] >> 2),
            range,
        )?;
        add_unsigned(
            sink,
            children,
            "explicit_congestion_notification",
            u64::from(bytes[offset + 1] & 0x03),
            range,
        )?;
    }
    if available >= 4 {
        add_u16(input, sink, children, "total_length", offset + 2)?;
    }
    if available >= 6 {
        add_u16(input, sink, children, "identification", offset + 4)?;
    }
    if available >= 8 {
        add_fragment_fields(input, sink, children, offset + 6)?;
    }
    if available >= 9 {
        let range = packet_range(input, offset + 8, 1)?;
        add_unsigned(
            sink,
            children,
            "time_to_live",
            u64::from(bytes[offset + 8]),
            range,
        )?;
    }
    if available >= 10 {
        let range = packet_range(input, offset + 9, 1)?;
        add_unsigned(
            sink,
            children,
            "protocol",
            u64::from(bytes[offset + 9]),
            range,
        )?;
    }
    if available >= 12 {
        add_u16(input, sink, children, "header_checksum", offset + 10)?;
    }
    if available >= 16 {
        add_bytes(input, sink, children, "source_address", offset + 12, 4)?;
    }
    if available >= FIXED_HEADER_LENGTH {
        add_bytes(input, sink, children, "destination_address", offset + 16, 4)?;
        let total_length = usize::from(read_u16(bytes, offset + 2).ok_or(ImportError::Arithmetic)?);
        let flags_fragment = read_u16(bytes, offset + 6).ok_or(ImportError::Arithmetic)?;
        debug_assert_eq!(first >> 4, 4);
        return Ok(Some(FixedHeader {
            total_length,
            flags_fragment,
        }));
    }
    Ok(None)
}

fn add_fragment_fields(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    offset: usize,
) -> Result<(), ImportError> {
    let value = read_u16(input.bytes(), offset).ok_or(ImportError::Arithmetic)?;
    let range = packet_range(input, offset, 2)?;
    let fragment_offset = value & 0x1fff;
    add_unsigned(sink, children, "flags", u64::from(value >> 13), range)?;
    add_boolean(sink, children, "reserved_flag", value & 0x8000 != 0, range)?;
    add_boolean(sink, children, "dont_fragment", value & 0x4000 != 0, range)?;
    add_boolean(sink, children, "more_fragments", value & 0x2000 != 0, range)?;
    add_unsigned(
        sink,
        children,
        "fragment_offset",
        u64::from(fragment_offset),
        range,
    )?;
    add_unsigned(
        sink,
        children,
        "fragment_offset_bytes",
        u64::from(fragment_offset) * 8,
        range,
    )
}

fn validate_lengths_and_fragments(
    input: PacketDecodeInput<'_>,
    offset: usize,
    available: usize,
    header_length: usize,
    fixed: FixedHeader,
    finding: &mut Option<Finding>,
) -> Result<bool, ImportError> {
    let total_range = packet_range(input, offset + 2, 2)?;
    if fixed.total_length < header_length {
        record_finding(
            finding,
            Some(Finding {
                priority: 90,
                code: DiagnosticCode::MALFORMED_PROTOCOL,
                severity: Severity::Warning,
                evidence: total_range,
                message: MESSAGE_INVALID_TOTAL_LENGTH,
            }),
        );
        return Ok(false);
    }
    if fixed.total_length > available {
        record_finding(
            finding,
            Some(Finding {
                priority: 100,
                code: DiagnosticCode::TRUNCATED_PROTOCOL,
                severity: Severity::Error,
                evidence: total_range,
                message: MESSAGE_TRUNCATED_PAYLOAD,
            }),
        );
    }

    let reserved = fixed.flags_fragment & 0x8000 != 0;
    let dont_fragment = fixed.flags_fragment & 0x4000 != 0;
    let more_fragments = fixed.flags_fragment & 0x2000 != 0;
    let fragment_offset = fixed.flags_fragment & 0x1fff;
    let payload_length = fixed.total_length - header_length;
    let contradictory = reserved
        || (dont_fragment && (more_fragments || fragment_offset != 0))
        || (more_fragments && payload_length % 8 != 0);
    if contradictory {
        record_finding(
            finding,
            Some(Finding {
                priority: 80,
                code: DiagnosticCode::MALFORMED_PROTOCOL,
                severity: Severity::Warning,
                evidence: packet_range(input, offset + 6, 2)?,
                message: MESSAGE_INVALID_FRAGMENT_FLAGS,
            }),
        );
    }
    Ok(!contradictory)
}

fn decode_options(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    start: usize,
    end: usize,
    root_children: &mut ChildIds,
) -> Result<Option<Finding>, ImportError> {
    debug_assert!(end >= start && end - start <= MAX_HEADER_LENGTH - FIXED_HEADER_LENGTH);
    let area_range = packet_range(input, start, end - start)?;
    let area_root = add_named_field(sink, "ipv4_options", FieldValue::None, area_range)?;
    let mut option_children = ChildIds::new();
    let mut cursor = start;
    let mut item_count = 0_u32;
    let mut finding = None;

    while cursor < end {
        item_count = item_count.checked_add(1).ok_or(ImportError::Arithmetic)?;
        debug_assert!(item_count <= MAX_IPV4_OPTION_ITEMS);
        let option_type = input.bytes()[cursor];
        if option_type == 0 {
            let range = packet_range(input, cursor, 1)?;
            option_children.push(add_named_field(
                sink,
                "end_of_options",
                FieldValue::Unsigned(0),
                range,
            )?)?;
            cursor += 1;
            if cursor < end {
                add_bytes(
                    input,
                    sink,
                    &mut option_children,
                    "padding",
                    cursor,
                    end - cursor,
                )?;
            }
            break;
        }
        if option_type == 1 {
            let range = packet_range(input, cursor, 1)?;
            option_children.push(add_named_field(
                sink,
                "no_operation",
                FieldValue::Unsigned(1),
                range,
            )?)?;
            cursor += 1;
            continue;
        }

        let available = end - cursor;
        let declared_length = if available >= 2 {
            let length_offset = cursor.checked_add(1).ok_or(ImportError::Arithmetic)?;
            input.bytes().get(length_offset).copied().map(usize::from)
        } else {
            None
        };
        let retained_length = declared_length.map_or(1, |length| length.max(2).min(available));
        let item_range = packet_range(input, cursor, retained_length)?;
        let item_root = add_named_field(sink, "ipv4_option", FieldValue::None, item_range)?;
        let mut fields = ChildIds::new();
        let type_range = packet_range(input, cursor, 1)?;
        add_unsigned(
            sink,
            &mut fields,
            "option_type",
            u64::from(option_type),
            type_range,
        )?;
        if let Some(declared_length) = declared_length {
            let length_range = packet_range(input, cursor + 1, 1)?;
            add_unsigned(
                sink,
                &mut fields,
                "option_length",
                u64::try_from(declared_length).map_err(|_| ImportError::Arithmetic)?,
                length_range,
            )?;
            if declared_length >= 2 && declared_length <= available && declared_length > 2 {
                add_bytes(
                    input,
                    sink,
                    &mut fields,
                    "data",
                    cursor + 2,
                    declared_length - 2,
                )?;
            }
        }
        sink.set_field_children(item_root, fields.as_slice())?;
        option_children.push(item_root)?;

        let Some(declared_length) = declared_length else {
            finding = Some(invalid_option_finding(item_range));
            break;
        };
        if declared_length < 2 || declared_length > available {
            finding = Some(invalid_option_finding(item_range));
            break;
        }
        cursor = cursor
            .checked_add(declared_length)
            .ok_or(ImportError::Arithmetic)?;
    }

    sink.set_field_children(area_root, option_children.as_slice())?;
    root_children.push(area_root)?;
    Ok(finding)
}

fn invalid_option_finding(evidence: ByteRange) -> Finding {
    Finding {
        priority: 90,
        code: DiagnosticCode::MALFORMED_PROTOCOL,
        severity: Severity::Warning,
        evidence,
        message: MESSAGE_INVALID_OPTION_LENGTH,
    }
}

fn add_u16(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    offset: usize,
) -> Result<(), ImportError> {
    let range = packet_range(input, offset, 2)?;
    let value = read_u16(input.bytes(), offset).ok_or(ImportError::Arithmetic)?;
    add_unsigned(sink, children, name, u64::from(value), range)
}

fn add_unsigned(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    value: u64,
    range: ByteRange,
) -> Result<(), ImportError> {
    children.push(add_named_field(
        sink,
        name,
        FieldValue::Unsigned(value),
        range,
    )?)
}

fn add_boolean(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    value: bool,
    range: ByteRange,
) -> Result<(), ImportError> {
    children.push(add_named_field(
        sink,
        name,
        FieldValue::Boolean(value),
        range,
    )?)
}

fn add_bytes(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    offset: usize,
    length: usize,
) -> Result<(), ImportError> {
    let range = packet_range(input, offset, length)?;
    children.push(add_named_field(
        sink,
        name,
        FieldValue::Bytes(range),
        range,
    )?)
}

fn checksum_valid(header: &[u8]) -> bool {
    let mut sum = 0_u32;
    for word in header.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    sum == u32::from(u16::MAX)
}

fn record_finding(current: &mut Option<Finding>, candidate: Option<Finding>) {
    if let Some(candidate) = candidate {
        if current.is_none_or(|existing| candidate.priority > existing.priority) {
            *current = Some(candidate);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use packet_core::{
        CaptureImporter, ImportLimits, ImportStep, PacketDecodeInput, PacketDecodeSink,
        PacketDecoder,
    };

    use super::*;

    #[derive(Clone)]
    struct PayloadProbe {
        observed: Arc<Mutex<Option<NetworkPayload>>>,
    }

    impl PacketDecoder for PayloadProbe {
        fn decode(
            &mut self,
            input: PacketDecodeInput<'_>,
            sink: &mut PacketDecodeSink<'_>,
        ) -> Result<(), ImportError> {
            let payload = super::decode(input, sink, 0)?;
            *self.observed.lock().expect("probe lock is not poisoned") = payload;
            Ok(())
        }
    }

    fn probe(packet: &[u8]) -> Option<NetworkPayload> {
        let observed = Arc::new(Mutex::new(None));
        let probe = PayloadProbe {
            observed: Arc::clone(&observed),
        };
        let capture = legacy_capture(packet);
        let mut importer = CaptureImporter::new_with_decoder(
            capture.into_boxed_slice(),
            ImportLimits::default(),
            Box::new(probe),
        )
        .expect("synthetic raw-IP capture is valid");
        loop {
            match importer
                .step(16, 1024 * 1024)
                .expect("synthetic raw-IP import succeeds")
            {
                ImportStep::Progress(_) => {}
                ImportStep::NeedsBudget { minimum_bytes, .. } => {
                    importer
                        .step(1, minimum_bytes)
                        .expect("reported minimum makes progress");
                }
                ImportStep::Ready(_) => break,
            }
        }
        importer.finish().expect("probe dataset validates");
        *observed.lock().expect("probe lock is not poisoned")
    }

    fn legacy_capture(packet: &[u8]) -> Vec<u8> {
        let packet_length = u32::try_from(packet.len()).expect("packet length fits u32");
        let mut capture = Vec::with_capacity(40 + packet.len());
        capture.extend([0xd4, 0xc3, 0xb2, 0xa1]);
        capture.extend(2_u16.to_le_bytes());
        capture.extend(4_u16.to_le_bytes());
        capture.extend(0_i32.to_le_bytes());
        capture.extend(0_u32.to_le_bytes());
        capture.extend(65_535_u32.to_le_bytes());
        capture.extend(101_u32.to_le_bytes());
        capture.extend(1_u32.to_le_bytes());
        capture.extend(2_u32.to_le_bytes());
        capture.extend(packet_length.to_le_bytes());
        capture.extend(packet_length.to_le_bytes());
        capture.extend(packet);
        capture
    }

    fn packet(
        options: &[u8],
        captured_payload: &[u8],
        total_length: u16,
        protocol: u8,
        flags_fragment: u16,
    ) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let header_length = 20 + options.len();
        let mut packet = Vec::with_capacity(header_length + captured_payload.len());
        packet.extend([
            0x40 | u8::try_from(header_length / 4).expect("IHL fits u8"),
            0,
        ]);
        packet.extend(total_length.to_be_bytes());
        packet.extend(0x1234_u16.to_be_bytes());
        packet.extend(flags_fragment.to_be_bytes());
        packet.extend([64, protocol]);
        packet.extend(0_u16.to_be_bytes());
        packet.extend([192, 0, 2, 1]);
        packet.extend([198, 51, 100, 2]);
        packet.extend(options);
        let checksum = checksum_for_fixture(&packet);
        packet[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.extend(captured_payload);
        packet
    }

    fn checksum_for_fixture(header: &[u8]) -> u16 {
        let mut sum = 0_u32;
        for pair in header.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
        }
        while sum > u32::from(u16::MAX) {
            sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
        }
        !u16::try_from(sum).expect("folded checksum fits u16")
    }

    #[test]
    fn hands_off_exact_selector_and_truncated_payload_bounds() {
        let payload = probe(&packet(&[], &[1, 2, 3, 4], 100, 17, 0))
            .expect("complete IPv4 header has a bounded handoff");

        assert_eq!(payload.next_header, 17);
        assert_eq!(payload.selector_range, ByteRange::new(49, 1).unwrap());
        assert_eq!(payload.payload_range, ByteRange::new(60, 4).unwrap());
        assert_eq!(payload.declared_length, 80);
        assert_eq!(payload.fragment, FragmentPosition::Unfragmented);
    }

    #[test]
    fn preserves_non_initial_fragment_position_for_dispatch_policy() {
        let payload = probe(&packet(&[], &[0; 8], 28, 6, 0x2002))
            .expect("structurally valid fragment has a bounded handoff");

        assert_eq!(
            payload.fragment,
            FragmentPosition::NonInitial {
                offset_bytes: 16,
                more_fragments: true,
            }
        );
        assert!(!payload.fragment.allows_transport_header());
    }

    #[test]
    fn malformed_options_do_not_reach_transport_dispatch() {
        assert!(probe(&packet(&[0x82, 1, 0, 0], &[], 24, 6, 0)).is_none());
    }
}
