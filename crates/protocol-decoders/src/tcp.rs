//! Bounded TCP header and option decoding.

use packet_core::{
    ByteRange, DiagnosticCode, FieldValue, ImportError, PacketDecodeInput, PacketDecodeSink,
    Severity,
};

use crate::{
    ChildIds, MAX_TCP_OPTION_ITEMS, NetworkPayload, ProtocolFinding, TransportDecode,
    TransportPayload, TransportProtocol, add_named_field, checksum, finish_layer, packet_slice,
    read_u16, read_u32, record_finding,
};

const FIXED_HEADER_LENGTH: usize = 20;
const MAX_HEADER_LENGTH: usize = 60;

const MESSAGE_TRUNCATED_HEADER: &str = "TCP header ends before all required bytes are available";
const MESSAGE_TRUNCATED_SEGMENT: &str = "TCP segment extends beyond the captured network payload";
const MESSAGE_INVALID_HEADER_LENGTH: &str =
    "TCP data offset describes a header shorter than 20 bytes";
const MESSAGE_HEADER_EXCEEDS_SEGMENT: &str =
    "TCP data offset describes a header longer than the enclosing network payload";
const MESSAGE_INVALID_OPTION_LENGTH: &str =
    "TCP option length does not advance within the data-offset-bounded header";
const MESSAGE_INVALID_KNOWN_OPTION_LENGTH: &str =
    "TCP option length contradicts the recognized option format";
const MESSAGE_NONZERO_OPTION_PADDING: &str =
    "TCP bytes after End of Option List contain non-zero padding";
const MESSAGE_INVALID_CHECKSUM: &str = "TCP checksum does not validate against the captured segment; capture offload may explain the observed value";

#[allow(clippy::too_many_lines)] // Keeping ordered length gates together makes the bounds auditable.
pub(crate) fn decode(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
) -> Result<TransportDecode, ImportError> {
    let bytes = packet_slice(input, network.payload_range)?;
    let available = bytes.len();
    let declared_length = network.declared_length as usize;
    let data_offset_words = bytes.get(12).map_or(0, |byte| byte >> 4);
    let declared_header_length = usize::from(data_offset_words) * 4;
    let valid_data_offset = data_offset_words >= 5;
    let layer_length = if valid_data_offset {
        available.min(declared_header_length)
    } else {
        available.min(FIXED_HEADER_LENGTH)
    };
    let layer_range = tcp_range(network, 0, layer_length)?;
    let root = add_named_field(sink, "tcp", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();

    add_fixed_fields(bytes, sink, network, &mut children)?;

    if network.fragment.is_complete_datagram() && declared_length < FIXED_HEADER_LENGTH {
        return finish_decode(
            sink,
            layer_range,
            root,
            &children,
            None,
            Some(malformed_finding(
                evidence_or_selector(layer_range, network.selector_range),
                MESSAGE_HEADER_EXCEEDS_SEGMENT,
            )),
        );
    }
    if available < FIXED_HEADER_LENGTH {
        let finding = (available < declared_length).then_some(truncated_finding(
            evidence_or_selector(layer_range, network.selector_range),
            MESSAGE_TRUNCATED_HEADER,
        ));
        return finish_decode(sink, layer_range, root, &children, None, finding);
    }

    let data_offset_range = tcp_range(network, 12, 1)?;
    if !valid_data_offset {
        return finish_decode(
            sink,
            layer_range,
            root,
            &children,
            None,
            Some(malformed_finding(
                data_offset_range,
                MESSAGE_INVALID_HEADER_LENGTH,
            )),
        );
    }
    if declared_header_length > declared_length {
        let finding = network
            .fragment
            .is_complete_datagram()
            .then_some(malformed_finding(
                data_offset_range,
                MESSAGE_HEADER_EXCEEDS_SEGMENT,
            ));
        return finish_decode(sink, layer_range, root, &children, None, finding);
    }
    if available < declared_header_length {
        let finding = (network.fragment.is_complete_datagram() || available < declared_length)
            .then_some(truncated_finding(
                evidence_or_selector(layer_range, network.selector_range),
                MESSAGE_TRUNCATED_HEADER,
            ));
        return finish_decode(sink, layer_range, root, &children, None, finding);
    }

    let mut finding = if available < declared_length {
        Some(truncated_finding(
            evidence_or_selector(layer_range, network.selector_range),
            MESSAGE_TRUNCATED_SEGMENT,
        ))
    } else {
        None
    };
    let option_finding = if declared_header_length > FIXED_HEADER_LENGTH {
        decode_options(bytes, sink, network, declared_header_length, &mut children)?
    } else {
        None
    };
    record_finding(&mut finding, option_finding);
    let structurally_sound = option_finding.is_none();
    let complete_segment = network.fragment.is_complete_datagram()
        && available == declared_length
        && structurally_sound;

    if complete_segment {
        if let Some(valid) =
            checksum::transport_checksum_valid(input, network, 6, network.payload_range)?
        {
            let checksum_range = tcp_range(network, 16, 2)?;
            add_boolean(sink, &mut children, "checksum_valid", valid, checksum_range)?;
            if !valid {
                record_finding(
                    &mut finding,
                    Some(ProtocolFinding {
                        priority: 10,
                        code: DiagnosticCode::INVALID_PROTOCOL_CHECKSUM,
                        severity: Severity::Warning,
                        evidence: checksum_range,
                        message: MESSAGE_INVALID_CHECKSUM,
                    }),
                );
            }
        }
    }

    let payload = if complete_segment {
        let source_port = read_u16(bytes, 0).ok_or(ImportError::Arithmetic)?;
        let destination_port = read_u16(bytes, 2).ok_or(ImportError::Arithmetic)?;
        let payload_length = declared_length
            .checked_sub(declared_header_length)
            .ok_or(ImportError::Arithmetic)?;
        Some(TransportPayload {
            protocol: TransportProtocol::Tcp,
            source_port,
            destination_port,
            payload_range: tcp_range(network, declared_header_length, payload_length)?,
            declared_length: u32::try_from(payload_length).map_err(|_| ImportError::Arithmetic)?,
        })
    } else {
        None
    };

    finish_decode(sink, layer_range, root, &children, payload, finding)
}

fn add_fixed_fields(
    bytes: &[u8],
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
    children: &mut ChildIds,
) -> Result<(), ImportError> {
    if bytes.len() >= 2 {
        add_unsigned(
            sink,
            children,
            "source_port",
            u64::from(read_u16(bytes, 0).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, 0, 2)?,
        )?;
    }
    if bytes.len() >= 4 {
        add_unsigned(
            sink,
            children,
            "destination_port",
            u64::from(read_u16(bytes, 2).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, 2, 2)?,
        )?;
    }
    if bytes.len() >= 8 {
        add_unsigned(
            sink,
            children,
            "sequence_number",
            u64::from(read_u32(bytes, 4).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, 4, 4)?,
        )?;
    }
    if bytes.len() >= 12 {
        add_unsigned(
            sink,
            children,
            "acknowledgment_number",
            u64::from(read_u32(bytes, 8).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, 8, 4)?,
        )?;
    }
    if bytes.len() >= 13 {
        let range = tcp_range(network, 12, 1)?;
        let data_offset_words = bytes[12] >> 4;
        add_unsigned(
            sink,
            children,
            "data_offset_words",
            u64::from(data_offset_words),
            range,
        )?;
        add_unsigned(
            sink,
            children,
            "header_length",
            u64::from(data_offset_words) * 4,
            range,
        )?;
        add_unsigned(
            sink,
            children,
            "reserved",
            u64::from(bytes[12] & 0x0f),
            range,
        )?;
    }
    if bytes.len() >= 14 {
        add_flags(sink, children, bytes[13], tcp_range(network, 13, 1)?)?;
    }
    if bytes.len() >= 16 {
        add_unsigned(
            sink,
            children,
            "window",
            u64::from(read_u16(bytes, 14).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, 14, 2)?,
        )?;
    }
    if bytes.len() >= 18 {
        add_unsigned(
            sink,
            children,
            "checksum",
            u64::from(read_u16(bytes, 16).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, 16, 2)?,
        )?;
    }
    if bytes.len() >= FIXED_HEADER_LENGTH {
        add_unsigned(
            sink,
            children,
            "urgent_pointer",
            u64::from(read_u16(bytes, 18).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, 18, 2)?,
        )?;
    }
    Ok(())
}

fn add_flags(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    flags: u8,
    range: ByteRange,
) -> Result<(), ImportError> {
    add_unsigned(sink, children, "flags", u64::from(flags), range)?;
    for (name, mask) in [
        ("cwr", 0x80),
        ("ece", 0x40),
        ("urg", 0x20),
        ("ack", 0x10),
        ("psh", 0x08),
        ("rst", 0x04),
        ("syn", 0x02),
        ("fin", 0x01),
    ] {
        add_boolean(sink, children, name, flags & mask != 0, range)?;
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One bounded cursor loop keeps option progress guarantees local.
fn decode_options(
    bytes: &[u8],
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
    header_length: usize,
    root_children: &mut ChildIds,
) -> Result<Option<ProtocolFinding>, ImportError> {
    debug_assert!((FIXED_HEADER_LENGTH..=MAX_HEADER_LENGTH).contains(&header_length));
    let area_range = tcp_range(
        network,
        FIXED_HEADER_LENGTH,
        header_length - FIXED_HEADER_LENGTH,
    )?;
    let area_root = add_named_field(sink, "tcp_options", FieldValue::None, area_range)?;
    let mut option_children = ChildIds::new();
    let mut cursor = FIXED_HEADER_LENGTH;
    let mut item_count = 0_u32;
    let mut finding = None;

    while cursor < header_length {
        item_count = item_count.checked_add(1).ok_or(ImportError::Arithmetic)?;
        debug_assert!(item_count <= MAX_TCP_OPTION_ITEMS);
        let kind = bytes[cursor];
        if kind == 0 {
            let range = tcp_range(network, cursor, 1)?;
            option_children.push(add_named_field(
                sink,
                "end_of_options",
                FieldValue::Unsigned(0),
                range,
            )?)?;
            cursor += 1;
            if cursor < header_length {
                let padding_range = tcp_range(network, cursor, header_length - cursor)?;
                option_children.push(add_named_field(
                    sink,
                    "padding",
                    FieldValue::Bytes(padding_range),
                    padding_range,
                )?)?;
                if bytes[cursor..header_length].iter().any(|byte| *byte != 0) {
                    record_finding(
                        &mut finding,
                        Some(malformed_finding(
                            padding_range,
                            MESSAGE_NONZERO_OPTION_PADDING,
                        )),
                    );
                }
            }
            break;
        }
        if kind == 1 {
            let range = tcp_range(network, cursor, 1)?;
            option_children.push(add_named_field(
                sink,
                "no_operation",
                FieldValue::Unsigned(1),
                range,
            )?)?;
            cursor += 1;
            continue;
        }

        let available = header_length - cursor;
        let declared_length = if cursor + 1 < header_length {
            Some(usize::from(bytes[cursor + 1]))
        } else {
            None
        };
        let retained_length = declared_length.map_or(1, |length| length.max(2).min(available));
        let item_range = tcp_range(network, cursor, retained_length)?;
        let item_root =
            add_named_field(sink, option_root_name(kind), FieldValue::None, item_range)?;
        let mut fields = ChildIds::new();
        add_unsigned(
            sink,
            &mut fields,
            "option_kind",
            u64::from(kind),
            tcp_range(network, cursor, 1)?,
        )?;
        if let Some(declared_length) = declared_length {
            add_unsigned(
                sink,
                &mut fields,
                "option_length",
                u64::try_from(declared_length).map_err(|_| ImportError::Arithmetic)?,
                tcp_range(network, cursor + 1, 1)?,
            )?;
        }

        let structurally_valid =
            declared_length.is_some_and(|length| length >= 2 && length <= available);
        if !structurally_valid {
            if retained_length > 2 {
                add_bytes(
                    sink,
                    &mut fields,
                    "data",
                    tcp_range(network, cursor + 2, retained_length - 2)?,
                )?;
            }
            sink.set_field_children(item_root, fields.as_slice())?;
            option_children.push(item_root)?;
            record_finding(
                &mut finding,
                Some(malformed_finding(item_range, MESSAGE_INVALID_OPTION_LENGTH)),
            );
            break;
        }

        let length = declared_length.ok_or(ImportError::Arithmetic)?;
        let known_length_valid = match kind {
            2 => length == 4,
            3 => length == 3,
            4 => length == 2,
            5 => length >= 10 && (length - 2) % 8 == 0,
            8 => length == 10,
            _ => true,
        };
        if known_length_valid {
            decode_known_option(bytes, sink, network, cursor, kind, length, &mut fields)?;
        } else {
            if length > 2 {
                add_bytes(
                    sink,
                    &mut fields,
                    "data",
                    tcp_range(network, cursor + 2, length - 2)?,
                )?;
            }
            record_finding(
                &mut finding,
                Some(malformed_finding(
                    tcp_range(network, cursor + 1, 1)?,
                    MESSAGE_INVALID_KNOWN_OPTION_LENGTH,
                )),
            );
        }
        sink.set_field_children(item_root, fields.as_slice())?;
        option_children.push(item_root)?;
        cursor = cursor.checked_add(length).ok_or(ImportError::Arithmetic)?;
    }

    sink.set_field_children(area_root, option_children.as_slice())?;
    root_children.push(area_root)?;
    Ok(finding)
}

fn decode_known_option(
    bytes: &[u8],
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
    cursor: usize,
    kind: u8,
    length: usize,
    fields: &mut ChildIds,
) -> Result<(), ImportError> {
    match kind {
        2 => add_unsigned(
            sink,
            fields,
            "maximum_segment_size",
            u64::from(read_u16(bytes, cursor + 2).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, cursor + 2, 2)?,
        ),
        3 => add_unsigned(
            sink,
            fields,
            "window_scale_shift",
            u64::from(bytes[cursor + 2]),
            tcp_range(network, cursor + 2, 1)?,
        ),
        4 => Ok(()),
        5 => add_sack_blocks(bytes, sink, network, cursor, length, fields),
        8 => {
            add_unsigned(
                sink,
                fields,
                "timestamp_value",
                u64::from(read_u32(bytes, cursor + 2).ok_or(ImportError::Arithmetic)?),
                tcp_range(network, cursor + 2, 4)?,
            )?;
            add_unsigned(
                sink,
                fields,
                "timestamp_echo_reply",
                u64::from(read_u32(bytes, cursor + 6).ok_or(ImportError::Arithmetic)?),
                tcp_range(network, cursor + 6, 4)?,
            )
        }
        _ => {
            if length > 2 {
                add_bytes(
                    sink,
                    fields,
                    "data",
                    tcp_range(network, cursor + 2, length - 2)?,
                )?;
            }
            Ok(())
        }
    }
}

fn add_sack_blocks(
    bytes: &[u8],
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
    cursor: usize,
    length: usize,
    fields: &mut ChildIds,
) -> Result<(), ImportError> {
    let sack_area_range = tcp_range(network, cursor + 2, length - 2)?;
    let sack_area_root = add_named_field(sink, "sack_blocks", FieldValue::None, sack_area_range)?;
    let mut blocks = ChildIds::new();
    let mut block_cursor = cursor + 2;
    let end = cursor.checked_add(length).ok_or(ImportError::Arithmetic)?;
    while block_cursor < end {
        let item_range = tcp_range(network, block_cursor, 8)?;
        let item_root = add_named_field(sink, "sack_block", FieldValue::None, item_range)?;
        let mut block_fields = ChildIds::new();
        add_unsigned(
            sink,
            &mut block_fields,
            "left_edge",
            u64::from(read_u32(bytes, block_cursor).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, block_cursor, 4)?,
        )?;
        add_unsigned(
            sink,
            &mut block_fields,
            "right_edge",
            u64::from(read_u32(bytes, block_cursor + 4).ok_or(ImportError::Arithmetic)?),
            tcp_range(network, block_cursor + 4, 4)?,
        )?;
        sink.set_field_children(item_root, block_fields.as_slice())?;
        blocks.push(item_root)?;
        block_cursor = block_cursor.checked_add(8).ok_or(ImportError::Arithmetic)?;
    }
    sink.set_field_children(sack_area_root, blocks.as_slice())?;
    fields.push(sack_area_root)
}

const fn option_root_name(kind: u8) -> &'static str {
    match kind {
        2 => "maximum_segment_size_option",
        3 => "window_scale_option",
        4 => "sack_permitted_option",
        5 => "sack_option",
        8 => "timestamp_option",
        _ => "tcp_option",
    }
}

fn finish_decode(
    sink: &mut PacketDecodeSink<'_>,
    layer_range: ByteRange,
    root: packet_core::FieldId,
    children: &ChildIds,
    payload: Option<TransportPayload>,
    finding: Option<ProtocolFinding>,
) -> Result<TransportDecode, ImportError> {
    finish_layer(sink, "tcp", layer_range, root, children)?;
    Ok(TransportDecode::new(payload, finding))
}

fn malformed_finding(evidence: ByteRange, message: &'static str) -> ProtocolFinding {
    ProtocolFinding {
        priority: 120,
        code: DiagnosticCode::MALFORMED_PROTOCOL,
        severity: Severity::Warning,
        evidence,
        message,
    }
}

fn truncated_finding(evidence: ByteRange, message: &'static str) -> ProtocolFinding {
    ProtocolFinding {
        priority: 100,
        code: DiagnosticCode::TRUNCATED_PROTOCOL,
        severity: Severity::Error,
        evidence,
        message,
    }
}

const fn evidence_or_selector(range: ByteRange, selector: ByteRange) -> ByteRange {
    if range.length() == 0 { selector } else { range }
}

fn tcp_range(
    network: NetworkPayload,
    offset: usize,
    length: usize,
) -> Result<ByteRange, ImportError> {
    let offset = u32::try_from(offset).map_err(|_| ImportError::Arithmetic)?;
    let length = u32::try_from(length).map_err(|_| ImportError::Arithmetic)?;
    network
        .payload_range
        .child(offset, length)
        .ok_or(ImportError::Arithmetic)
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
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    range: ByteRange,
) -> Result<(), ImportError> {
    children.push(add_named_field(
        sink,
        name,
        FieldValue::Bytes(range),
        range,
    )?)
}
