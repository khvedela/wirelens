//! Bounded IPv6 decoding.

use packet_core::{
    ByteRange, DiagnosticCode, FieldValue, ImportError, PacketDecodeInput, PacketDecodeSink,
    Severity,
};

use crate::{
    ChildIds, FragmentPosition, MAX_IPV6_EXTENSION_BYTES, MAX_IPV6_EXTENSION_HEADERS,
    NetworkChecksumContext, NetworkDecode, NetworkPayload, NetworkVersion, ProtocolFinding,
    add_named_field, finish_layer, packet_range, read_u16, record_finding,
};

const FIXED_HEADER_LENGTH: usize = 40;
const FRAGMENT_HEADER_LENGTH: usize = 8;
const ESP_VISIBLE_HEADER_LENGTH: usize = 8;
const AH_FIXED_HEADER_LENGTH: usize = 12;

const HOP_BY_HOP: u8 = 0;
const ROUTING: u8 = 43;
const FRAGMENT: u8 = 44;
const ESP: u8 = 50;
const AUTHENTICATION: u8 = 51;
const NO_NEXT_HEADER: u8 = 59;
const DESTINATION_OPTIONS: u8 = 60;

const PRIORITY_MALFORMED: u8 = 120;
const PRIORITY_RESOURCE_LIMIT: u8 = 110;
const PRIORITY_TRUNCATED: u8 = 100;
const PRIORITY_UNSUPPORTED: u8 = 80;

const MESSAGE_TRUNCATED_HEADER: &str =
    "IPv6 header ends before all 40 fixed-header bytes are available";
const MESSAGE_INVALID_VERSION: &str = "IPv6 EtherType contains a non-IPv6 version value";
const MESSAGE_TRUNCATED_PAYLOAD: &str =
    "IPv6 payload length extends beyond the captured packet bytes";
const MESSAGE_TRUNCATED_EXTENSION: &str =
    "IPv6 extension header ends before its declared bytes are available";
const MESSAGE_MALFORMED_EXTENSION: &str =
    "IPv6 extension header length exceeds the enclosing IPv6 payload";
const MESSAGE_MISPLACED_HOP_BY_HOP: &str =
    "IPv6 Hop-by-Hop Options header does not immediately follow the fixed header";
const MESSAGE_MALFORMED_AH: &str =
    "IPv6 Authentication Header length is smaller than its fixed fields or is not 8-byte aligned";
const MESSAGE_EXTENSION_LIMIT: &str =
    "IPv6 extension traversal stopped at the configured depth or cumulative-byte limit";
const MESSAGE_UNSUPPORTED_JUMBOGRAM: &str =
    "IPv6 zero Payload Length with Hop-by-Hop requires unsupported Jumbo Payload semantics";
const MESSAGE_UNSUPPORTED_ESP: &str = "IPv6 ESP payload is retained, but security-association-dependent remainder, trailer, and next-header semantics are unsupported";

#[derive(Clone, Copy)]
enum VariableExtension {
    HopByHop,
    Routing,
    DestinationOptions,
}

impl VariableExtension {
    const fn protocol(self) -> &'static str {
        match self {
            Self::HopByHop => "ipv6_hop_by_hop",
            Self::Routing => "ipv6_routing",
            Self::DestinationOptions => "ipv6_destination_options",
        }
    }
}

#[derive(Clone, Copy)]
struct FixedHeader {
    payload_start: usize,
    declared_end: usize,
    captured_end: usize,
    next_header: u8,
    selector_range: ByteRange,
    checksum_context: NetworkChecksumContext,
    finding: Option<ProtocolFinding>,
}

#[derive(Clone, Copy)]
enum FixedStep {
    Complete(FixedHeader),
    Stop(ProtocolFinding),
}

pub(crate) fn decode(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    offset: usize,
) -> Result<NetworkDecode, ImportError> {
    match decode_fixed_header(input, sink, offset)? {
        FixedStep::Complete(fixed) => traverse_extensions(input, sink, fixed),
        FixedStep::Stop(finding) => Ok(NetworkDecode::stopped(finding)),
    }
}

fn decode_fixed_header(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    offset: usize,
) -> Result<FixedStep, ImportError> {
    let available = input.bytes().len().saturating_sub(offset);
    let fixed_range = packet_range(input, offset, available.min(FIXED_HEADER_LENGTH))?;
    let root = add_named_field(sink, "ipv6", FieldValue::None, fixed_range)?;
    let mut children = ChildIds::new();

    let Some(first) = input.bytes().get(offset).copied() else {
        finish_layer(sink, "ipv6", fixed_range, root, &children)?;
        return Ok(FixedStep::Stop(ProtocolFinding {
            priority: PRIORITY_TRUNCATED,
            code: DiagnosticCode::TRUNCATED_PROTOCOL,
            severity: Severity::Error,
            evidence: fixed_range,
            message: MESSAGE_TRUNCATED_HEADER,
        }));
    };
    let version_range = packet_range(input, offset, 1)?;
    let version = first >> 4;
    add_unsigned(
        sink,
        &mut children,
        "version",
        u64::from(version),
        version_range,
    )?;
    if version != 6 {
        finish_layer(sink, "ipv6", fixed_range, root, &children)?;
        return Ok(FixedStep::Stop(ProtocolFinding {
            priority: PRIORITY_MALFORMED,
            code: DiagnosticCode::MALFORMED_PROTOCOL,
            severity: Severity::Warning,
            evidence: version_range,
            message: MESSAGE_INVALID_VERSION,
        }));
    }

    add_fixed_fields(input, sink, offset, available, first, &mut children)?;
    finish_layer(sink, "ipv6", fixed_range, root, &children)?;
    if available < FIXED_HEADER_LENGTH {
        return Ok(FixedStep::Stop(ProtocolFinding {
            priority: PRIORITY_TRUNCATED,
            code: DiagnosticCode::TRUNCATED_PROTOCOL,
            severity: Severity::Error,
            evidence: fixed_range,
            message: MESSAGE_TRUNCATED_HEADER,
        }));
    }

    let payload_length =
        usize::from(read_u16(input.bytes(), offset + 4).ok_or(ImportError::Arithmetic)?);
    let next_header = input.bytes()[offset + 6];
    let selector_range = packet_range(input, offset + 6, 1)?;
    if payload_length == 0 && next_header == HOP_BY_HOP && available > FIXED_HEADER_LENGTH {
        add_jumbogram_marker(sink, next_header, selector_range)?;
        return Ok(FixedStep::Stop(ProtocolFinding {
            priority: PRIORITY_UNSUPPORTED,
            code: DiagnosticCode::UNSUPPORTED_ENCAPSULATION,
            severity: Severity::Info,
            evidence: selector_range,
            message: MESSAGE_UNSUPPORTED_JUMBOGRAM,
        }));
    }
    let payload_start = offset
        .checked_add(FIXED_HEADER_LENGTH)
        .ok_or(ImportError::Arithmetic)?;
    let declared_end = payload_start
        .checked_add(payload_length)
        .ok_or(ImportError::Arithmetic)?;
    let captured_end = input.bytes().len();
    let payload_length_range = packet_range(input, offset + 4, 2)?;
    let finding = (declared_end > captured_end).then_some(ProtocolFinding {
        priority: PRIORITY_TRUNCATED,
        code: DiagnosticCode::TRUNCATED_PROTOCOL,
        severity: Severity::Error,
        evidence: payload_length_range,
        message: MESSAGE_TRUNCATED_PAYLOAD,
    });

    Ok(FixedStep::Complete(FixedHeader {
        payload_start,
        declared_end,
        captured_end,
        next_header,
        selector_range,
        checksum_context: NetworkChecksumContext {
            source_address: packet_range(input, offset + 8, 16)?,
            destination_address: Some(packet_range(input, offset + 24, 16)?),
        },
        finding,
    }))
}

fn traverse_extensions(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    fixed: FixedHeader,
) -> Result<NetworkDecode, ImportError> {
    let mut finding = fixed.finding;
    let mut next_header = fixed.next_header;
    let mut selector_range = fixed.selector_range;
    let mut checksum_context = fixed.checksum_context;
    let mut cursor = fixed.payload_start;
    let mut fragment = FragmentPosition::Unfragmented;
    let mut depth = 0_usize;
    let mut traversed_bytes = 0_usize;
    let max_depth =
        usize::try_from(MAX_IPV6_EXTENSION_HEADERS).map_err(|_| ImportError::Arithmetic)?;
    let max_bytes =
        usize::try_from(MAX_IPV6_EXTENSION_BYTES).map_err(|_| ImportError::Arithmetic)?;
    loop {
        if let Some(result) = terminal_result(
            input,
            fixed,
            cursor,
            next_header,
            selector_range,
            fragment,
            checksum_context,
            finding,
        )? {
            return Ok(result);
        }
        if stop_before_extension(
            sink,
            next_header,
            selector_range,
            depth,
            max_depth,
            &mut finding,
        )? {
            return Ok(NetworkDecode::new(None, finding));
        }

        let traversing_routing_header = next_header == ROUTING;
        let step = decode_next_extension(
            input,
            sink,
            next_header,
            cursor,
            fixed.declared_end,
            fixed.captured_end,
            traversed_bytes,
            max_bytes,
            selector_range,
        )?;

        match step {
            ExtensionStep::Continue {
                next,
                next_selector,
                length,
                fragment: observed_fragment,
            } => {
                next_header = next;
                selector_range = next_selector;
                cursor = cursor.checked_add(length).ok_or(ImportError::Arithmetic)?;
                traversed_bytes = traversed_bytes
                    .checked_add(length)
                    .ok_or(ImportError::Arithmetic)?;
                depth = depth.checked_add(1).ok_or(ImportError::Arithmetic)?;
                if traversing_routing_header {
                    checksum_context.destination_address = None;
                }
                if let Some(observed_fragment) = observed_fragment {
                    fragment = observed_fragment;
                }
            }
            ExtensionStep::Stop { finding: stopped } => {
                record_finding(&mut finding, Some(stopped));
                if stopped.code == DiagnosticCode::RESOURCE_LIMIT {
                    add_limit_marker(sink, next_header, selector_range)?;
                }
                return Ok(NetworkDecode::new(None, finding));
            }
            ExtensionStep::StopFragment {
                next,
                next_selector,
                length,
                fragment,
            } => {
                let payload_start = cursor.checked_add(length).ok_or(ImportError::Arithmetic)?;
                return fragment_terminal_result(
                    input,
                    fixed,
                    payload_start,
                    next,
                    next_selector,
                    fragment,
                    checksum_context,
                    finding,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn fragment_terminal_result(
    input: PacketDecodeInput<'_>,
    fixed: FixedHeader,
    payload_start: usize,
    next_header: u8,
    selector_range: ByteRange,
    fragment: FragmentPosition,
    checksum_context: NetworkChecksumContext,
    finding: Option<ProtocolFinding>,
) -> Result<NetworkDecode, ImportError> {
    let payload = if next_header == NO_NEXT_HEADER {
        None
    } else {
        Some(terminal_payload(
            input,
            payload_start,
            fixed.declared_end,
            fixed.captured_end,
            next_header,
            selector_range,
            fragment,
            checksum_context,
        )?)
    };
    Ok(NetworkDecode::new(payload, finding))
}

#[allow(clippy::too_many_arguments)]
fn terminal_result(
    input: PacketDecodeInput<'_>,
    fixed: FixedHeader,
    cursor: usize,
    next_header: u8,
    selector_range: ByteRange,
    fragment: FragmentPosition,
    checksum_context: NetworkChecksumContext,
    finding: Option<ProtocolFinding>,
) -> Result<Option<NetworkDecode>, ImportError> {
    if next_header == NO_NEXT_HEADER {
        return Ok(Some(NetworkDecode::new(None, finding)));
    }
    if is_extension(next_header) {
        return Ok(None);
    }
    Ok(Some(NetworkDecode::new(
        Some(terminal_payload(
            input,
            cursor,
            fixed.declared_end,
            fixed.captured_end,
            next_header,
            selector_range,
            fragment,
            checksum_context,
        )?),
        finding,
    )))
}

fn stop_before_extension(
    sink: &mut PacketDecodeSink<'_>,
    next_header: u8,
    selector_range: ByteRange,
    depth: usize,
    max_depth: usize,
    finding: &mut Option<ProtocolFinding>,
) -> Result<bool, ImportError> {
    if depth >= max_depth {
        add_limit_marker(sink, next_header, selector_range)?;
        record_finding(
            finding,
            Some(ProtocolFinding {
                priority: PRIORITY_RESOURCE_LIMIT,
                code: DiagnosticCode::RESOURCE_LIMIT,
                severity: Severity::Warning,
                evidence: selector_range,
                message: MESSAGE_EXTENSION_LIMIT,
            }),
        );
        return Ok(true);
    }
    if next_header == HOP_BY_HOP && depth != 0 {
        record_finding(
            finding,
            Some(ProtocolFinding {
                priority: PRIORITY_MALFORMED,
                code: DiagnosticCode::MALFORMED_PROTOCOL,
                severity: Severity::Warning,
                evidence: selector_range,
                message: MESSAGE_MISPLACED_HOP_BY_HOP,
            }),
        );
        return Ok(true);
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
fn terminal_payload(
    input: PacketDecodeInput<'_>,
    cursor: usize,
    declared_end: usize,
    captured_end: usize,
    next_header: u8,
    selector_range: ByteRange,
    fragment: FragmentPosition,
    checksum_context: NetworkChecksumContext,
) -> Result<NetworkPayload, ImportError> {
    let retained_end = declared_end.min(captured_end);
    let retained_length = retained_end
        .checked_sub(cursor)
        .ok_or(ImportError::Arithmetic)?;
    let declared_length = declared_end
        .checked_sub(cursor)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or(ImportError::Arithmetic)?;
    Ok(NetworkPayload {
        version: NetworkVersion::Ipv6,
        next_header,
        selector_range,
        payload_range: packet_range(input, cursor, retained_length)?,
        declared_length,
        fragment,
        checksum_context,
    })
}

const fn is_extension(next_header: u8) -> bool {
    matches!(
        next_header,
        HOP_BY_HOP | ROUTING | FRAGMENT | ESP | AUTHENTICATION | DESTINATION_OPTIONS
    )
}

#[allow(clippy::too_many_arguments)]
fn decode_next_extension(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    next_header: u8,
    cursor: usize,
    declared_end: usize,
    captured_end: usize,
    traversed_bytes: usize,
    max_bytes: usize,
    selector_range: ByteRange,
) -> Result<ExtensionStep, ImportError> {
    match next_header {
        HOP_BY_HOP | ROUTING | DESTINATION_OPTIONS => decode_variable(
            input,
            sink,
            cursor,
            declared_end,
            captured_end,
            traversed_bytes,
            max_bytes,
            selector_range,
            match next_header {
                HOP_BY_HOP => VariableExtension::HopByHop,
                ROUTING => VariableExtension::Routing,
                DESTINATION_OPTIONS => VariableExtension::DestinationOptions,
                _ => unreachable!("variable extension type was matched above"),
            },
        ),
        FRAGMENT => decode_fragment(
            input,
            sink,
            cursor,
            declared_end,
            captured_end,
            traversed_bytes,
            max_bytes,
            selector_range,
        ),
        AUTHENTICATION => decode_authentication(
            input,
            sink,
            cursor,
            declared_end,
            captured_end,
            traversed_bytes,
            max_bytes,
            selector_range,
        ),
        ESP => decode_esp(
            input,
            sink,
            cursor,
            declared_end,
            captured_end,
            traversed_bytes,
            max_bytes,
            selector_range,
        ),
        _ => unreachable!("recognized extension header is exhaustively matched"),
    }
}

fn add_fixed_fields(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    offset: usize,
    available: usize,
    first: u8,
    children: &mut ChildIds,
) -> Result<(), ImportError> {
    let bytes = input.bytes();
    if available >= 2 {
        let traffic_class = ((first & 0x0f) << 4) | (bytes[offset + 1] >> 4);
        add_unsigned(
            sink,
            children,
            "traffic_class",
            u64::from(traffic_class),
            packet_range(input, offset, 2)?,
        )?;
    }
    if available >= 4 {
        let flow_label = (u32::from(bytes[offset + 1] & 0x0f) << 16)
            | (u32::from(bytes[offset + 2]) << 8)
            | u32::from(bytes[offset + 3]);
        add_unsigned(
            sink,
            children,
            "flow_label",
            u64::from(flow_label),
            packet_range(input, offset + 1, 3)?,
        )?;
    }
    if available >= 6 {
        add_u16(input, sink, children, "payload_length", offset + 4)?;
    }
    if available >= 7 {
        add_u8(input, sink, children, "next_header", offset + 6)?;
    }
    if available >= 8 {
        add_u8(input, sink, children, "hop_limit", offset + 7)?;
    }
    if available >= 24 {
        add_bytes(input, sink, children, "source_address", offset + 8, 16)?;
    }
    if available >= FIXED_HEADER_LENGTH {
        add_bytes(
            input,
            sink,
            children,
            "destination_address",
            offset + 24,
            16,
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ExtensionStep {
    Continue {
        next: u8,
        next_selector: ByteRange,
        length: usize,
        fragment: Option<FragmentPosition>,
    },
    Stop {
        finding: ProtocolFinding,
    },
    StopFragment {
        next: u8,
        next_selector: ByteRange,
        length: usize,
        fragment: FragmentPosition,
    },
}

#[allow(clippy::too_many_arguments)]
fn decode_variable(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    cursor: usize,
    declared_end: usize,
    captured_end: usize,
    traversed_bytes: usize,
    max_bytes: usize,
    selector_range: ByteRange,
    kind: VariableExtension,
) -> Result<ExtensionStep, ImportError> {
    if let Some(finding) =
        validate_prefix_extent(input, cursor, 2, declared_end, captured_end, selector_range)?
    {
        return Ok(ExtensionStep::Stop { finding });
    }

    let length_byte = input.bytes()[cursor + 1];
    let length = usize::from(length_byte)
        .checked_add(1)
        .and_then(|units| units.checked_mul(8))
        .ok_or(ImportError::Arithmetic)?;
    if let Some(finding) = validate_extension_extent(
        input,
        cursor,
        length,
        declared_end,
        captured_end,
        traversed_bytes,
        max_bytes,
        packet_range(input, cursor + 1, 1)?,
    )? {
        return Ok(ExtensionStep::Stop { finding });
    }

    let next = input.bytes()[cursor];
    let next_selector = packet_range(input, cursor, 1)?;
    let layer_range = packet_range(input, cursor, length)?;
    let root = add_named_field(sink, kind.protocol(), FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();
    add_u8(input, sink, &mut children, "next_header", cursor)?;
    add_u8(
        input,
        sink,
        &mut children,
        "header_extension_length",
        cursor + 1,
    )?;
    let data_start = if matches!(kind, VariableExtension::Routing) {
        add_u8(input, sink, &mut children, "routing_type", cursor + 2)?;
        add_u8(input, sink, &mut children, "segments_left", cursor + 3)?;
        cursor + 4
    } else {
        cursor + 2
    };
    let data_length = cursor
        .checked_add(length)
        .and_then(|end| end.checked_sub(data_start))
        .ok_or(ImportError::Arithmetic)?;
    add_bytes(input, sink, &mut children, "data", data_start, data_length)?;
    finish_layer(sink, kind.protocol(), layer_range, root, &children)?;

    Ok(ExtensionStep::Continue {
        next,
        next_selector,
        length,
        fragment: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_fragment(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    cursor: usize,
    declared_end: usize,
    captured_end: usize,
    traversed_bytes: usize,
    max_bytes: usize,
    selector_range: ByteRange,
) -> Result<ExtensionStep, ImportError> {
    if let Some(finding) = validate_extension_extent(
        input,
        cursor,
        FRAGMENT_HEADER_LENGTH,
        declared_end,
        captured_end,
        traversed_bytes,
        max_bytes,
        selector_range,
    )? {
        return Ok(ExtensionStep::Stop { finding });
    }

    let next = input.bytes()[cursor];
    let next_selector = packet_range(input, cursor, 1)?;
    let fragment_word = read_u16(input.bytes(), cursor + 2).ok_or(ImportError::Arithmetic)?;
    let fragment_offset = fragment_word >> 3;
    let more_fragments = fragment_word & 1 != 0;
    let reserved = (u16::from(input.bytes()[cursor + 1]) << 2) | ((fragment_word >> 1) & 0x3);
    let layer_range = packet_range(input, cursor, FRAGMENT_HEADER_LENGTH)?;
    let root = add_named_field(sink, "ipv6_fragment", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();
    add_u8(input, sink, &mut children, "next_header", cursor)?;
    add_unsigned(
        sink,
        &mut children,
        "reserved",
        u64::from(reserved),
        packet_range(input, cursor + 1, 3)?,
    )?;
    let fragment_range = packet_range(input, cursor + 2, 2)?;
    add_unsigned(
        sink,
        &mut children,
        "fragment_offset",
        u64::from(fragment_offset),
        fragment_range,
    )?;
    add_unsigned(
        sink,
        &mut children,
        "fragment_offset_bytes",
        u64::from(fragment_offset) * 8,
        fragment_range,
    )?;
    add_boolean(
        sink,
        &mut children,
        "more_fragments",
        more_fragments,
        fragment_range,
    )?;
    add_u32(input, sink, &mut children, "identification", cursor + 4)?;
    finish_layer(sink, "ipv6_fragment", layer_range, root, &children)?;

    let fragment = if fragment_offset == 0 {
        FragmentPosition::Initial { more_fragments }
    } else {
        FragmentPosition::NonInitial {
            offset_bytes: u32::from(fragment_offset) * 8,
            more_fragments,
        }
    };
    if fragment_offset != 0 {
        return Ok(ExtensionStep::StopFragment {
            next,
            next_selector,
            length: FRAGMENT_HEADER_LENGTH,
            fragment,
        });
    }
    Ok(ExtensionStep::Continue {
        next,
        next_selector,
        length: FRAGMENT_HEADER_LENGTH,
        fragment: Some(fragment),
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_authentication(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    cursor: usize,
    declared_end: usize,
    captured_end: usize,
    traversed_bytes: usize,
    max_bytes: usize,
    selector_range: ByteRange,
) -> Result<ExtensionStep, ImportError> {
    if let Some(finding) =
        validate_prefix_extent(input, cursor, 2, declared_end, captured_end, selector_range)?
    {
        return Ok(ExtensionStep::Stop { finding });
    }

    let payload_length = input.bytes()[cursor + 1];
    let length = usize::from(payload_length)
        .checked_add(2)
        .and_then(|words| words.checked_mul(4))
        .ok_or(ImportError::Arithmetic)?;
    let length_range = packet_range(input, cursor + 1, 1)?;
    if let Some(finding) = validate_extension_extent(
        input,
        cursor,
        length,
        declared_end,
        captured_end,
        traversed_bytes,
        max_bytes,
        length_range,
    )? {
        return Ok(ExtensionStep::Stop { finding });
    }

    let next = input.bytes()[cursor];
    let next_selector = packet_range(input, cursor, 1)?;
    let layer_range = packet_range(input, cursor, length)?;
    let root = add_named_field(sink, "ipv6_authentication", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();
    add_u8(input, sink, &mut children, "next_header", cursor)?;
    add_u8(input, sink, &mut children, "payload_length", cursor + 1)?;
    if length >= 8 {
        add_u32(
            input,
            sink,
            &mut children,
            "security_parameters_index",
            cursor + 4,
        )?;
    }
    if length >= AH_FIXED_HEADER_LENGTH {
        add_u32(input, sink, &mut children, "sequence_number", cursor + 8)?;
        if length > AH_FIXED_HEADER_LENGTH {
            add_bytes(
                input,
                sink,
                &mut children,
                "authentication_data",
                cursor + AH_FIXED_HEADER_LENGTH,
                length - AH_FIXED_HEADER_LENGTH,
            )?;
        }
    }
    finish_layer(sink, "ipv6_authentication", layer_range, root, &children)?;

    if length < AH_FIXED_HEADER_LENGTH || length % 8 != 0 {
        return Ok(ExtensionStep::Stop {
            finding: ProtocolFinding {
                priority: PRIORITY_MALFORMED,
                code: DiagnosticCode::MALFORMED_PROTOCOL,
                severity: Severity::Warning,
                evidence: length_range,
                message: MESSAGE_MALFORMED_AH,
            },
        });
    }
    Ok(ExtensionStep::Continue {
        next,
        next_selector,
        length,
        fragment: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_esp(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    cursor: usize,
    declared_end: usize,
    captured_end: usize,
    traversed_bytes: usize,
    max_bytes: usize,
    selector_range: ByteRange,
) -> Result<ExtensionStep, ImportError> {
    if let Some(finding) = validate_extension_extent(
        input,
        cursor,
        ESP_VISIBLE_HEADER_LENGTH,
        declared_end,
        captured_end,
        traversed_bytes,
        max_bytes,
        selector_range,
    )? {
        return Ok(ExtensionStep::Stop { finding });
    }
    let retained_end = declared_end.min(captured_end);
    let length = retained_end
        .checked_sub(cursor)
        .ok_or(ImportError::Arithmetic)?;
    let layer_range = packet_range(input, cursor, length)?;
    let root = add_named_field(sink, "ipv6_esp", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();
    add_u32(
        input,
        sink,
        &mut children,
        "security_parameters_index",
        cursor,
    )?;
    add_u32(input, sink, &mut children, "sequence_number", cursor + 4)?;
    if length > ESP_VISIBLE_HEADER_LENGTH {
        add_bytes(
            input,
            sink,
            &mut children,
            "data",
            cursor + ESP_VISIBLE_HEADER_LENGTH,
            length - ESP_VISIBLE_HEADER_LENGTH,
        )?;
    }
    finish_layer(sink, "ipv6_esp", layer_range, root, &children)?;
    Ok(ExtensionStep::Stop {
        finding: ProtocolFinding {
            priority: PRIORITY_UNSUPPORTED,
            code: DiagnosticCode::UNSUPPORTED_ENCAPSULATION,
            severity: Severity::Info,
            evidence: layer_range,
            message: MESSAGE_UNSUPPORTED_ESP,
        },
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_extension_extent(
    input: PacketDecodeInput<'_>,
    cursor: usize,
    length: usize,
    declared_end: usize,
    captured_end: usize,
    traversed_bytes: usize,
    max_bytes: usize,
    evidence: ByteRange,
) -> Result<Option<ProtocolFinding>, ImportError> {
    let end = cursor.checked_add(length).ok_or(ImportError::Arithmetic)?;
    if end > declared_end {
        return Ok(Some(ProtocolFinding {
            priority: PRIORITY_MALFORMED,
            code: DiagnosticCode::MALFORMED_PROTOCOL,
            severity: Severity::Warning,
            evidence,
            message: MESSAGE_MALFORMED_EXTENSION,
        }));
    }
    let total = traversed_bytes
        .checked_add(length)
        .ok_or(ImportError::Arithmetic)?;
    if total > max_bytes {
        return Ok(Some(ProtocolFinding {
            priority: PRIORITY_RESOURCE_LIMIT,
            code: DiagnosticCode::RESOURCE_LIMIT,
            severity: Severity::Warning,
            evidence,
            message: MESSAGE_EXTENSION_LIMIT,
        }));
    }
    if end > captured_end {
        let captured_length = captured_end.saturating_sub(cursor);
        let evidence = if captured_length == 0 {
            evidence
        } else {
            packet_range(input, cursor, captured_length)?
        };
        return Ok(Some(ProtocolFinding {
            priority: PRIORITY_TRUNCATED,
            code: DiagnosticCode::TRUNCATED_PROTOCOL,
            severity: Severity::Error,
            evidence,
            message: MESSAGE_TRUNCATED_EXTENSION,
        }));
    }
    Ok(None)
}

fn validate_prefix_extent(
    input: PacketDecodeInput<'_>,
    cursor: usize,
    length: usize,
    declared_end: usize,
    captured_end: usize,
    evidence: ByteRange,
) -> Result<Option<ProtocolFinding>, ImportError> {
    let end = cursor.checked_add(length).ok_or(ImportError::Arithmetic)?;
    if end > declared_end {
        return Ok(Some(ProtocolFinding {
            priority: PRIORITY_MALFORMED,
            code: DiagnosticCode::MALFORMED_PROTOCOL,
            severity: Severity::Warning,
            evidence,
            message: MESSAGE_MALFORMED_EXTENSION,
        }));
    }
    if end <= captured_end {
        return Ok(None);
    }
    let captured_length = captured_end.saturating_sub(cursor);
    let evidence = if captured_length == 0 {
        evidence
    } else {
        packet_range(input, cursor, captured_length.min(length))?
    };
    Ok(Some(ProtocolFinding {
        priority: PRIORITY_TRUNCATED,
        code: DiagnosticCode::TRUNCATED_PROTOCOL,
        severity: Severity::Error,
        evidence,
        message: MESSAGE_TRUNCATED_EXTENSION,
    }))
}

fn add_limit_marker(
    sink: &mut PacketDecodeSink<'_>,
    next_header: u8,
    selector_range: ByteRange,
) -> Result<(), ImportError> {
    let root = add_named_field(
        sink,
        "unsupported_ipv6_extension_chain",
        FieldValue::None,
        selector_range,
    )?;
    let mut children = ChildIds::new();
    add_unsigned(
        sink,
        &mut children,
        "next_header",
        u64::from(next_header),
        selector_range,
    )?;
    finish_layer(sink, "unsupported", selector_range, root, &children)
}

fn add_jumbogram_marker(
    sink: &mut PacketDecodeSink<'_>,
    next_header: u8,
    selector_range: ByteRange,
) -> Result<(), ImportError> {
    let root = add_named_field(
        sink,
        "unsupported_ipv6_jumbogram",
        FieldValue::None,
        selector_range,
    )?;
    let mut children = ChildIds::new();
    add_unsigned(
        sink,
        &mut children,
        "next_header",
        u64::from(next_header),
        selector_range,
    )?;
    finish_layer(sink, "unsupported", selector_range, root, &children)
}

fn add_u8(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    offset: usize,
) -> Result<(), ImportError> {
    let range = packet_range(input, offset, 1)?;
    let value = input
        .bytes()
        .get(offset)
        .copied()
        .ok_or(ImportError::Arithmetic)?;
    add_unsigned(sink, children, name, u64::from(value), range)
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

fn add_u32(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    offset: usize,
) -> Result<(), ImportError> {
    let range = packet_range(input, offset, 4)?;
    let bytes: [u8; 4] = input
        .bytes()
        .get(offset..offset.checked_add(4).ok_or(ImportError::Arithmetic)?)
        .ok_or(ImportError::Arithmetic)?
        .try_into()
        .map_err(|_| ImportError::Arithmetic)?;
    add_unsigned(
        sink,
        children,
        name,
        u64::from(u32::from_be_bytes(bytes)),
        range,
    )
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
            let decoded = super::decode(input, sink, 0)?;
            *self.observed.lock().expect("probe lock is not poisoned") = decoded.payload;
            Ok(())
        }
    }

    fn probe(packet: &[u8]) -> Option<NetworkPayload> {
        let observed = Arc::new(Mutex::new(None));
        let capture = legacy_capture(packet);
        let mut importer = CaptureImporter::new_with_decoder(
            capture.into_boxed_slice(),
            ImportLimits::default(),
            Box::new(PayloadProbe {
                observed: Arc::clone(&observed),
            }),
        )
        .expect("synthetic raw-IPv6 capture is valid");
        loop {
            match importer
                .step(16, 1024 * 1024)
                .expect("synthetic raw-IPv6 import succeeds")
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

    fn packet(next_header: u8, captured_payload: &[u8], payload_length: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(FIXED_HEADER_LENGTH + captured_payload.len());
        packet.extend([0x60, 0, 0, 0]);
        packet.extend(payload_length.to_be_bytes());
        packet.extend([next_header, 64]);
        packet.extend([0; 32]);
        packet.extend(captured_payload);
        packet
    }

    fn fragment(next_header: u8, offset: u16, more_fragments: bool) -> [u8; 8] {
        let word = ((offset << 3) | u16::from(more_fragments)).to_be_bytes();
        [next_header, 0, word[0], word[1], 0x12, 0x34, 0x56, 0x78]
    }

    #[test]
    fn hands_off_exact_selector_truncated_bounds_and_initial_fragment() {
        let mut captured_payload = Vec::from(fragment(17, 0, true));
        captured_payload.extend([1, 2, 3, 4]);
        let payload = probe(&packet(44, &captured_payload, 28))
            .expect("complete initial fragment header has a bounded handoff");

        assert_eq!(payload.next_header, 17);
        assert_eq!(payload.selector_range, ByteRange::new(80, 1).unwrap());
        assert_eq!(payload.payload_range, ByteRange::new(88, 4).unwrap());
        assert_eq!(payload.declared_length, 20);
        assert_eq!(payload.version, NetworkVersion::Ipv6);
        assert_eq!(
            payload.checksum_context,
            NetworkChecksumContext {
                source_address: ByteRange::new(48, 16).unwrap(),
                destination_address: Some(ByteRange::new(64, 16).unwrap()),
            }
        );
        assert_eq!(
            payload.fragment,
            FragmentPosition::Initial {
                more_fragments: true
            }
        );
    }

    #[test]
    fn preserves_non_initial_fragment_metadata_for_dispatch_policy() {
        let mut captured_payload = Vec::from(fragment(6, 2, true));
        captured_payload.extend([0; 8]);
        let payload = probe(&packet(44, &captured_payload, 16))
            .expect("non-initial fragment retains a bounded terminal payload");

        assert_eq!(payload.next_header, 6);
        assert_eq!(payload.payload_range, ByteRange::new(88, 8).unwrap());
        assert_eq!(payload.declared_length, 8);
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
    fn routing_header_makes_checksum_destination_unknown() {
        let mut captured_payload = vec![17, 0, 0, 0, 0, 0, 0, 0];
        captured_payload.extend([0; 8]);
        let payload = probe(&packet(43, &captured_payload, 16))
            .expect("a traversed Routing header reaches its terminal payload");

        assert_eq!(payload.version, NetworkVersion::Ipv6);
        assert_eq!(payload.next_header, 17);
        assert_eq!(
            payload.checksum_context.source_address,
            ByteRange::new(48, 16).unwrap()
        );
        assert_eq!(payload.checksum_context.destination_address, None);
    }

    #[test]
    fn no_next_header_and_structurally_invalid_extension_do_not_dispatch() {
        assert!(probe(&packet(59, &[1, 2, 3, 4], 4)).is_none());
        assert!(probe(&packet(60, &[17, 1, 0, 0, 0, 0, 0, 0], 8)).is_none());
    }
}
