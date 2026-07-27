//! Bounded ICMP and `ICMPv6` decoding.

use packet_core::{
    ByteRange, DiagnosticCode, FieldValue, ImportError, PacketDecodeInput, PacketDecodeSink,
    Severity,
};

use crate::{
    ChildIds, NetworkPayload, ProtocolFinding, TransportDecode, add_named_field, checksum,
    finish_layer, packet_slice, read_u16, read_u32,
};

const COMMON_HEADER_LENGTH: usize = 4;
const COMMON_BODY_HEADER_LENGTH: usize = 8;
const ICMPV6_PROTOCOL: u8 = 58;

const PRIORITY_MALFORMED: u8 = 120;
const PRIORITY_TRUNCATED: u8 = 100;
const PRIORITY_CHECKSUM: u8 = 10;

const MESSAGE_MALFORMED_ICMP: &str =
    "ICMP message is shorter than the fixed header required by its type";
const MESSAGE_MALFORMED_ICMPV6: &str =
    "ICMPv6 message is shorter than the fixed header required by its type";
const MESSAGE_TRUNCATED_ICMP: &str = "ICMP message ends before its declared bytes are available";
const MESSAGE_TRUNCATED_ICMPV6: &str =
    "ICMPv6 message ends before its declared bytes are available";
const MESSAGE_INVALID_ICMP_CHECKSUM: &str =
    "ICMP checksum does not validate; capture offload may explain the observed value";
const MESSAGE_INVALID_ICMPV6_CHECKSUM: &str =
    "ICMPv6 checksum does not validate; capture offload may explain the observed value";

#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
}

impl Family {
    const fn protocol(self) -> &'static str {
        match self {
            Self::V4 => "icmp",
            Self::V6 => "icmpv6",
        }
    }

    const fn malformed_message(self) -> &'static str {
        match self {
            Self::V4 => MESSAGE_MALFORMED_ICMP,
            Self::V6 => MESSAGE_MALFORMED_ICMPV6,
        }
    }

    const fn truncated_message(self) -> &'static str {
        match self {
            Self::V4 => MESSAGE_TRUNCATED_ICMP,
            Self::V6 => MESSAGE_TRUNCATED_ICMPV6,
        }
    }

    const fn checksum_message(self) -> &'static str {
        match self {
            Self::V4 => MESSAGE_INVALID_ICMP_CHECKSUM,
            Self::V6 => MESSAGE_INVALID_ICMPV6_CHECKSUM,
        }
    }
}

pub(crate) fn decode_v4(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
) -> Result<TransportDecode, ImportError> {
    decode(input, sink, network, Family::V4)
}

pub(crate) fn decode_v6(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
) -> Result<TransportDecode, ImportError> {
    decode(input, sink, network, Family::V6)
}

fn decode(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    network: NetworkPayload,
    family: Family,
) -> Result<TransportDecode, ImportError> {
    let message = packet_slice(input, network.payload_range)?;
    let layer_range = network.payload_range;
    let root = add_named_field(sink, family.protocol(), FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();

    if let Some(&message_type) = message.first() {
        add_unsigned(
            sink,
            &mut children,
            "type",
            u64::from(message_type),
            child_range(layer_range, 0, 1)?,
        )?;
    }
    if let Some(&code) = message.get(1) {
        add_unsigned(
            sink,
            &mut children,
            "code",
            u64::from(code),
            child_range(layer_range, 1, 1)?,
        )?;
    }
    if let Some(checksum_value) = read_u16(message, 2) {
        add_unsigned(
            sink,
            &mut children,
            "checksum",
            u64::from(checksum_value),
            child_range(layer_range, 2, 2)?,
        )?;
    }

    let required_length = message
        .first()
        .copied()
        .map_or(COMMON_HEADER_LENGTH, |message_type| {
            required_length(family, message_type)
        });
    let declared_length = network.declared_length as usize;
    let complete_datagram = network.fragment.is_complete_datagram();
    let structurally_sound = !complete_datagram || declared_length >= required_length;

    if message.len() >= COMMON_BODY_HEADER_LENGTH && declared_length >= COMMON_BODY_HEADER_LENGTH {
        decode_common_body(family, message, layer_range, sink, &mut children)?;
    }

    let mut finding = if complete_datagram && declared_length < required_length {
        Some(ProtocolFinding {
            priority: PRIORITY_MALFORMED,
            code: DiagnosticCode::MALFORMED_PROTOCOL,
            severity: Severity::Warning,
            evidence: layer_range,
            message: family.malformed_message(),
        })
    } else if message.len() < declared_length {
        Some(ProtocolFinding {
            priority: PRIORITY_TRUNCATED,
            code: DiagnosticCode::TRUNCATED_PROTOCOL,
            severity: Severity::Error,
            evidence: layer_range,
            message: family.truncated_message(),
        })
    } else {
        None
    };

    if complete_datagram
        && structurally_sound
        && message.len() == declared_length
        && message.len() >= COMMON_HEADER_LENGTH
    {
        let checksum_valid = match family {
            Family::V4 => Some(checksum::internet_checksum_valid(&[message])),
            Family::V6 => {
                checksum::transport_checksum_valid(input, network, ICMPV6_PROTOCOL, layer_range)?
            }
        };
        if let Some(checksum_valid) = checksum_valid {
            children.push(add_named_field(
                sink,
                "checksum_valid",
                FieldValue::Boolean(checksum_valid),
                layer_range,
            )?)?;
            if !checksum_valid && finding.is_none() {
                finding = Some(ProtocolFinding {
                    priority: PRIORITY_CHECKSUM,
                    code: DiagnosticCode::INVALID_PROTOCOL_CHECKSUM,
                    severity: Severity::Warning,
                    evidence: layer_range,
                    message: family.checksum_message(),
                });
            }
        }
    }

    finish_layer(sink, family.protocol(), layer_range, root, &children)?;
    Ok(TransportDecode::new(None, finding))
}

fn required_length(family: Family, message_type: u8) -> usize {
    let has_common_body = match family {
        Family::V4 => matches!(message_type, 0 | 3 | 8 | 11 | 12),
        Family::V6 => matches!(message_type, 1 | 2 | 3 | 4 | 128 | 129),
    };
    if has_common_body {
        COMMON_BODY_HEADER_LENGTH
    } else {
        COMMON_HEADER_LENGTH
    }
}

fn decode_common_body(
    family: Family,
    message: &[u8],
    layer_range: ByteRange,
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
) -> Result<(), ImportError> {
    let Some(&message_type) = message.first() else {
        return Ok(());
    };
    match (family, message_type) {
        (Family::V4, 0 | 8) | (Family::V6, 128 | 129) => {
            add_u16(sink, children, "identifier", message, layer_range, 4)?;
            add_u16(sink, children, "sequence_number", message, layer_range, 6)
        }
        (Family::V4, 3 | 11) | (Family::V6, 1 | 3) => {
            let range = child_range(layer_range, 4, 4)?;
            children.push(add_named_field(
                sink,
                "rest_of_header",
                FieldValue::Bytes(range),
                range,
            )?)
        }
        (Family::V6, 2) => add_u32(sink, children, "mtu", message, layer_range, 4),
        (Family::V4, 12) => add_unsigned(
            sink,
            children,
            "pointer",
            u64::from(message[4]),
            child_range(layer_range, 4, 1)?,
        ),
        (Family::V6, 4) => add_u32(sink, children, "pointer", message, layer_range, 4),
        _ => Ok(()),
    }
}

fn add_u16(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    message: &[u8],
    layer_range: ByteRange,
    offset: usize,
) -> Result<(), ImportError> {
    let value = read_u16(message, offset).ok_or(ImportError::Arithmetic)?;
    add_unsigned(
        sink,
        children,
        name,
        u64::from(value),
        child_range(layer_range, offset, 2)?,
    )
}

fn add_u32(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    message: &[u8],
    layer_range: ByteRange,
    offset: usize,
) -> Result<(), ImportError> {
    let value = read_u32(message, offset).ok_or(ImportError::Arithmetic)?;
    add_unsigned(
        sink,
        children,
        name,
        u64::from(value),
        child_range(layer_range, offset, 4)?,
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

fn child_range(parent: ByteRange, offset: usize, length: usize) -> Result<ByteRange, ImportError> {
    let offset = u32::try_from(offset).map_err(|_| ImportError::Arithmetic)?;
    let length = u32::try_from(length).map_err(|_| ImportError::Arithmetic)?;
    parent.child(offset, length).ok_or(ImportError::Arithmetic)
}
