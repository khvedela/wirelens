//! Platform-neutral, bounded protocol decoders for `WireLens`.
//!
//! Decoders borrow packet bytes from `packet-core` and write only canonical
//! arena facts with absolute evidence ranges. They do not depend on a browser,
//! WebAssembly, or UI framework. The link-layer decoder intentionally supports
//! only Ethernet II, one customer 802.1Q tag, and Ethernet/IPv4 ARP in v0.1.
//! Every other encapsulation stays visible as structured, uninterpreted data.

#![forbid(unsafe_code)]

use packet_core::{
    ByteRange, DiagnosticCode, FieldId, FieldValue, ImportError, PacketDecodeInput,
    PacketDecodeSink, PacketDecoder, Recovery, Severity,
};

const LINKTYPE_ETHERNET: u32 = 1;
const ETHERNET_HEADER_LENGTH: usize = 14;
const VLAN_HEADER_END: usize = 18;
const ARP_FIXED_HEADER_LENGTH: usize = 8;
const ARP_ETHERNET_IPV4_LENGTH: usize = 28;
const ETHERNET_TYPE_MINIMUM: u16 = 0x0600;
const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_ARP: u16 = 0x0806;
const ETHER_TYPE_VLAN: u16 = 0x8100;
const ETHER_TYPE_IPV6: u16 = 0x86dd;
const ETHER_TYPE_PROVIDER_VLAN: u16 = 0x88a8;
const ETHER_TYPE_LEGACY_VLAN: u16 = 0x9100;

const MESSAGE_TRUNCATED_ETHERNET: &str =
    "Ethernet header ends before all required fields are available";
const MESSAGE_TRUNCATED_VLAN: &str =
    "802.1Q header ends before the tag and inner type are complete";
const MESSAGE_TRUNCATED_ARP: &str =
    "ARP message ends before its declared address fields are complete";
const MESSAGE_AMBIGUOUS_TYPE_LENGTH: &str =
    "Ethernet type-or-length value is in the reserved ambiguity gap";
const MESSAGE_CONTRADICTORY_ARP_LENGTH: &str =
    "ARP address lengths contradict the declared Ethernet or IPv4 address type";

/// Conservative ceiling for unique protocol, root, field, and diagnostic text
/// strings interned by this decoder version.
///
/// Boundary admission may use this alongside the byte-oriented string limit
/// to reserve hash-map and finalization slots. The slack intentionally permits
/// compatible vocabulary additions without silently invalidating that model.
pub const LINK_LAYER_VOCABULARY_COUNT_UPPER_BOUND: u32 = 64;

/// Maximum protocol layers the current link-layer decoder can emit per packet.
///
/// This includes the structured unsupported layer that can follow Ethernet,
/// one VLAN tag, and an ARP layer.
pub const LINK_LAYER_MAX_LAYERS_PER_PACKET: u32 = 4;
/// Maximum decoded fields the current link-layer decoder can emit per packet.
pub const LINK_LAYER_MAX_FIELDS_PER_PACKET: u32 = 25;
/// Maximum field-child references the current link-layer decoder can emit per packet.
pub const LINK_LAYER_MAX_FIELD_CHILDREN_PER_PACKET: u32 = 21;

/// Stateless Ethernet, single-tag VLAN, and ARP decoder.
#[derive(Clone, Copy, Debug, Default)]
pub struct LinkLayerDecoder;

impl LinkLayerDecoder {
    /// Creates a stateless link-layer decoder.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl PacketDecoder for LinkLayerDecoder {
    fn decode(
        &mut self,
        input: PacketDecodeInput<'_>,
        sink: &mut PacketDecodeSink<'_>,
    ) -> Result<(), ImportError> {
        if input.link_type().0 != LINKTYPE_ETHERNET {
            return Ok(());
        }
        decode_ethernet(input, sink)
    }
}

fn decode_ethernet(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
) -> Result<(), ImportError> {
    let available = input.bytes().len().min(ETHERNET_HEADER_LENGTH);
    let layer_range = packet_range(input, 0, available)?;
    let root = add_named_field(sink, "ethernet", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();

    if input.bytes().len() >= 6 {
        let range = packet_range(input, 0, 6)?;
        children.push(add_named_field(
            sink,
            "destination",
            FieldValue::Bytes(range),
            range,
        )?)?;
    }
    if input.bytes().len() >= 12 {
        let range = packet_range(input, 6, 6)?;
        children.push(add_named_field(
            sink,
            "source",
            FieldValue::Bytes(range),
            range,
        )?)?;
    }
    let ether_type = if input.bytes().len() >= ETHERNET_HEADER_LENGTH {
        let range = packet_range(input, 12, 2)?;
        let value = read_u16(input.bytes(), 12).ok_or(ImportError::Arithmetic)?;
        children.push(add_named_field(
            sink,
            "ether_type",
            FieldValue::Unsigned(u64::from(value)),
            range,
        )?)?;
        Some(value)
    } else {
        None
    };
    finish_layer(sink, "ethernet", layer_range, root, &children)?;

    let Some(ether_type) = ether_type else {
        return add_diagnostic(
            sink,
            DiagnosticCode::TRUNCATED_PROTOCOL,
            Severity::Error,
            Some(layer_range),
            MESSAGE_TRUNCATED_ETHERNET,
        );
    };

    dispatch_ether_type(input, sink, ether_type, 12, ETHERNET_HEADER_LENGTH, false)
}

fn dispatch_ether_type(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    ether_type: u16,
    type_offset: usize,
    payload_offset: usize,
    inside_vlan: bool,
) -> Result<(), ImportError> {
    match ether_type {
        ETHER_TYPE_ARP => decode_arp(input, sink, payload_offset),
        ETHER_TYPE_VLAN if !inside_vlan => decode_vlan(input, sink),
        ETHER_TYPE_IPV4 | ETHER_TYPE_IPV6 => Ok(()),
        0..=1500 => add_unsupported_encapsulation(
            input,
            sink,
            type_offset,
            payload_offset,
            "ieee_802_3",
            "length",
            ether_type,
        ),
        1501..ETHERNET_TYPE_MINIMUM => {
            let evidence = packet_range(input, type_offset, 2)?;
            add_diagnostic(
                sink,
                DiagnosticCode::MALFORMED_PROTOCOL,
                Severity::Warning,
                Some(evidence),
                MESSAGE_AMBIGUOUS_TYPE_LENGTH,
            )?;
            add_unsupported_encapsulation(
                input,
                sink,
                type_offset,
                payload_offset,
                "ambiguous_type_or_length",
                "type_or_length",
                ether_type,
            )
        }
        ETHER_TYPE_PROVIDER_VLAN | ETHER_TYPE_LEGACY_VLAN => add_unsupported_encapsulation(
            input,
            sink,
            type_offset,
            payload_offset,
            "provider_vlan",
            "encapsulation",
            ether_type,
        ),
        ETHER_TYPE_VLAN => add_unsupported_encapsulation(
            input,
            sink,
            type_offset,
            payload_offset,
            "stacked_vlan",
            "encapsulation",
            ether_type,
        ),
        // The exact numeric value already remains visible in the enclosing
        // Ethernet/VLAN field. An unknown, well-formed EtherType is not damage
        // and does not merit a per-packet diagnostic or another arena tree.
        _ => Ok(()),
    }
}

fn decode_vlan(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
) -> Result<(), ImportError> {
    let available_end = input.bytes().len().min(VLAN_HEADER_END);
    let layer_length = available_end
        .checked_sub(12)
        .ok_or(ImportError::Arithmetic)?;
    let layer_range = packet_range(input, 12, layer_length)?;
    let root = add_named_field(sink, "vlan", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();

    let tpid_range = packet_range(input, 12, 2)?;
    children.push(add_named_field(
        sink,
        "tag_protocol_identifier",
        FieldValue::Unsigned(u64::from(ETHER_TYPE_VLAN)),
        tpid_range,
    )?)?;
    if input.bytes().len() >= 16 {
        let tci_range = packet_range(input, 14, 2)?;
        let tci = read_u16(input.bytes(), 14).ok_or(ImportError::Arithmetic)?;
        children.push(add_named_field(
            sink,
            "tag_control_information",
            FieldValue::Unsigned(u64::from(tci)),
            tci_range,
        )?)?;
        children.push(add_named_field(
            sink,
            "priority_code_point",
            FieldValue::Unsigned(u64::from((tci >> 13) & 0x7)),
            tci_range,
        )?)?;
        children.push(add_named_field(
            sink,
            "drop_eligible",
            FieldValue::Boolean((tci & 0x1000) != 0),
            tci_range,
        )?)?;
        children.push(add_named_field(
            sink,
            "vlan_identifier",
            FieldValue::Unsigned(u64::from(tci & 0x0fff)),
            tci_range,
        )?)?;
    }
    let inner_type = if input.bytes().len() >= VLAN_HEADER_END {
        let range = packet_range(input, 16, 2)?;
        let value = read_u16(input.bytes(), 16).ok_or(ImportError::Arithmetic)?;
        children.push(add_named_field(
            sink,
            "inner_ether_type",
            FieldValue::Unsigned(u64::from(value)),
            range,
        )?)?;
        Some(value)
    } else {
        None
    };
    finish_layer(sink, "vlan", layer_range, root, &children)?;

    let Some(inner_type) = inner_type else {
        return add_diagnostic(
            sink,
            DiagnosticCode::TRUNCATED_PROTOCOL,
            Severity::Error,
            Some(layer_range),
            MESSAGE_TRUNCATED_VLAN,
        );
    };
    dispatch_ether_type(input, sink, inner_type, 16, VLAN_HEADER_END, true)
}

fn decode_arp(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    arp_offset: usize,
) -> Result<(), ImportError> {
    let available = input.bytes().len().saturating_sub(arp_offset);
    if available < ARP_FIXED_HEADER_LENGTH {
        let range = add_arp_layer(input, sink, arp_offset, available, false, None)?;
        return add_diagnostic(
            sink,
            DiagnosticCode::TRUNCATED_PROTOCOL,
            Severity::Error,
            Some(range),
            MESSAGE_TRUNCATED_ARP,
        );
    }

    let hardware_type = read_u16(input.bytes(), arp_offset).ok_or(ImportError::Arithmetic)?;
    let protocol_type = read_u16(input.bytes(), arp_offset + 2).ok_or(ImportError::Arithmetic)?;
    let hardware_length = usize::from(input.bytes()[arp_offset + 4]);
    let protocol_length = usize::from(input.bytes()[arp_offset + 5]);
    let operation = read_u16(input.bytes(), arp_offset + 6).ok_or(ImportError::Arithmetic)?;
    let declared_length = ARP_FIXED_HEADER_LENGTH
        .checked_add(
            hardware_length
                .checked_add(protocol_length)
                .and_then(|one_side| one_side.checked_mul(2))
                .ok_or(ImportError::Arithmetic)?,
        )
        .ok_or(ImportError::Arithmetic)?;
    let supported_addressing = hardware_type == 1
        && protocol_type == ETHER_TYPE_IPV4
        && hardware_length == 6
        && protocol_length == 4;
    let contradictory = (hardware_type == 1 && hardware_length != 6)
        || (protocol_type == ETHER_TYPE_IPV4 && protocol_length != 4);

    if available < declared_length {
        let range = add_arp_layer(
            input,
            sink,
            arp_offset,
            available,
            supported_addressing,
            Some(operation),
        )?;
        if contradictory {
            // A trusted registered address type already proves the length
            // field contradictory. Do not describe bytes as merely truncated
            // based on a length that is itself invalid.
            let fixed_header = packet_range(input, arp_offset, ARP_FIXED_HEADER_LENGTH)?;
            return add_diagnostic(
                sink,
                DiagnosticCode::MALFORMED_PROTOCOL,
                Severity::Warning,
                Some(fixed_header),
                MESSAGE_CONTRADICTORY_ARP_LENGTH,
            );
        }
        return add_diagnostic(
            sink,
            DiagnosticCode::TRUNCATED_PROTOCOL,
            Severity::Error,
            Some(range),
            MESSAGE_TRUNCATED_ARP,
        );
    }

    if !supported_addressing {
        let fixed_range = add_arp_layer(
            input,
            sink,
            arp_offset,
            ARP_FIXED_HEADER_LENGTH,
            false,
            Some(operation),
        )?;
        if contradictory {
            add_diagnostic(
                sink,
                DiagnosticCode::MALFORMED_PROTOCOL,
                Severity::Warning,
                Some(fixed_range),
                MESSAGE_CONTRADICTORY_ARP_LENGTH,
            )?;
        }
        return add_unsupported_arp(
            input,
            sink,
            arp_offset,
            declared_length,
            hardware_type,
            protocol_type,
            hardware_length,
            protocol_length,
        );
    }

    add_arp_layer(
        input,
        sink,
        arp_offset,
        ARP_ETHERNET_IPV4_LENGTH,
        true,
        Some(operation),
    )?;
    if matches!(operation, 1 | 2) {
        Ok(())
    } else {
        add_unsupported_operation(input, sink, arp_offset, operation)
    }
}

fn add_arp_layer(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    offset: usize,
    length: usize,
    decode_addresses: bool,
    operation: Option<u16>,
) -> Result<ByteRange, ImportError> {
    let layer_range = packet_range(input, offset, length)?;
    let root = add_named_field(sink, "arp", FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();
    let bytes = input.bytes();
    let relative_available = bytes.len().saturating_sub(offset).min(length);

    if relative_available >= 2 {
        add_u16_child(sink, &mut children, "hardware_type", input, offset)?;
    }
    if relative_available >= 4 {
        add_u16_child(sink, &mut children, "protocol_type", input, offset + 2)?;
    }
    if relative_available >= 5 {
        let range = packet_range(input, offset + 4, 1)?;
        children.push(add_named_field(
            sink,
            "hardware_address_length",
            FieldValue::Unsigned(u64::from(bytes[offset + 4])),
            range,
        )?)?;
    }
    if relative_available >= 6 {
        let range = packet_range(input, offset + 5, 1)?;
        children.push(add_named_field(
            sink,
            "protocol_address_length",
            FieldValue::Unsigned(u64::from(bytes[offset + 5])),
            range,
        )?)?;
    }
    if relative_available >= 8 {
        let range = packet_range(input, offset + 6, 2)?;
        let value = operation
            .or_else(|| read_u16(bytes, offset + 6))
            .ok_or(ImportError::Arithmetic)?;
        children.push(add_named_field(
            sink,
            "operation",
            FieldValue::Unsigned(u64::from(value)),
            range,
        )?)?;
        if matches!(value, 1 | 2) {
            children.push(add_named_field(
                sink,
                "is_request",
                FieldValue::Boolean(value == 1),
                range,
            )?)?;
            children.push(add_named_field(
                sink,
                "is_reply",
                FieldValue::Boolean(value == 2),
                range,
            )?)?;
        }
    }
    if decode_addresses {
        add_bytes_child_if_complete(
            sink,
            &mut children,
            "sender_hardware_address",
            input,
            offset + 8,
            6,
            offset + length,
        )?;
        add_bytes_child_if_complete(
            sink,
            &mut children,
            "sender_protocol_address",
            input,
            offset + 14,
            4,
            offset + length,
        )?;
        add_bytes_child_if_complete(
            sink,
            &mut children,
            "target_hardware_address",
            input,
            offset + 18,
            6,
            offset + length,
        )?;
        add_bytes_child_if_complete(
            sink,
            &mut children,
            "target_protocol_address",
            input,
            offset + 24,
            4,
            offset + length,
        )?;
    }
    finish_layer(sink, "arp", layer_range, root, &children)?;
    Ok(layer_range)
}

#[allow(clippy::too_many_arguments)]
fn add_unsupported_encapsulation(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    type_offset: usize,
    payload_offset: usize,
    root_name: &str,
    type_name: &str,
    type_value: u16,
) -> Result<(), ImportError> {
    let length = input.bytes().len().saturating_sub(type_offset);
    let layer_range = packet_range(input, type_offset, length)?;
    let root = add_named_field(sink, root_name, FieldValue::None, layer_range)?;
    let mut children = ChildIds::new();
    let type_range = packet_range(input, type_offset, 2)?;
    children.push(add_named_field(
        sink,
        type_name,
        FieldValue::Unsigned(u64::from(type_value)),
        type_range,
    )?)?;
    let payload_length = input.bytes().len().saturating_sub(payload_offset);
    let payload_range = packet_range(input, payload_offset, payload_length)?;
    children.push(add_named_field(
        sink,
        "data",
        FieldValue::Bytes(payload_range),
        payload_range,
    )?)?;
    finish_layer(sink, "unsupported", layer_range, root, &children)
}

#[allow(clippy::too_many_arguments)]
fn add_unsupported_arp(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    arp_offset: usize,
    declared_length: usize,
    hardware_type: u16,
    protocol_type: u16,
    hardware_length: usize,
    protocol_length: usize,
) -> Result<(), ImportError> {
    let layer_range = packet_range(input, arp_offset, declared_length)?;
    let root = add_named_field(
        sink,
        "unsupported_arp_addressing",
        FieldValue::None,
        layer_range,
    )?;
    let mut children = ChildIds::new();
    for (name, value, relative_offset, length) in [
        ("hardware_type", u64::from(hardware_type), 0, 2),
        ("protocol_type", u64::from(protocol_type), 2, 2),
        (
            "hardware_address_length",
            u64::try_from(hardware_length).map_err(|_| ImportError::Arithmetic)?,
            4,
            1,
        ),
        (
            "protocol_address_length",
            u64::try_from(protocol_length).map_err(|_| ImportError::Arithmetic)?,
            5,
            1,
        ),
    ] {
        let range = packet_range(input, arp_offset + relative_offset, length)?;
        children.push(add_named_field(
            sink,
            name,
            FieldValue::Unsigned(value),
            range,
        )?)?;
    }
    let data_length = declared_length
        .checked_sub(ARP_FIXED_HEADER_LENGTH)
        .ok_or(ImportError::Arithmetic)?;
    let data_range = packet_range(input, arp_offset + ARP_FIXED_HEADER_LENGTH, data_length)?;
    children.push(add_named_field(
        sink,
        "data",
        FieldValue::Bytes(data_range),
        data_range,
    )?)?;
    finish_layer(sink, "unsupported", layer_range, root, &children)
}

fn add_unsupported_operation(
    input: PacketDecodeInput<'_>,
    sink: &mut PacketDecodeSink<'_>,
    arp_offset: usize,
    operation: u16,
) -> Result<(), ImportError> {
    let range = packet_range(input, arp_offset + 6, 2)?;
    let root = add_named_field(sink, "unsupported_arp_operation", FieldValue::None, range)?;
    let mut children = ChildIds::new();
    children.push(add_named_field(
        sink,
        "operation",
        FieldValue::Unsigned(u64::from(operation)),
        range,
    )?)?;
    finish_layer(sink, "unsupported", range, root, &children)
}

fn add_u16_child(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    input: PacketDecodeInput<'_>,
    offset: usize,
) -> Result<(), ImportError> {
    let range = packet_range(input, offset, 2)?;
    let value = read_u16(input.bytes(), offset).ok_or(ImportError::Arithmetic)?;
    children.push(add_named_field(
        sink,
        name,
        FieldValue::Unsigned(u64::from(value)),
        range,
    )?)
}

fn add_bytes_child_if_complete(
    sink: &mut PacketDecodeSink<'_>,
    children: &mut ChildIds,
    name: &str,
    input: PacketDecodeInput<'_>,
    offset: usize,
    length: usize,
    decoded_end: usize,
) -> Result<(), ImportError> {
    let Some(end) = offset.checked_add(length) else {
        return Err(ImportError::Arithmetic);
    };
    if end > decoded_end || input.bytes().get(offset..end).is_none() {
        return Ok(());
    }
    let range = packet_range(input, offset, length)?;
    children.push(add_named_field(
        sink,
        name,
        FieldValue::Bytes(range),
        range,
    )?)
}

fn add_named_field(
    sink: &mut PacketDecodeSink<'_>,
    name: &str,
    value: FieldValue,
    range: ByteRange,
) -> Result<FieldId, ImportError> {
    let name = sink.intern(name)?;
    sink.add_field(name, value, range)
}

fn finish_layer(
    sink: &mut PacketDecodeSink<'_>,
    protocol: &str,
    range: ByteRange,
    root: FieldId,
    children: &ChildIds,
) -> Result<(), ImportError> {
    sink.set_field_children(root, children.as_slice())?;
    let protocol = sink.intern(protocol)?;
    sink.add_layer(protocol, range, Some(root))
}

fn add_diagnostic(
    sink: &mut PacketDecodeSink<'_>,
    code: DiagnosticCode,
    severity: Severity,
    evidence: Option<ByteRange>,
    message: &str,
) -> Result<(), ImportError> {
    let message = sink.intern(message)?;
    sink.add_diagnostic(code, severity, Recovery::Continued, evidence, message)
}

fn packet_range(
    input: PacketDecodeInput<'_>,
    offset: usize,
    length: usize,
) -> Result<ByteRange, ImportError> {
    let offset = u32::try_from(offset).map_err(|_| ImportError::Arithmetic)?;
    let length = u32::try_from(length).map_err(|_| ImportError::Arithmetic)?;
    input
        .data_range()
        .child(offset, length)
        .ok_or(ImportError::Arithmetic)
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let source: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(source))
}

struct ChildIds {
    values: [FieldId; 12],
    length: usize,
}

impl ChildIds {
    const fn new() -> Self {
        Self {
            values: [FieldId(0); 12],
            length: 0,
        }
    }

    fn push(&mut self, value: FieldId) -> Result<(), ImportError> {
        let Some(slot) = self.values.get_mut(self.length) else {
            return Err(ImportError::Arithmetic);
        };
        *slot = value;
        self.length += 1;
        Ok(())
    }

    fn as_slice(&self) -> &[FieldId] {
        &self.values[..self.length]
    }
}
