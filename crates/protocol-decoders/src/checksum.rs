//! Allocation-free Internet checksum helpers shared by transport decoders.

use packet_core::{ByteRange, ImportError, PacketDecodeInput};

use crate::{NetworkPayload, NetworkVersion, packet_slice};

/// Validates an Internet checksum across an ordered sequence of byte slices.
///
/// A trailing odd byte is carried across slice boundaries, so callers can
/// provide pseudo-header components without concatenating packet data.
pub(crate) fn internet_checksum_valid(parts: &[&[u8]]) -> bool {
    let mut sum = 0_u64;
    let mut high_byte = None;

    for part in parts {
        for &byte in *part {
            if let Some(high) = high_byte.take() {
                sum += u64::from(u16::from_be_bytes([high, byte]));
            } else {
                high_byte = Some(byte);
            }
        }
    }
    if let Some(high) = high_byte {
        sum += u64::from(u16::from_be_bytes([high, 0]));
    }
    while sum > u64::from(u16::MAX) {
        sum = (sum & u64::from(u16::MAX)) + (sum >> 16);
    }
    sum == u64::from(u16::MAX)
}

/// Validates a TCP, UDP, or `ICMPv6` checksum when its complete pseudo-header
/// domain is available and the effective destination address is unambiguous.
pub(crate) fn transport_checksum_valid(
    input: PacketDecodeInput<'_>,
    network: NetworkPayload,
    protocol: u8,
    message_range: ByteRange,
) -> Result<Option<bool>, ImportError> {
    if !network.fragment.is_complete_datagram() {
        return Ok(None);
    }
    if message_range.start() < network.payload_range.start()
        || message_range.end() > network.payload_range.end()
    {
        return Ok(None);
    }
    let Some(destination_range) = network.checksum_context.destination_address else {
        return Ok(None);
    };

    let source = packet_slice(input, network.checksum_context.source_address)?;
    let destination = packet_slice(input, destination_range)?;
    let message = packet_slice(input, message_range)?;
    match network.version {
        NetworkVersion::Ipv4 => {
            let Ok(length) = u16::try_from(message.len()) else {
                return Ok(None);
            };
            let zero_protocol = [0, protocol];
            let length = length.to_be_bytes();
            Ok(Some(internet_checksum_valid(&[
                source,
                destination,
                &zero_protocol,
                &length,
                message,
            ])))
        }
        NetworkVersion::Ipv6 => {
            let length = u32::try_from(message.len())
                .map_err(|_| ImportError::Arithmetic)?
                .to_be_bytes();
            let protocol = [0, 0, 0, protocol];
            Ok(Some(internet_checksum_valid(&[
                source,
                destination,
                &length,
                &protocol,
                message,
            ])))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::internet_checksum_valid;

    #[test]
    fn carries_an_odd_byte_across_slice_boundaries() {
        assert!(internet_checksum_valid(&[&[0x12], &[0x34, 0xed], &[0xcb]]));
        assert!(internet_checksum_valid(&[&[0x12, 0x34, 0xed], &[0xcb]]));
    }

    #[test]
    fn pads_a_final_odd_byte_as_the_high_octet() {
        assert!(internet_checksum_valid(&[&[0xff, 0xff, 0x00]]));
        assert!(!internet_checksum_valid(&[&[0xff, 0xff, 0x01]]));
    }
}
