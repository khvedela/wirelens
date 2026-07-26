//! Opaque generational handles with explicit kind tags.

use core::fmt;

use crate::{BoundaryError, BoundaryErrorCode};

const KIND_SHIFT: u32 = 56;
const GENERATION_SHIFT: u32 = 32;
const GENERATION_MASK: u64 = 0x00ff_ffff;
pub(crate) const MAX_GENERATION: u32 = 0x00ff_ffff;

/// Runtime ownership kind encoded into every handle.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HandleKind {
    /// An immutable [`packet_core::CaptureDataset`].
    Dataset,
    /// A bounded packet-page cursor owned by one dataset.
    PacketCursor,
    /// An in-progress or ready-to-publish capture import.
    Import,
}

impl HandleKind {
    const fn tag(self) -> u8 {
        match self {
            Self::Dataset => 1,
            Self::PacketCursor => 2,
            Self::Import => 3,
        }
    }

    const fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Dataset),
            2 => Some(Self::PacketCursor),
            3 => Some(Self::Import),
            _ => None,
        }
    }
}

/// Two exact 32-bit words for environments without a direct unsigned-64 ABI.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct HandleWords {
    /// Most-significant 32 bits.
    pub high: u32,
    /// Least-significant 32 bits.
    pub low: u32,
}

/// Opaque 64-bit generational handle.
///
/// Handle values are intentionally not constrained to JavaScript's exact
/// `Number` range. Bindings must use `BigInt` or [`HandleWords`].
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundaryHandle(u64);

impl BoundaryHandle {
    /// Reconstructs an untrusted raw boundary value for validation by an API.
    #[must_use]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Reconstructs a handle from exact high/low words.
    #[must_use]
    pub fn from_words(words: HandleWords) -> Self {
        Self((u64::from(words.high) << u32::BITS) | u64::from(words.low))
    }

    /// Returns the exact raw value for a `BigInt`-capable binding.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Splits the exact value into portable high/low words.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // Each cast intentionally selects one word.
    pub const fn words(self) -> HandleWords {
        HandleWords {
            high: (self.0 >> u32::BITS) as u32,
            low: self.0 as u32,
        }
    }

    /// Returns the encoded kind when the raw tag is recognized.
    #[must_use]
    pub const fn kind(self) -> Option<HandleKind> {
        HandleKind::from_tag((self.0 >> KIND_SHIFT) as u8)
    }

    pub(crate) fn encode(kind: HandleKind, generation: u32, index: u32) -> Option<Self> {
        if generation == 0 || generation > MAX_GENERATION {
            return None;
        }
        let slot_token = index.checked_add(1)?;
        Some(Self(
            (u64::from(kind.tag()) << KIND_SHIFT)
                | (u64::from(generation) << GENERATION_SHIFT)
                | u64::from(slot_token),
        ))
    }

    pub(crate) fn decode(self) -> Result<DecodedHandle, BoundaryError> {
        let raw_kind = (self.0 >> KIND_SHIFT) as u8;
        let Some(kind) = HandleKind::from_tag(raw_kind) else {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_HANDLE,
                "handle kind is invalid",
            ));
        };
        let generation = ((self.0 >> GENERATION_SHIFT) & GENERATION_MASK) as u32;
        #[allow(clippy::cast_possible_truncation)]
        let slot_token = self.0 as u32;
        if generation == 0 || slot_token == 0 {
            return Err(BoundaryError::new(
                BoundaryErrorCode::INVALID_HANDLE,
                "handle generation or slot is invalid",
            ));
        }
        Ok(DecodedHandle {
            generation,
            index: slot_token - 1,
            kind,
        })
    }
}

impl fmt::Debug for BoundaryHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BoundaryHandle(0x{:016x})", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DecodedHandle {
    pub(crate) kind: HandleKind,
    pub(crate) generation: u32,
    pub(crate) index: u32,
}

#[cfg(test)]
mod tests {
    use super::{BoundaryHandle, HandleKind, MAX_GENERATION};

    #[test]
    fn words_round_trip_values_outside_javascript_number_precision() {
        let handle = BoundaryHandle::encode(HandleKind::PacketCursor, MAX_GENERATION, 42)
            .expect("test handle is encodable");
        assert!(handle.raw() > (1_u64 << 53));
        assert_eq!(BoundaryHandle::from_words(handle.words()), handle);
        assert_eq!(BoundaryHandle::from_raw(handle.raw()), handle);
        assert_ne!(handle.words().high, 0);
    }

    #[test]
    fn malformed_handles_do_not_decode() {
        assert!(BoundaryHandle::from_raw(0).decode().is_err());
        assert!(BoundaryHandle::from_raw(3_u64 << 56).decode().is_err());
        assert!(BoundaryHandle::from_raw(1_u64 << 56).decode().is_err());
    }
}
