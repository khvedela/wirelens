//! Exact capture timestamp semantics.

use core::fmt;

/// Timestamp tick resolution from a capture interface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimestampResolution {
    /// `10^-exponent` seconds per tick (PCAP and decimal PCAPNG resolution).
    Decimal(u8),
    /// `2^-exponent` seconds per tick (binary PCAPNG resolution).
    Binary(u8),
}

impl TimestampResolution {
    /// Returns the number of fractional ticks in one second when representable.
    #[must_use]
    pub const fn ticks_per_second(self) -> Option<u64> {
        match self {
            Self::Decimal(exponent) => 10_u64.checked_pow(exponent as u32),
            Self::Binary(exponent) => 1_u64.checked_shl(exponent as u32),
        }
    }
}

/// An exact timestamp retaining its source resolution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CaptureTimestamp {
    /// Whole seconds since the Unix epoch.
    pub seconds: i64,
    /// Fractional ticks at `resolution`.
    pub fraction: u64,
    /// Original timestamp resolution.
    pub resolution: TimestampResolution,
}

impl CaptureTimestamp {
    /// Creates a normalized timestamp whose fraction is less than one second.
    ///
    /// # Errors
    ///
    /// Returns [`TimestampError::UnsupportedResolution`] when the resolution
    /// cannot be represented, or [`TimestampError::FractionOutOfRange`] when
    /// the fractional value is not normalized below one second.
    pub fn new(
        seconds: i64,
        fraction: u64,
        resolution: TimestampResolution,
    ) -> Result<Self, TimestampError> {
        let ticks = resolution
            .ticks_per_second()
            .ok_or(TimestampError::UnsupportedResolution)?;
        if fraction >= ticks {
            return Err(TimestampError::FractionOutOfRange);
        }
        Ok(Self {
            seconds,
            fraction,
            resolution,
        })
    }
}

/// Validation failure for capture timestamp metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimestampError {
    /// The exponent cannot be represented in the canonical integer model.
    UnsupportedResolution,
    /// Fractional ticks are not normalized to less than one second.
    FractionOutOfRange,
}

impl fmt::Display for TimestampError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedResolution => formatter.write_str("unsupported timestamp resolution"),
            Self::FractionOutOfRange => formatter.write_str("timestamp fraction is out of range"),
        }
    }
}

impl std::error::Error for TimestampError {}
