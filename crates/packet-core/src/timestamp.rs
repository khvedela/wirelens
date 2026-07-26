//! Exact capture timestamp semantics.

use core::{cmp::Ordering, fmt};

/// Timestamp tick resolution from a capture interface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TimestampResolution {
    /// `10^-exponent` seconds per tick (PCAP and decimal PCAPNG resolution).
    Decimal(u8),
    /// `2^-exponent` seconds per tick (binary PCAPNG resolution).
    Binary(u8),
}

impl TimestampResolution {
    /// Largest exponent representable by PCAPNG's seven-bit resolution field.
    pub const MAX_EXPONENT: u8 = 127;

    /// Returns whether this resolution can appear in a PCAPNG interface.
    #[must_use]
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Decimal(exponent) | Self::Binary(exponent) => exponent <= Self::MAX_EXPONENT,
        }
    }

    /// Returns the number of fractional ticks in one second when representable.
    #[must_use]
    pub const fn ticks_per_second(self) -> Option<u64> {
        if !self.is_valid() {
            return None;
        }
        match self {
            Self::Decimal(exponent) => 10_u64.checked_pow(exponent as u32),
            Self::Binary(exponent) => 1_u64.checked_shl(exponent as u32),
        }
    }

    const fn denominator(self) -> WideUint {
        match self {
            Self::Decimal(exponent) => DECIMAL_DENOMINATORS[exponent as usize],
            Self::Binary(exponent) => BINARY_DENOMINATORS[exponent as usize],
        }
    }
}

/// An exact timestamp retaining its source resolution.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CaptureTimestamp {
    /// Whole seconds since the Unix epoch.
    seconds: i64,
    /// Fractional ticks at `resolution`.
    fraction: u64,
    /// Original timestamp resolution.
    resolution: TimestampResolution,
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
        if !resolution.is_valid() {
            return Err(TimestampError::UnsupportedResolution);
        }
        if resolution
            .ticks_per_second()
            .is_some_and(|ticks| fraction >= ticks)
        {
            return Err(TimestampError::FractionOutOfRange);
        }
        Ok(Self {
            seconds,
            fraction,
            resolution,
        })
    }

    /// Returns whole Unix seconds.
    #[must_use]
    pub const fn seconds(self) -> i64 {
        self.seconds
    }

    /// Returns fractional ticks in the original resolution.
    #[must_use]
    pub const fn fraction(self) -> u64 {
        self.fraction
    }

    /// Returns the exact source tick resolution.
    #[must_use]
    pub const fn resolution(self) -> TimestampResolution {
        self.resolution
    }

    /// Compares instants exactly without reducing their source resolution.
    #[must_use]
    pub fn cmp_instant(self, other: Self) -> Ordering {
        self.seconds.cmp(&other.seconds).then_with(|| {
            let left = other.resolution.denominator().mul_u64(self.fraction);
            let right = self.resolution.denominator().mul_u64(other.fraction);
            left.cmp(&right)
        })
    }
}

/// Fixed-width integer large enough for `u64 * 10^127`.
#[derive(Clone, Copy, Eq, PartialEq)]
struct WideUint([u64; 8]);

impl WideUint {
    const ZERO: Self = Self([0; 8]);
    const ONE: Self = Self([1, 0, 0, 0, 0, 0, 0, 0]);

    #[allow(clippy::cast_possible_truncation)] // The cast intentionally keeps the low limb.
    const fn mul_u64(self, factor: u64) -> Self {
        let mut limbs = [0_u64; 8];
        let mut carry = 0_u128;
        let mut index = 0;
        while index < limbs.len() {
            let product = self.0[index] as u128 * factor as u128 + carry;
            limbs[index] = product as u64;
            carry = product >> u64::BITS;
            index += 1;
        }
        // The largest supported value is below 2^487, so eight limbs suffice.
        Self(limbs)
    }
}

impl Ord for WideUint {
    fn cmp(&self, other: &Self) -> Ordering {
        for index in (0..self.0.len()).rev() {
            match self.0[index].cmp(&other.0[index]) {
                Ordering::Equal => {}
                ordering => return ordering,
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for WideUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

const fn denominator_table(base: u64) -> [WideUint; 128] {
    let mut values = [WideUint::ZERO; 128];
    values[0] = WideUint::ONE;
    let mut exponent = 1;
    while exponent < values.len() {
        values[exponent] = values[exponent - 1].mul_u64(base);
        exponent += 1;
    }
    values
}

const DECIMAL_DENOMINATORS: [WideUint; 128] = denominator_table(10);
const BINARY_DENOMINATORS: [WideUint; 128] = denominator_table(2);

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
