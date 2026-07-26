//! Checked ranges used for byte evidence and arena slices.

/// A half-open byte range `[start, end)` within the original capture.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ByteRange {
    start: u64,
    length: u32,
}

impl ByteRange {
    /// Builds a range when `start + length` is representable.
    #[must_use]
    pub const fn new(start: u64, length: u32) -> Option<Self> {
        if start.checked_add(length as u64).is_some() {
            Some(Self { start, length })
        } else {
            None
        }
    }

    /// Returns the first included byte offset.
    #[must_use]
    pub const fn start(self) -> u64 {
        self.start
    }

    /// Returns the number of bytes in the range.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }

    /// Returns the exclusive end offset.
    #[must_use]
    pub const fn end(self) -> u64 {
        // Construction proves this addition cannot overflow.
        self.start + self.length as u64
    }

    /// Returns whether the complete range fits within `container_length`.
    #[must_use]
    pub const fn is_within(self, container_length: u64) -> bool {
        self.end() <= container_length
    }

    /// Resolves a child range relative to this range.
    #[must_use]
    pub const fn child(self, relative_start: u32, length: u32) -> Option<Self> {
        let Some(relative_end) = relative_start.checked_add(length) else {
            return None;
        };
        if relative_end > self.length {
            return None;
        }
        Self::new(self.start + relative_start as u64, length)
    }
}

/// A half-open range into an arena vector.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct IndexRange {
    /// First arena index.
    start: u32,
    /// Number of consecutive entries.
    length: u32,
}

impl IndexRange {
    /// Creates an arena range if its exclusive end fits in `u32`.
    #[must_use]
    pub const fn new(start: u32, length: u32) -> Option<Self> {
        if start.checked_add(length).is_some() {
            Some(Self { start, length })
        } else {
            None
        }
    }

    /// Returns the exclusive arena index.
    #[must_use]
    pub const fn end(self) -> u32 {
        self.start + self.length
    }

    /// Returns the first included arena index.
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    /// Returns the number of entries.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }
}
