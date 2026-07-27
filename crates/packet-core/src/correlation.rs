//! Bounded packet-relative decoded-field traversal and correlation.

use core::cmp::Ordering;

use crate::{CaptureDataset, FieldId, PacketId};

/// A checked half-open range relative to the first captured packet byte.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketRelativeRange {
    start: u32,
    length: u32,
}

impl PacketRelativeRange {
    /// Creates a packet-relative range when its exclusive end fits in `u32`.
    #[must_use]
    pub const fn new(start: u32, length: u32) -> Option<Self> {
        if start.checked_add(length).is_some() {
            Some(Self { start, length })
        } else {
            None
        }
    }

    /// Returns the first included packet-relative byte offset.
    #[must_use]
    pub const fn start(self) -> u32 {
        self.start
    }

    /// Returns the number of bytes in the range.
    #[must_use]
    pub const fn length(self) -> u32 {
        self.length
    }

    /// Returns the exclusive packet-relative end offset.
    #[must_use]
    pub const fn end(self) -> u32 {
        // Construction proves this addition cannot overflow.
        self.start + self.length
    }
}

/// One decoded field positioned in its packet-local layer tree.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketFieldPath {
    /// Stable dataset-local field identity.
    pub field_id: FieldId,
    /// Parent field identity, or `None` for a layer root.
    pub parent_field_id: Option<FieldId>,
    /// Zero-based layer ordinal within the packet.
    pub layer_index: u32,
    /// Zero-based depth within the layer's field tree.
    pub depth: u32,
    /// Exact half-open evidence range relative to the packet bytes.
    pub byte_range: PacketRelativeRange,
}

/// One field selected by packet-byte correlation, ordered by specificity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketFieldMatch {
    /// Stable dataset-local field identity.
    pub field_id: FieldId,
    /// Zero-based layer ordinal within the packet.
    pub layer_index: u32,
    /// Zero-based depth within the layer's field tree.
    pub depth: u32,
    /// Exact half-open evidence range relative to the packet bytes.
    pub byte_range: PacketRelativeRange,
}

/// Ordered result for one packet-relative byte selection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketFieldSelection {
    matches: Box<[PacketFieldMatch]>,
}

impl PacketFieldSelection {
    /// Returns every matching field in deterministic primary-first order.
    #[must_use]
    pub fn matches(&self) -> &[PacketFieldMatch] {
        &self.matches
    }

    /// Returns the most specific matching field, if any.
    #[must_use]
    pub fn primary(&self) -> Option<PacketFieldMatch> {
        self.matches.first().copied()
    }
}

/// Failure to traverse or correlate a packet field tree safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CorrelationError {
    /// The packet identity is outside the dataset packet arena.
    PacketNotFound,
    /// The requested packet-relative range exceeds captured bytes.
    SelectionOutOfBounds,
    /// The caller's field ceiling is too small for the packet field tree.
    FieldLimitExceeded,
    /// A supposedly validated dataset contains an invalid field reference or range.
    DatasetInvariant,
    /// A bounded query allocation could not be reserved.
    AllocationFailed,
}

impl CaptureDataset {
    /// Returns a bounded preorder description of one packet's field trees.
    ///
    /// `max_fields` is a caller-owned resource ceiling. The operation rejects
    /// the packet instead of partially representing its decoded fields.
    ///
    /// # Errors
    ///
    /// Returns [`CorrelationError`] for an unknown packet, an insufficient
    /// field ceiling, allocation failure, or a violated canonical invariant.
    pub fn packet_field_paths(
        &self,
        packet_id: PacketId,
        max_fields: u32,
    ) -> Result<Box<[PacketFieldPath]>, CorrelationError> {
        let packet = self
            .packet(packet_id)
            .ok_or(CorrelationError::PacketNotFound)?;
        let layer_start = packet.layers.start() as usize;
        let layer_end = packet.layers.end() as usize;
        let layers = self
            .layers()
            .get(layer_start..layer_end)
            .ok_or(CorrelationError::DatasetInvariant)?;
        let capacity =
            usize::try_from(max_fields).map_err(|_| CorrelationError::FieldLimitExceeded)?;
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(capacity)
            .map_err(|_| CorrelationError::AllocationFailed)?;
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(capacity)
            .map_err(|_| CorrelationError::AllocationFailed)?;

        for (layer_index, layer) in layers.iter().enumerate() {
            let Some(root) = layer.root_field else {
                continue;
            };
            if paths
                .len()
                .checked_add(stack.len())
                .and_then(|count| count.checked_add(1))
                .is_none_or(|count| count > capacity)
            {
                return Err(CorrelationError::FieldLimitExceeded);
            }
            stack.push((
                root,
                None,
                u32::try_from(layer_index).map_err(|_| CorrelationError::DatasetInvariant)?,
                0_u32,
            ));
            while let Some((field_id, parent_field_id, layer_index, depth)) = stack.pop() {
                if paths.len() >= capacity {
                    return Err(CorrelationError::FieldLimitExceeded);
                }
                let field = self
                    .fields()
                    .get(field_id.0 as usize)
                    .ok_or(CorrelationError::DatasetInvariant)?;
                let relative_start = field
                    .byte_range
                    .start()
                    .checked_sub(packet.data.start())
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(CorrelationError::DatasetInvariant)?;
                let byte_range =
                    PacketRelativeRange::new(relative_start, field.byte_range.length())
                        .filter(|range| range.end() <= packet.captured_length)
                        .ok_or(CorrelationError::DatasetInvariant)?;
                paths.push(PacketFieldPath {
                    field_id,
                    parent_field_id,
                    layer_index,
                    depth,
                    byte_range,
                });

                let child_start = field.children.start() as usize;
                let child_end = field.children.end() as usize;
                let children = self
                    .field_children()
                    .get(child_start..child_end)
                    .ok_or(CorrelationError::DatasetInvariant)?;
                if paths
                    .len()
                    .checked_add(stack.len())
                    .and_then(|count| count.checked_add(children.len()))
                    .is_none_or(|count| count > capacity)
                {
                    return Err(CorrelationError::FieldLimitExceeded);
                }
                let child_depth = depth
                    .checked_add(1)
                    .ok_or(CorrelationError::DatasetInvariant)?;
                for child in children.iter().rev().copied() {
                    stack.push((child, Some(field_id), layer_index, child_depth));
                }
            }
        }
        Ok(paths.into_boxed_slice())
    }

    /// Resolves a packet-relative selection to every overlapping decoded field.
    ///
    /// Non-empty selections match positive-length fields by strict half-open
    /// overlap. A zero-length selection matches only zero-length fields at the
    /// same insertion boundary. Results are ordered by exactness, containment,
    /// overlap, depth, range length, and stable field identity.
    ///
    /// # Errors
    ///
    /// Returns [`CorrelationError`] for an unknown packet, an out-of-bounds
    /// selection, an insufficient field ceiling, allocation failure, or a
    /// violated canonical invariant.
    pub fn correlate_packet_fields(
        &self,
        packet_id: PacketId,
        selection: PacketRelativeRange,
        max_fields: u32,
    ) -> Result<PacketFieldSelection, CorrelationError> {
        let packet = self
            .packet(packet_id)
            .ok_or(CorrelationError::PacketNotFound)?;
        if selection.end() > packet.captured_length {
            return Err(CorrelationError::SelectionOutOfBounds);
        }
        let paths = self.packet_field_paths(packet_id, max_fields)?;
        let mut matches = Vec::new();
        matches
            .try_reserve_exact(paths.len())
            .map_err(|_| CorrelationError::AllocationFailed)?;
        for path in paths.iter().copied() {
            if ranges_match(path.byte_range, selection) {
                matches.push(PacketFieldMatch {
                    field_id: path.field_id,
                    layer_index: path.layer_index,
                    depth: path.depth,
                    byte_range: path.byte_range,
                });
            }
        }
        matches.sort_by(|left, right| compare_matches(*left, *right, selection));
        Ok(PacketFieldSelection {
            matches: matches.into_boxed_slice(),
        })
    }
}

fn ranges_match(field: PacketRelativeRange, selection: PacketRelativeRange) -> bool {
    if selection.length() == 0 {
        return field.length() == 0 && field.start() == selection.start();
    }
    field.length() > 0 && field.start() < selection.end() && field.end() > selection.start()
}

fn compare_matches(
    left: PacketFieldMatch,
    right: PacketFieldMatch,
    selection: PacketRelativeRange,
) -> Ordering {
    let left_exact = left.byte_range == selection;
    let right_exact = right.byte_range == selection;
    right_exact
        .cmp(&left_exact)
        .then_with(|| {
            let left_contains = contains(left.byte_range, selection);
            let right_contains = contains(right.byte_range, selection);
            right_contains.cmp(&left_contains).then_with(|| {
                if left_contains && right_contains {
                    left.byte_range.length().cmp(&right.byte_range.length())
                } else {
                    Ordering::Equal
                }
            })
        })
        .then_with(|| {
            overlap_length(right.byte_range, selection)
                .cmp(&overlap_length(left.byte_range, selection))
        })
        .then_with(|| right.depth.cmp(&left.depth))
        .then_with(|| left.byte_range.length().cmp(&right.byte_range.length()))
        .then_with(|| left.field_id.0.cmp(&right.field_id.0))
}

fn contains(container: PacketRelativeRange, child: PacketRelativeRange) -> bool {
    child.start() >= container.start() && child.end() <= container.end()
}

fn overlap_length(left: PacketRelativeRange, right: PacketRelativeRange) -> u32 {
    left.end()
        .min(right.end())
        .saturating_sub(left.start().max(right.start()))
}

#[cfg(test)]
mod tests {
    use super::{PacketFieldMatch, PacketRelativeRange, compare_matches, ranges_match};
    use crate::FieldId;

    fn relative(start: u32, length: u32) -> PacketRelativeRange {
        PacketRelativeRange::new(start, length).expect("test packet range is valid")
    }

    fn field(id: u32, depth: u32, start: u32, length: u32) -> PacketFieldMatch {
        PacketFieldMatch {
            field_id: FieldId(id),
            layer_index: 0,
            depth,
            byte_range: relative(start, length),
        }
    }

    #[test]
    fn half_open_and_zero_length_matching_are_distinct() {
        assert!(ranges_match(relative(2, 2), relative(3, 1)));
        assert!(!ranges_match(relative(2, 1), relative(3, 1)));
        assert!(!ranges_match(relative(3, 0), relative(3, 1)));
        assert!(ranges_match(relative(3, 0), relative(3, 0)));
        assert!(!ranges_match(relative(2, 0), relative(3, 0)));
    }

    #[test]
    fn exact_and_specific_matches_sort_before_broader_parents() {
        let selection = relative(4, 2);
        let mut matches = [field(0, 0, 0, 12), field(2, 2, 4, 2), field(1, 1, 3, 4)];
        matches.sort_by(|left, right| compare_matches(*left, *right, selection));
        assert_eq!(
            matches.map(|item| item.field_id),
            [FieldId(2), FieldId(1), FieldId(0)]
        );
    }
}
