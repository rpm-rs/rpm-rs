mod editor;
mod header;
mod lead;
mod signatures;
mod types;

/// Return whether a tag identifies a header region record.
///
/// `HEADER_REGIONS` is the exclusive upper bound of the region-tag range.
/// Accepts raw tag numbers and typed tag enums.
pub fn is_region_tag(tag: impl Into<u32>) -> bool {
    (crate::constants::HEADER_IMAGE..crate::constants::HEADER_REGIONS).contains(&tag.into())
}

pub use editor::*;
pub use header::*;
pub use lead::*;
pub use signatures::*;
pub use types::*;

#[cfg(test)]
mod tests {
    use super::is_region_tag;
    use crate::constants::{
        HEADER_IMAGE, HEADER_IMMUTABLE, HEADER_REGIONS, HEADER_SIGNATURES, IndexSignatureTag,
        IndexTag,
    };

    /// The region-tag range covers HEADER_SIGNATURES and HEADER_IMMUTABLE.
    #[test]
    fn test_is_region_tag() {
        assert!(is_region_tag(HEADER_IMAGE));
        assert!(is_region_tag(HEADER_SIGNATURES));
        assert!(is_region_tag(HEADER_IMMUTABLE));
        assert!(!is_region_tag(HEADER_REGIONS));
        assert!(is_region_tag(IndexTag::RPMTAG_HEADERIMMUTABLE));
        assert!(is_region_tag(IndexSignatureTag::HEADER_SIGNATURES));
        assert!(!is_region_tag(IndexTag::RPMTAG_NAME));
    }
}
