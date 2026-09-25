//! Editing raw RPM header entries before rebuilding a header.

use std::collections::BTreeMap;

use super::{Header, HeaderEntry, IndexData};
use crate::Error;
use crate::constants::Tag;

/// A tag-keyed editor for an RPM header, including tags unknown to rpm-rs.
///
/// Region entries are regenerated when the editor is built. Positional file
/// arrays must be updated by the caller if the package file order changes.
pub struct HeaderEditor<T: Tag> {
    region_tag: T,
    entries: BTreeMap<u32, HeaderEntry>,
}

impl<T: Tag> HeaderEditor<T> {
    /// Start an empty header with the given immutable-region tag.
    pub fn new(region_tag: T) -> Self {
        Self {
            region_tag,
            entries: BTreeMap::new(),
        }
    }

    /// Copy entries from a parsed header, excluding generated region records.
    pub fn from_header(header: &Header<T>, region_tag: T) -> Result<Self, Error> {
        let mut editor = Self::new(region_tag);
        for (tag, data) in header.get_all_entries()? {
            if tag != region_tag.to_u32() && tag != crate::constants::HEADER_REGIONS {
                editor.upsert(tag, data);
            }
        }
        Ok(editor)
    }

    /// Insert or replace one tag value; the region tag is always regenerated.
    pub fn upsert(&mut self, tag: u32, data: IndexData) -> &mut Self {
        if tag != self.region_tag.to_u32() {
            self.entries.insert(tag, HeaderEntry::new(tag, data));
        }
        self
    }

    /// Insert or replace entries from an iterator.
    pub fn extend(&mut self, entries: impl IntoIterator<Item = HeaderEntry>) -> &mut Self {
        for entry in entries {
            self.upsert(entry.tag, entry.data);
        }
        self
    }

    /// Remove a tag, returning whether it was present.
    pub fn remove(&mut self, tag: u32) -> bool {
        self.entries.remove(&tag).is_some()
    }

    /// Construct the header and regenerate its immutable-region record.
    pub fn build(self) -> Header<T> {
        Header::from_entries(self.entries.into_values(), self.region_tag)
    }
}
