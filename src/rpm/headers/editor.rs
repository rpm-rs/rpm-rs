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
            editor.upsert(tag, data);
        }
        Ok(editor)
    }

    /// Insert or replace one tag value; generated region tags are ignored.
    pub fn upsert(&mut self, tag: u32, data: IndexData) -> &mut Self {
        if !super::is_region_tag(tag) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IndexTag;
    use std::io::Cursor;

    /// All raw index value types survive serialization with one regenerated region entry.
    #[test]
    fn raw_entries_round_trip_every_value_type_and_regenerate_region() -> Result<(), Error> {
        let entries = vec![
            HeaderEntry::new(20000, IndexData::Null),
            HeaderEntry::new(20001, IndexData::Char(vec![1, 2])),
            HeaderEntry::new(20002, IndexData::Int8(vec![3, 4])),
            HeaderEntry::new(20003, IndexData::Int16(vec![5, 6])),
            HeaderEntry::new(20004, IndexData::Int32(vec![7, 8])),
            HeaderEntry::new(20005, IndexData::Int64(vec![9, 10])),
            HeaderEntry::new(20006, IndexData::StringTag("text".into())),
            HeaderEntry::new(20007, IndexData::Bin(vec![0, 255])),
            HeaderEntry::new(20008, IndexData::StringArray(vec!["a".into(), "b".into()])),
            HeaderEntry::new(20009, IndexData::I18NString(vec!["translated".into()])),
        ];
        let mut editor = HeaderEditor::new(IndexTag::RPMTAG_HEADERIMMUTABLE);
        editor.extend(entries.clone());
        for tag in [
            crate::constants::HEADER_IMMUTABLE,
            crate::constants::HEADER_SIGNATURES,
        ] {
            editor.upsert(tag, IndexData::Bin(vec![0]));
        }
        let header = editor.build();
        let mut bytes = Vec::new();
        header.write(&mut bytes)?;
        let parsed = Header::<IndexTag>::parse(&mut Cursor::new(bytes))?;
        let actual = parsed.get_all_entries()?;
        assert_eq!(
            actual
                .iter()
                .filter(|(tag, _)| *tag == crate::constants::HEADER_IMMUTABLE)
                .count(),
            1
        );
        assert_eq!(
            actual
                .into_iter()
                .filter(|(tag, _)| *tag != crate::constants::HEADER_IMMUTABLE)
                .collect::<Vec<_>>(),
            entries
                .into_iter()
                .map(|entry| (entry.tag, entry.data))
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    /// Editing known tags leaves unknown tags in a parsed header untouched.
    #[test]
    fn editing_a_parsed_header_preserves_unknown_tags() -> Result<(), Error> {
        let original = Header::from_entries(
            [HeaderEntry::new(65000, IndexData::Bin(vec![3, 2, 1]))],
            IndexTag::RPMTAG_HEADERIMMUTABLE,
        );
        let mut editor = HeaderEditor::from_header(&original, IndexTag::RPMTAG_HEADERIMMUTABLE)?;
        editor.upsert(
            IndexTag::RPMTAG_NAME as u32,
            IndexData::StringTag("new".into()),
        );
        let header = editor.build();
        assert_eq!(header.entry(65000u32)?, IndexData::Bin(vec![3, 2, 1]));
        assert_eq!(
            header.entry(IndexTag::RPMTAG_NAME)?,
            IndexData::StringTag("new".into())
        );
        Ok(())
    }
}
