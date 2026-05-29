use nom::{
    bytes::complete,
    number::complete::{be_i32, be_u8, be_u16, be_u32, be_u64},
};
use std::{
    fmt::{self, Display},
    io,
    marker::PhantomData,
    path::{Path, PathBuf},
};

use super::*;
use crate::{Timestamp, constants::*, errors::*};

#[derive(Clone, Debug, PartialEq)]
pub struct Header<T: Tag> {
    pub(crate) index_header: IndexHeader,
    pub(crate) index_entries: Vec<IndexEntry<T>>,
    pub(crate) store: Vec<u8>,
}

impl<T> Header<T>
where
    T: Tag,
{
    pub(crate) fn parse(input: &mut impl io::BufRead) -> Result<Header<T>, Error> {
        let mut buf: [u8; INDEX_HEADER_SIZE as usize] = [0; INDEX_HEADER_SIZE as usize];
        input.read_exact(&mut buf)?;
        let index_header = IndexHeader::parse(&buf)?;
        // read rest of header (index + data portions)
        let size_rest =
            (index_header.data_section_size + index_header.num_entries * INDEX_ENTRY_SIZE) as usize;
        let mut buf = vec![0; size_rest];
        input.read_exact(&mut buf)?;
        Self::parse_header(index_header, &buf[..])
    }

    /// Given a pre-parsed index header, parse the rest of the header
    fn parse_header(index_header: IndexHeader, mut bytes: &[u8]) -> Result<Header<T>, Error> {
        // parse all entries
        let mut entries: Vec<IndexEntry<T>> = Vec::new();
        let mut buf_len = bytes.len();
        for _ in 0..index_header.num_entries {
            let (rest, entry) = IndexEntry::parse(bytes)?;
            entries.push(entry);
            bytes = rest;
            debug_assert_eq!(INDEX_ENTRY_SIZE as usize, buf_len - bytes.len());
            buf_len = bytes.len();
        }

        debug_assert_eq!(bytes.len(), index_header.data_section_size as usize);

        let store = Vec::from(bytes);

        // Check if RPMTAG_ENCODING is present and set to "utf-8". If so, the
        // header is guaranteed to contain only UTF-8 strings, and invalid UTF-8
        // should be treated as an error rather than silently lossy-converted.
        let encoding_is_utf8 = entries.iter().any(|e| {
            e.tag == IndexTag::RPMTAG_ENCODING.to_u32()
                && matches!(&e.data, IndexData::StringTag(_))
                && bytes[e.offset as usize..].starts_with(b"utf-8\0")
        });

        // add data to entries
        for entry in &mut entries {
            let remaining = &bytes[entry.offset as usize..];

            match &mut entry.data {
                IndexData::Null => {}
                IndexData::Char(chars) => {
                    parse_binary_entry(remaining, entry.num_items, chars, "Char")?;
                }
                IndexData::Int8(ints) => {
                    parse_binary_entry(remaining, entry.num_items, ints, "Int8")?;
                }
                IndexData::Int16(ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u16)?;
                }
                IndexData::Int32(ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u32)?;
                }
                IndexData::Int64(ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u64)?;
                }
                // String data lives in `store` and is read on access via offset/num_items.
                //
                // When encoding_is_utf8 is true (modern packages with RPMTAG_ENCODING),
                // we skip validation here entirely — getters validate lazily and return
                // Error::InvalidUtf8 on failure. This avoids scanning strings that are
                // never accessed.
                //
                // When encoding_is_utf8 is false (old packages without RPMTAG_ENCODING),
                // we validate eagerly and store a lossy-converted fallback in the
                // IndexData variant for any invalid strings. Getters detect this via
                // `is_empty()`: an empty String/Vec means "valid UTF-8, read from
                // store", while a populated one holds the lossy fallback. This is
                // unambiguous because an empty byte sequence is always valid UTF-8, so
                // the fallback path is never triggered for genuinely empty strings.
                IndexData::StringTag(s) => {
                    if !encoding_is_utf8 {
                        let nul =
                            memchr::memchr(0, remaining).ok_or(Error::UnterminatedHeaderString)?;
                        if std::str::from_utf8(&remaining[..nul]).is_err() {
                            *s = String::from_utf8_lossy(&remaining[..nul]).into_owned();
                        }
                    }
                }
                IndexData::StringArray(strings) | IndexData::I18NString(strings) => {
                    if !encoding_is_utf8 {
                        let mut pos = remaining;
                        let mut has_invalid = false;
                        for _ in 0..entry.num_items {
                            let nul =
                                memchr::memchr(0, pos).ok_or(Error::UnterminatedHeaderString)?;
                            if std::str::from_utf8(&pos[..nul]).is_err() {
                                has_invalid = true;
                            }
                            pos = &pos[nul + 1..];
                        }
                        if has_invalid {
                            let mut pos = remaining;
                            for _ in 0..entry.num_items {
                                let nul = memchr::memchr(0, pos)
                                    .ok_or(Error::UnterminatedHeaderString)?;
                                strings.push(String::from_utf8_lossy(&pos[..nul]).into_owned());
                                pos = &pos[nul + 1..];
                            }
                        }
                    }
                }
                // Bin data lives in `store` and is read on access via offset/num_items,
                // same as string data. See get_entry_data_as_binary.
                IndexData::Bin(_) => {}
            }
        }

        Ok(Header {
            index_header,
            index_entries: entries,
            store,
        })
    }

    pub(crate) fn write(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        self.index_header.write(out)?;
        for entry in &self.index_entries {
            entry.write_index(out)?;
        }
        out.write_all(&self.store)?;
        Ok(())
    }

    /// Returns all entries in this header with fully resolved data.
    ///
    /// This method returns a vector of (tag, IndexData) pairs where all lazy-loaded
    /// data (strings, binaries) has been resolved from the store. Entries are
    /// guaranteed to be sorted by tag number.
    ///
    /// This is primarily useful for debugging and testing purposes.
    pub fn get_all_entries(&self) -> Result<Vec<(u32, IndexData)>, Error> {
        self.index_entries
            .iter()
            .map(|entry| {
                let data = self.resolve_entry_data(entry)?;
                Ok((entry.tag, data))
            })
            .collect()
    }

    /// Check whether the header contains an entry for the given tag.
    ///
    /// Accepts either a typed tag (e.g. `IndexTag::RPMTAG_NAME`) or a raw `u32`.
    pub fn entry_is_present(&self, tag: impl Into<u32>) -> bool {
        let tag = tag.into();
        self.index_entries.iter().any(|entry| entry.tag == tag)
    }

    /// Look up a tag in the header and resolve its data.
    ///
    /// Accepts either a typed tag (e.g. `IndexTag::RPMTAG_NAME`) or a raw `u32`.
    /// Returns `Error::TagNotFound` if the tag is not present.
    pub fn entry(&self, tag: impl Into<u32>) -> Result<IndexData, Error> {
        let tag = tag.into();
        self.resolve_entry_data(self.find_entry_or_err(tag)?)
    }

    /// Find the raw index entry for a tag, or return `Error::TagNotFound`.
    pub(crate) fn find_entry_or_err(&self, tag: impl Into<u32>) -> Result<&IndexEntry<T>, Error> {
        let tag = tag.into();
        self.index_entries
            .iter()
            .find(|entry| entry.tag == tag)
            .ok_or(Error::TagNotFound(tag))
    }

    /// Resolve an entry's data from the store, returning a filled owned `IndexData`.
    ///
    /// For eagerly-parsed types (Char, Int8, Int16, Int32, Int64), this clones
    /// the existing data. For lazily-resolved types (StringTag, StringArray,
    /// I18NString, Bin), this reads from the store and allocates owned data.
    ///
    /// You probably don't want to use this, unless it's for e.g. debugging purposes.
    fn resolve_entry_data(&self, entry: &IndexEntry<T>) -> Result<IndexData, Error> {
        match &entry.data {
            IndexData::Null => Ok(IndexData::Null),
            IndexData::Char(d) => Ok(IndexData::Char(d.clone())),
            IndexData::Int8(d) => Ok(IndexData::Int8(d.clone())),
            IndexData::Int16(d) => Ok(IndexData::Int16(d.clone())),
            IndexData::Int32(d) => Ok(IndexData::Int32(d.clone())),
            IndexData::Int64(d) => Ok(IndexData::Int64(d.clone())),
            IndexData::StringTag(_) => {
                let s = self.entry_as_string(entry)?;
                Ok(IndexData::StringTag(s.to_owned()))
            }
            IndexData::Bin(_) => {
                let b = self.entry_as_binary(entry)?;
                Ok(IndexData::Bin(b.to_vec()))
            }
            IndexData::StringArray(_) => {
                let v = self.entry_as_string_array(entry)?;
                Ok(IndexData::StringArray(
                    v.into_iter().map(|s| s.to_owned()).collect(),
                ))
            }
            IndexData::I18NString(_) => {
                let v = self.entry_as_string_array(entry)?;
                Ok(IndexData::I18NString(
                    v.into_iter().map(|s| s.to_owned()).collect(),
                ))
            }
        }
    }

    /// Resolve a `Bin` entry's data, reading from the store for parsed entries
    /// or returning inline data for builder-created entries.
    fn entry_as_binary<'a>(&'a self, entry: &'a IndexEntry<T>) -> Result<&'a [u8], Error> {
        match &entry.data {
            // Non-empty: builder-created entry with inline data.
            // Empty: parsed entry, read directly from store.
            IndexData::Bin(d) if !d.is_empty() => Ok(d.as_slice()),
            IndexData::Bin(_) => {
                let start = entry.offset as usize;
                Ok(&self.store[start..start + entry.num_items as usize])
            }
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "binary",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    /// Resolve a `StringTag` entry's data, returning the lossy fallback if one
    /// was stored during parse, or reading directly from the store otherwise.
    fn entry_as_string<'a>(&'a self, entry: &'a IndexEntry<T>) -> Result<&'a str, Error> {
        match &entry.data {
            // Non-empty: lossy fallback populated during parse (see parse comment above).
            // Empty: valid UTF-8 (or not yet validated), read directly from store.
            IndexData::StringTag(s) if !s.is_empty() => Ok(s.as_str()),
            IndexData::StringTag(_) => {
                let remaining = &self.store[entry.offset as usize..];
                let nul = memchr::memchr(0, remaining).ok_or(Error::UnterminatedHeaderString)?;
                std::str::from_utf8(&remaining[..nul]).map_err(|_| Error::InvalidUtf8 {
                    tag: entry.tag.to_string(),
                })
            }
            // Some tags that are typically String types are written as StringArray type for backwards compatibility reasons.
            // e.g. PAYLOADSHA256
            IndexData::StringArray(a) if a.len() == 1 => Ok(&a[0]),
            IndexData::StringArray(_) if entry.num_items == 1 => {
                let remaining = &self.store[entry.offset as usize..];
                let nul = memchr::memchr(0, remaining).ok_or(Error::UnterminatedHeaderString)?;
                std::str::from_utf8(&remaining[..nul]).map_err(|_| Error::InvalidUtf8 {
                    tag: entry.tag.to_string(),
                })
            }
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "string",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    /// Resolve an `I18NString` entry, returning the first string from the table.
    /// Returns the lossy fallback if stored during parse, or reads from the store.
    fn entry_as_i18n_string<'a>(&'a self, entry: &'a IndexEntry<T>) -> Result<&'a str, Error> {
        match &entry.data {
            // Non-empty: lossy fallback populated during parse (see parse comment above).
            // Empty: valid UTF-8 (or not yet validated), read directly from store.
            IndexData::I18NString(strings) if !strings.is_empty() => Ok(strings[0].as_str()),
            IndexData::I18NString(_) => {
                // @todo: an actual implementation that doesn't just get the first string from the table
                let remaining = &self.store[entry.offset as usize..];
                let nul = memchr::memchr(0, remaining).ok_or(Error::UnterminatedHeaderString)?;
                std::str::from_utf8(&remaining[..nul]).map_err(|_| Error::InvalidUtf8 {
                    tag: entry.tag.to_string(),
                })
            }
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "i18n string array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    /// Resolve a `StringArray` or `I18NString` entry as a list of strings.
    /// Returns lossy fallbacks if stored during parse, or reads from the store.
    fn entry_as_string_array<'a>(
        &'a self,
        entry: &'a IndexEntry<T>,
    ) -> Result<Vec<&'a str>, Error> {
        match &entry.data {
            // Non-empty: lossy fallback populated during parse (see parse comment above).
            // Empty: valid UTF-8 (or not yet validated), read directly from store.
            IndexData::StringArray(strings) | IndexData::I18NString(strings)
                if !strings.is_empty() =>
            {
                Ok(strings.iter().map(|s| s.as_str()).collect())
            }
            IndexData::StringArray(_) | IndexData::I18NString(_) => {
                let mut remaining = &self.store[entry.offset as usize..];
                let mut result = Vec::with_capacity(entry.num_items as usize);
                for _ in 0..entry.num_items {
                    let nul =
                        memchr::memchr(0, remaining).ok_or(Error::UnterminatedHeaderString)?;
                    let s =
                        std::str::from_utf8(&remaining[..nul]).map_err(|_| Error::InvalidUtf8 {
                            tag: entry.tag.to_string(),
                        })?;
                    result.push(s);
                    remaining = &remaining[nul + 1..];
                }
                Ok(result)
            }
            // Some tags that are typically StringArray types are written as String type when only
            // a single value exists. e.g. scriptlet "prog" tags with a single interpreter argument
            IndexData::StringTag(s) if !s.is_empty() => Ok(vec![s.as_str()]),
            IndexData::StringTag(_) => {
                let remaining = &self.store[entry.offset as usize..];
                let nul = memchr::memchr(0, remaining).ok_or(Error::UnterminatedHeaderString)?;
                let s = std::str::from_utf8(&remaining[..nul]).map_err(|_| Error::InvalidUtf8 {
                    tag: entry.tag.to_string(),
                })?;
                Ok(vec![s])
            }
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "string array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    pub fn get_entry_data_as_binary(&self, tag: T) -> Result<&[u8], Error> {
        self.entry_as_binary(self.find_entry_or_err(tag)?)
    }

    pub fn get_entry_data_as_string(&self, tag: T) -> Result<&str, Error> {
        self.entry_as_string(self.find_entry_or_err(tag)?)
    }

    pub fn get_entry_data_as_string_array(&self, tag: T) -> Result<Vec<&str>, Error> {
        self.entry_as_string_array(self.find_entry_or_err(tag)?)
    }

    pub fn get_entry_data_as_i18n_string(&self, tag: T) -> Result<&str, Error> {
        self.entry_as_i18n_string(self.find_entry_or_err(tag)?)
    }

    pub fn get_entry_data_as_u16_array(&self, tag: T) -> Result<Vec<u16>, Error> {
        let entry = self.find_entry_or_err(tag)?;
        match &entry.data {
            IndexData::Int16(s) => Ok(s.to_vec()),
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "uint16 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    pub fn get_entry_data_as_u32(&self, tag: T) -> Result<u32, Error> {
        let entry = self.find_entry_or_err(tag)?;
        match &entry.data {
            IndexData::Int32(s) => s
                .first()
                .copied()
                .ok_or_else(|| Error::UnexpectedTagDataType {
                    expected_data_type: "uint32",
                    actual_data_type: entry.data.to_string(),
                    tag: entry.tag.to_string(),
                }),
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "uint32",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    pub fn get_entry_data_as_u32_array(&self, tag: T) -> Result<Vec<u32>, Error> {
        let entry = self.find_entry_or_err(tag)?;
        match &entry.data {
            IndexData::Int32(s) => Ok(s.to_vec()),
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "uint32 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    pub fn get_entry_data_as_u64(&self, tag: T) -> Result<u64, Error> {
        let entry = self.find_entry_or_err(tag)?;
        match &entry.data {
            IndexData::Int64(s) => s
                .first()
                .copied()
                .ok_or_else(|| Error::UnexpectedTagDataType {
                    expected_data_type: "uint64",
                    actual_data_type: entry.data.to_string(),
                    tag: entry.tag.to_string(),
                }),
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "uint64",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    pub fn get_entry_data_as_u64_array(&self, tag: T) -> Result<Vec<u64>, Error> {
        let entry = self.find_entry_or_err(tag)?;
        match &entry.data {
            IndexData::Int64(s) => Ok(s.to_vec()),
            _ => Err(Error::UnexpectedTagDataType {
                expected_data_type: "uint64 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            }),
        }
    }

    pub(crate) fn create_region_tag(tag: T, records_count: i32, offset: i32) -> IndexEntry<T> {
        let mut header_immutable_index_data = vec![];
        let hie: IndexEntry<T> = IndexEntry {
            tag: tag.to_u32(),
            data: IndexData::Bin(Vec::new()),
            offset: (records_count + 1) * -(INDEX_ENTRY_SIZE as i32),
            // num_items for Bin is the byte count; the region tag's data is one
            // serialized index entry, which is INDEX_ENTRY_SIZE (16) bytes.
            num_items: INDEX_ENTRY_SIZE,
            entry_type: PhantomData,
        };
        hie.write_index(&mut header_immutable_index_data)
            .expect("unable to write to memory buffer");
        let data = IndexData::Bin(header_immutable_index_data);
        let num_items = data.num_items();
        IndexEntry {
            tag: tag.to_u32(),
            data,
            offset, // offset matters in this case
            num_items,
            entry_type: PhantomData,
        }
    }

    pub(crate) fn from_entries(mut actual_records: Vec<IndexEntry<T>>, region_tag: T) -> Self {
        // Ensure the tags in the header we're creating will be in sorted order
        actual_records.sort_by_key(|e| e.tag);

        let mut store = Vec::new();
        for record in &mut actual_records {
            record.offset = store.len() as i32;
            let alignment = record.data.append(&mut store);
            record.offset += alignment as i32;
        }

        let region_tag =
            Self::create_region_tag(region_tag, actual_records.len() as i32, store.len() as i32);
        region_tag.data.append(&mut store);

        let mut all_records = vec![region_tag];

        all_records.append(&mut actual_records);
        let store_size = store.len();

        let index_header = IndexHeader::new(all_records.len() as u32, store_size as u32);
        Header {
            index_entries: all_records,
            index_header,
            store,
        }
    }

    /// Size (in bytes) of this header in on-disk representation, not including padding
    pub(crate) fn size(&self) -> u32 {
        let index_size = self.index_header.num_entries * INDEX_ENTRY_SIZE;
        let data_size = self.index_header.data_section_size;

        INDEX_HEADER_SIZE + index_size + data_size
    }
}

impl fmt::Display for Header<IndexSignatureTag> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let summary = format!(
            "Signature Header - Entries: {},  Data Section Size: {} bytes\n",
            self.index_header.num_entries, self.index_header.data_section_size
        );
        f.write_str(&summary)?;
        let separator = "=".repeat(summary.len());
        f.write_str(&separator)?;
        f.write_str("\n")?;

        for entry in &self.index_entries {
            f.write_fmt(format_args!("    {}\n", entry))?;
        }

        Ok(())
    }
}

impl fmt::Display for Header<IndexTag> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let summary = format!(
            "Header - Entries: {},  Data Section Size: {} bytes\n",
            self.index_header.num_entries, self.index_header.data_section_size
        );
        f.write_str(&summary)?;
        let separator = "=".repeat(summary.len());
        f.write_str(&separator)?;
        f.write_str("\n")?;

        for entry in &self.index_entries {
            f.write_fmt(format_args!("    {}\n", entry))?;
        }

        Ok(())
    }
}

impl Header<IndexSignatureTag> {
    /// Construct a new empty signature header
    pub fn new_empty() -> Self {
        Self {
            index_header: IndexHeader::new(0, 0),
            index_entries: vec![],
            store: vec![],
        }
    }

    /// Clear out the signature header entries
    pub fn clear(&mut self) {
        self.index_entries.clear();
        self.index_header.data_section_size = 0;
        self.index_header.num_entries = 0;
        self.store.clear()
    }

    /// The signature header is aligned to 8 bytes - the rest is filled up with zeroes.
    ///
    /// Parsing and writing out this section requires knowing how much padding is needed to complete
    /// the alignment.
    pub(crate) fn padding_required(&self) -> u32 {
        (8 - (self.index_header.data_section_size % 8)) % 8
    }

    /// Read a signature header from the byte stream
    pub(crate) fn parse_signature(
        input: &mut impl io::BufRead,
    ) -> Result<Header<IndexSignatureTag>, Error> {
        let result: Header<IndexSignatureTag> = Self::parse(input)?;
        // if the size of our store is not a modulo of 8, we discard the padding bytes
        let padding = result.padding_required();
        if padding > 0 {
            // todo: here and below it would be nice to avoid allocating and throwing away the buffer
            let mut discard = vec![0; padding as usize];
            input.read_exact(&mut discard)?;
        }
        Ok(result)
    }

    /// Write a signature header and it's alignment to the writer
    pub(crate) fn write_signature(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        self.write(out)?;
        // align to 8 bytes
        let padding_needed = self.padding_required();
        if padding_needed > 0 {
            let padding = vec![0; padding_needed as usize];
            out.write_all(&padding)?;
        }
        Ok(())
    }
}

/// User facing accessor type representing ownership of a file
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FileOwnership {
    pub user: String,
    pub group: String,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FileDigest {
    pub digest: String,
    pub algo: DigestAlgorithm,
}

impl FileDigest {
    pub(crate) fn new(
        algorithm: DigestAlgorithm,
        hex_digest: impl Into<String>,
    ) -> Result<Self, Error> {
        let hex = hex_digest.into();

        let expected_len = match algorithm {
            DigestAlgorithm::Md5 => 32,
            DigestAlgorithm::Sha2_224 => 56,
            DigestAlgorithm::Sha2_256 | DigestAlgorithm::Sha3_256 => 64,
            DigestAlgorithm::Sha2_384 => 96,
            DigestAlgorithm::Sha2_512 | DigestAlgorithm::Sha3_512 => 128,
        };

        if hex.len() != expected_len {
            return Err(Error::InvalidDigestLength {
                algo: algorithm,
                expected: expected_len,
                actual: hex.len(),
            });
        }

        Ok(FileDigest {
            digest: hex,
            algo: algorithm,
        })
    }

    /// Return the algorithm that was used for this digest.
    pub fn algorithm(&self) -> DigestAlgorithm {
        self.algo
    }

    /// Return the digest
    pub fn as_hex(&self) -> &str {
        self.digest.as_str()
    }
}

impl Display for FileDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_hex())
    }
}

/// User facing accessor type for a changelog entry
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ChangelogEntry {
    pub name: String,
    pub timestamp: u64,
    pub description: String,
}

/// User facing accessor type for a file entry with contextual information
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FileEntry {
    /// Full path of the file entry and where it will be installed to.
    pub(crate) path: PathBuf,
    /// The file mode of the file.
    pub(crate) mode: types::FileMode,
    /// Defines the owning user and group.
    pub(crate) ownership: FileOwnership,
    /// Clocks the last access time.
    pub(crate) modified_at: Timestamp,
    /// The size of this file, dirs have the inode size (which is insane)
    pub(crate) size: usize,
    /// Flags describing the file or directory into three groups.
    pub(crate) flags: FileFlags,
    // @todo SELinux context? how is that done?
    pub(crate) digest: Option<FileDigest>,
    /// Defines any capabilities on the file.
    pub(crate) caps: Option<String>,
    /// Defines a target of a symlink (if the file is a symbolic link).
    pub(crate) linkto: Option<String>,
    /// Integrity Measurement Architecture (IMA) signature.
    pub(crate) ima_signature: Option<String>,
}

impl FileEntry {
    /// Returns the full installation path of this file entry.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the file mode (permissions and type bits).
    pub fn mode(&self) -> types::FileMode {
        self.mode
    }

    /// Returns the owning user of this file entry.
    pub fn user(&self) -> &str {
        &self.ownership.user
    }

    /// Returns the owning group of this file entry.
    pub fn group(&self) -> &str {
        &self.ownership.group
    }

    /// Returns the permission bits of this file entry (including setuid/setgid/sticky).
    pub fn permissions(&self) -> u16 {
        self.mode.permissions()
    }

    //// Returns the [`FileType`]` of this file entry.
    pub fn file_type(&self) -> FileType {
        self.mode.file_type()
    }

    /// Returns the last-modified timestamp of this file entry.
    pub fn modified_at(&self) -> Timestamp {
        self.modified_at
    }

    /// Returns the size of this file in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the flags describing this file (e.g. config, doc, ghost).
    pub fn flags(&self) -> FileFlags {
        self.flags
    }
    /// Returns the cryptographic digest of this file, if present.
    pub fn digest(&self) -> Option<&FileDigest> {
        self.digest.as_ref()
    }

    /// Returns the capability string for this file, if any.
    pub fn caps(&self) -> Option<&str> {
        self.caps.as_deref()
    }

    /// Returns the symlink target of this file, if it is a symbolic link.
    pub fn linkto(&self) -> Option<&str> {
        self.linkto.as_deref()
    }

    /// Returns the IMA (Integrity Measurement Architecture) signature, if present.
    pub fn ima_signature(&self) -> Option<&str> {
        self.ima_signature.as_deref()
    }
}

fn parse_entry_data_number<'a, T, E, F>(
    mut input: &'a [u8],
    num_items: u32,
    items: &mut Vec<T>,
    parser: F,
) -> nom::IResult<&'a [u8], (), E>
where
    E: nom::error::ParseError<&'a [u8]>,
    F: Fn(&'a [u8]) -> nom::IResult<&'a [u8], T, E>,
{
    items.reserve_exact(num_items as usize);
    for _ in 0..num_items {
        let (rest, data) = parser(input)?;
        items.push(data);
        input = rest;
    }

    Ok((input, ()))
}

fn parse_binary_entry(
    input: &[u8],
    num_items: u32,
    items: &mut Vec<u8>,
    bin_type: &str,
) -> Result<(), Error> {
    let bin_bytes = input.get(..num_items as usize).ok_or_else(|| {
        Error::Nom(format!(
            "Insufficient bytes for IndexData::{} entry",
            bin_type
        ))
    })?;
    items.extend_from_slice(bin_bytes);
    Ok(())
}

/// A header keeping track of all other header records.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct IndexHeader {
    /// rpm specific magic header
    pub(crate) magic: [u8; 3],
    /// rpm version number, always 1
    pub(crate) version: u8,
    /// number of header entries
    pub(crate) num_entries: u32,
    /// total amount of data stored
    pub(crate) data_section_size: u32,
}

impl IndexHeader {
    // 16 bytes
    pub(crate) fn parse(input: &[u8]) -> Result<Self, Error> {
        // first three bytes are magic
        let (rest, magic) = complete::take(3usize)(input)?;
        for i in 0..2 {
            if HEADER_MAGIC[i] != magic[i] {
                return Err(Error::InvalidMagic {
                    expected: HEADER_MAGIC[i],
                    actual: magic[i],
                    complete_input: input.to_vec(),
                });
            }
        }
        // then one byte for version
        let (rest, version) = be_u8(rest)?;

        if version != 1 {
            return Err(Error::UnsupportedHeaderVersion(version));
        }
        // then 4 bytes reserved
        let (rest, _) = complete::take(4usize)(rest)?;
        // then number of of entries (u32, 4 bytes)
        let (rest, num_entries) = be_u32(rest)?;
        // then size of header (u32, 4 bytes)
        let (_rest, data_len) = be_u32(rest)?;

        Ok(IndexHeader {
            magic: HEADER_MAGIC,
            version: 1,
            num_entries,
            data_section_size: data_len,
        })
    }

    pub(crate) fn write<W: std::io::Write>(&self, out: &mut W) -> Result<(), Error> {
        out.write_all(&self.magic)?;
        out.write_all(&self.version.to_be_bytes())?;
        out.write_all(&[0; 4])?;
        out.write_all(&self.num_entries.to_be_bytes())?;
        out.write_all(&self.data_section_size.to_be_bytes())?;
        Ok(())
    }

    pub(crate) fn new(num_entries: u32, data_len: u32) -> Self {
        IndexHeader {
            magic: HEADER_MAGIC,
            version: 1,
            num_entries,
            data_section_size: data_len,
        }
    }
}

/// A single entry within the [`IndexHeader`](self::IndexHeader)
#[derive(Clone, PartialEq)]
pub(crate) struct IndexEntry<T: num::FromPrimitive> {
    pub(crate) tag: u32,
    /// For parsed headers, string data lives in `Header::store` and must be accessed
    /// through `Header` getter methods. This field may only hold a lossy UTF-8
    /// fallback for string types (see the parse comment in `Header::parse`).
    /// For builder-created entries, this holds the actual data to be written.
    pub(crate) data: IndexData,
    pub(crate) offset: i32,
    pub(crate) num_items: u32,
    // Marks what type of IndexEntry it is
    entry_type: PhantomData<T>,
}

/// Custom Debug impl for the benefit of showing the tag name, if we are familiar with it
impl<T: Tag> std::fmt::Debug for IndexEntry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let known_tag: Option<T> = num::FromPrimitive::from_u32(self.tag);
        // An RPM package could have tags which we don't know about, or expect. So if we don't
        // recognize the tag as being a known valid one for this header type, print UnknownTag[$id]
        let tag_name = if let Some(val) = known_tag {
            format!("{:?}", val)
        } else {
            format!("UnknownTag[{:?}]", self.tag)
        };

        f.debug_struct(&format!("IndexEntry<{}>", T::tag_type_name()))
            .field("tag", &tag_name)
            .field("data", &self.data)
            .field("offset", &self.offset)
            .field("num_items", &self.num_items)
            .finish()
    }
}

impl<T: Tag> IndexEntry<T> {
    // 16 bytes
    pub(crate) fn parse(input: &[u8]) -> Result<(&[u8], Self), Error> {
        // first 4 bytes are the tag.
        let (input, tag) = be_u32(input)?;
        // next 4 bytes is the tag type
        let (input, tag_type) = be_u32(input)?;

        // initialize the datatype. Parsing of the data happens later since the store comes after the index section.
        let data =
            IndexData::from_type_as_u32(tag_type).ok_or_else(|| Error::InvalidTagDataType {
                raw_data_type: tag_type,
                store_type: T::tag_type_name(),
            })?;

        //  next 4 bytes is the offset relative to the beginning of the store
        let (input, offset) = be_i32(input)?;

        // last 4 bytes are the count that contains the number of data items pointed to by the index entry
        let (rest, num_items) = be_u32(input)?;

        Ok((
            rest,
            IndexEntry {
                tag,
                data,
                offset,
                num_items,
                entry_type: PhantomData,
            },
        ))
    }

    pub(crate) fn write_index(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        out.write_all(&self.tag.to_be_bytes())?;
        out.write_all(&self.data.type_as_u32().to_be_bytes())?;
        out.write_all(&self.offset.to_be_bytes())?;
        out.write_all(&self.num_items.to_be_bytes())?;
        Ok(())
    }

    /// Create a new IndexEntry for use in building headers.
    ///
    /// The `offset` field is initialized to 0 because it is computed later
    /// by `Header::from_entries` when the entry's data is appended to the store.
    pub(crate) fn new(tag: T, data: IndexData) -> IndexEntry<T> {
        IndexEntry {
            tag: tag.to_u32(),
            offset: 0,
            num_items: data.num_items(),
            data,
            entry_type: PhantomData,
        }
    }
}

impl<T: Tag> fmt::Display for IndexEntry<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let known_tag: Option<T> = num::FromPrimitive::from_u32(self.tag);
        // An RPM package could have tags which we don't know about, or expect. So if we don't
        // recognize the tag as being a known valid one for this header type, print << UnknownTag >> [$id]
        let tag_name = if let Some(val) = known_tag {
            format!("{:?}", val)
        } else {
            format!("<< UnknownTag >> [{:?}]", self.tag)
        };

        f.write_fmt(format_args!("{}: {}", tag_name, self.data))
    }
}

/// Data as present in a [`IndexEntry`](self::IndexEntry) .
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexData {
    Null,
    Char(Vec<u8>),
    Int8(Vec<u8>),
    Int16(Vec<u16>),
    Int32(Vec<u32>),
    Int64(Vec<u64>),
    StringTag(String),
    Bin(Vec<u8>),
    StringArray(Vec<String>),
    I18NString(Vec<String>),
}

impl fmt::Display for IndexData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let rep = match self {
            IndexData::Null => "Null",
            IndexData::Bin(_) => "Bin",
            IndexData::Char(_) => "Char",
            IndexData::I18NString(_) => "I18NString",
            IndexData::StringTag(_) => "String",
            IndexData::StringArray(_) => "StringArray",
            IndexData::Int8(_) => "i8",
            IndexData::Int16(_) => "i16",
            IndexData::Int32(_) => "i32",
            IndexData::Int64(_) => "i64",
        };
        write!(f, "{}", rep)
    }
}

impl IndexData {
    pub(crate) fn append(&self, store: &mut Vec<u8>) -> u32 {
        match &self {
            IndexData::Null => 0,
            IndexData::Char(d) => {
                store.extend_from_slice(d);
                0
            }
            IndexData::Int8(d) => {
                for i in d.iter().map(|i| i.to_be_bytes()) {
                    store.push(i[0]);
                }
                0
            }
            IndexData::Int16(d) => {
                // align to 2 bytes

                let alignment = if !store.len().is_multiple_of(2) {
                    store.push(0);
                    1
                } else {
                    0
                };
                let iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for byte in iter {
                    store.push(byte);
                }
                alignment
            }
            IndexData::Int32(d) => {
                // align to 4 bytes
                let mut alignment = 0;
                while !store.len().is_multiple_of(4) {
                    store.push(0);
                    alignment += 1;
                }
                let iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for byte in iter {
                    store.push(byte);
                }
                alignment
            }
            IndexData::Int64(d) => {
                // align to 8 bytes
                let mut alignment = 0;
                while !store.len().is_multiple_of(8) {
                    store.push(0);
                    alignment += 1;
                }
                let iter = d.iter().flat_map(|item| item.to_be_bytes().to_vec());
                for byte in iter {
                    store.push(byte);
                }
                alignment
            }
            IndexData::StringTag(d) => {
                store.extend_from_slice(d.as_bytes());
                store.push(0);
                0
            }
            IndexData::Bin(d) => {
                store.extend_from_slice(d);
                0
            }
            IndexData::StringArray(d) => {
                for item in d {
                    store.extend_from_slice(item.as_bytes());
                    store.push(0);
                }
                0
            }
            IndexData::I18NString(d) => {
                for item in d {
                    store.extend_from_slice(item.as_bytes());
                    store.push(0);
                }
                0
            }
        }
    }

    pub(crate) fn num_items(&self) -> u32 {
        match self {
            IndexData::Null => 0,
            IndexData::Bin(items) => items.len() as u32,
            IndexData::Char(items) => items.len() as u32,
            IndexData::I18NString(items) => items.len() as u32,
            IndexData::StringTag(_) => 1,
            IndexData::StringArray(items) => items.len() as u32,
            IndexData::Int8(items) => items.len() as u32,
            IndexData::Int16(items) => items.len() as u32,
            IndexData::Int32(items) => items.len() as u32,
            IndexData::Int64(items) => items.len() as u32,
        }
    }

    pub(crate) fn from_type_as_u32(i: u32) -> Option<Self> {
        match i {
            0 => Some(IndexData::Null),
            1 => Some(IndexData::Char(Vec::new())),
            2 => Some(IndexData::Int8(Vec::new())),
            3 => Some(IndexData::Int16(Vec::new())),
            4 => Some(IndexData::Int32(Vec::new())),
            5 => Some(IndexData::Int64(Vec::new())),
            6 => Some(IndexData::StringTag(String::new())),
            7 => Some(IndexData::Bin(Vec::new())),
            8 => Some(IndexData::StringArray(Vec::new())),
            9 => Some(IndexData::I18NString(Vec::new())),
            _ => None,
        }
    }

    pub(crate) fn type_as_u32(&self) -> u32 {
        match self {
            IndexData::Null => 0,
            IndexData::Char(_) => 1,
            IndexData::Int8(_) => 2,
            IndexData::Int16(_) => 3,
            IndexData::Int32(_) => 4,
            IndexData::Int64(_) => 5,
            IndexData::StringTag(_) => 6,
            IndexData::Bin(_) => 7,

            IndexData::StringArray(_) => 8,
            IndexData::I18NString(_) => 9,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_region_tag() -> Result<(), Box<dyn std::error::Error>> {
        let region_entry = Header::create_region_tag(IndexSignatureTag::HEADER_SIGNATURES, 2, 400);

        let data = match &region_entry.data {
            IndexData::Bin(d) => d.as_slice(),
            _ => panic!("should be binary"),
        };

        let (_, entry) = IndexEntry::<IndexSignatureTag>::parse(data)?;

        assert_eq!(entry.tag, IndexSignatureTag::HEADER_SIGNATURES as u32);
        assert_eq!(
            entry.data.type_as_u32(),
            IndexData::Bin(Vec::new()).type_as_u32()
        );
        assert_eq!(-48, entry.offset);

        Ok(())
    }

    #[test]
    fn test_from_entries_sorts_tags() {
        // Create entries in non-sorted order
        let entries = vec![
            IndexEntry::new(
                IndexTag::RPMTAG_VERSION,
                IndexData::StringTag("1.0.0".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_NAME,
                IndexData::StringTag("test".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_RELEASE,
                IndexData::StringTag("1".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_ARCH,
                IndexData::StringTag("x86_64".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_LICENSE,
                IndexData::StringTag("MIT".to_string()),
            ),
        ];

        // Verify they're not sorted
        let tags_before: Vec<u32> = entries.iter().map(|e| e.tag).collect();
        assert!(
            !tags_before.windows(2).all(|w| w[0] <= w[1]),
            "Input should not be sorted"
        );

        // Create header with from_entries
        let header = Header::from_entries(entries, IndexTag::RPMTAG_HEADERIMMUTABLE);

        // Extract tags from the created header (skip the region tag at index 0)
        let tags_after: Vec<u32> = header.index_entries.iter().skip(1).map(|e| e.tag).collect();

        // Verify they're now sorted
        assert!(
            tags_after.windows(2).all(|w| w[0] <= w[1]),
            "Tags should be sorted: {:?}",
            tags_after
        );

        // Verify the specific expected order
        assert_eq!(tags_after[0], IndexTag::RPMTAG_NAME as u32);
        assert_eq!(tags_after[1], IndexTag::RPMTAG_VERSION as u32);
        assert_eq!(tags_after[2], IndexTag::RPMTAG_RELEASE as u32);
        assert_eq!(tags_after[3], IndexTag::RPMTAG_LICENSE as u32);
        assert_eq!(tags_after[4], IndexTag::RPMTAG_ARCH as u32);
    }
}
