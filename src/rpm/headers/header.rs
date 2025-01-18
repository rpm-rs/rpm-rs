use nom::{
    bytes::complete,
    number::complete::{be_i32, be_u16, be_u32, be_u64, be_u8},
};
use std::{
    fmt::{self, Display},
    io,
    marker::PhantomData,
    path::PathBuf,
};

use super::*;
use crate::{constants::*, errors::*, Timestamp};

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
        // add data to entries
        for entry in &mut entries {
            let mut remaining = &bytes[entry.offset as usize..];

            match &mut entry.data {
                IndexData::Null => {}
                IndexData::Char(ref mut chars) => {
                    parse_binary_entry(remaining, entry.num_items, chars, "Char")?;
                }
                IndexData::Int8(ref mut ints) => {
                    parse_binary_entry(remaining, entry.num_items, ints, "Int8")?;
                }
                IndexData::Int16(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u16)?;
                }
                IndexData::Int32(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u32)?;
                }
                IndexData::Int64(ref mut ints) => {
                    parse_entry_data_number(remaining, entry.num_items, ints, be_u64)?;
                }
                IndexData::StringTag(ref mut string) => {
                    let (_rest, raw_string) = complete::take_till(|item| item == 0)(remaining)?;
                    string.push_str(String::from_utf8_lossy(raw_string).as_ref());
                }
                IndexData::Bin(ref mut bin) => {
                    parse_binary_entry(remaining, entry.num_items, bin, "Bin")?;
                }
                IndexData::StringArray(ref mut strings) => {
                    for _ in 0..entry.num_items {
                        let (rest, raw_string) = complete::take_till(|item| item == 0)(remaining)?;
                        // the null byte is still in there.. we need to cut it out.
                        remaining = &rest[1..];
                        let string = String::from_utf8_lossy(raw_string).to_string();
                        strings.push(string);
                    }
                }
                IndexData::I18NString(ref mut strings) => {
                    for _ in 0..entry.num_items {
                        let (rest, raw_string) = complete::take_till(|item| item == 0)(remaining)?;
                        remaining = rest;
                        let string = String::from_utf8_lossy(raw_string).to_string();
                        strings.push(string);
                    }
                }
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

    pub fn entry_is_present(&self, tag: T) -> bool {
        self.index_entries
            .iter()
            .any(|entry| entry.tag == tag.to_u32())
    }

    pub(crate) fn find_entry_or_err(&self, tag: T) -> Result<&IndexEntry<T>, Error> {
        self.index_entries
            .iter()
            .find(|entry| entry.tag == tag.to_u32())
            .ok_or_else(|| Error::TagNotFound(tag.to_string()))
        // @todo: this could be more efficient, if the tag is an integer, we can just pass around
        // an integer, and the name of the tag (or "unknown") can be easily derived from that
    }

    pub fn get_entry_data_as_binary(&self, tag: T) -> Result<&[u8], Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_binary()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "binary",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_string(&self, tag: T) -> Result<&str, Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_str()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "string",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_i18n_string(&self, tag: T) -> Result<&str, Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_i18n_str()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "i18n string array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u16_array(&self, tag: T) -> Result<Vec<u16>, Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u16_array()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "uint16 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u32(&self, tag: T) -> Result<u32, Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u32()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "uint32",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u32_array(&self, tag: T) -> Result<Vec<u32>, Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u32_array()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "uint32 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u64(&self, tag: T) -> Result<u64, Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u64()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "uint64",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_u64_array(&self, tag: T) -> Result<Vec<u64>, Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_u64_array()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "uint64 array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub fn get_entry_data_as_string_array(&self, tag: T) -> Result<&[String], Error> {
        let entry = self.find_entry_or_err(tag)?;
        entry
            .data
            .as_string_array()
            .ok_or_else(|| Error::UnexpectedTagDataType {
                expected_data_type: "string array",
                actual_data_type: entry.data.to_string(),
                tag: entry.tag.to_string(),
            })
    }

    pub(crate) fn create_region_tag(tag: T, records_count: i32, offset: i32) -> IndexEntry<T> {
        let mut header_immutable_index_data = vec![];
        let mut hie = IndexEntry::new(
            tag,
            (records_count + 1) * -(INDEX_ENTRY_SIZE as i32),
            IndexData::Bin(Vec::new()),
        );
        hie.num_items = 16;
        hie.write_index(&mut header_immutable_index_data)
            .expect("unable to write to memory buffer");
        IndexEntry::new(tag, offset, IndexData::Bin(header_immutable_index_data))
    }

    pub(crate) fn from_entries(mut actual_records: Vec<IndexEntry<T>>, region_tag: T) -> Self {
        // Ensure the tags in the header we're creating will be in sorted order
        actual_records.sort_by(|e1, e2| e1.tag.cmp(&e2.tag));

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

        // TODO dunno if this is necessary yet.
        // if store_size % 8 > 0 {
        //     store_size += 8 - (store_size % 8);
        // }
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
    pub fn builder() -> SignatureHeaderBuilder<Empty> {
        SignatureHeaderBuilder::<Empty>::new()
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

    pub fn new_empty() -> Self {
        Self {
            index_header: IndexHeader::new(0, 0),
            index_entries: vec![],
            store: vec![],
        }
    }

    pub fn clear(&mut self) {
        self.index_entries.clear();
        self.index_header.data_section_size = 0;
        self.index_header.num_entries = 0;
        self.store.clear()
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
        let digest = FileDigest {
            digest: hex,
            algo: algorithm,
        };

        Ok(match algorithm {
            DigestAlgorithm::Md5 if digest.digest.len() == 32 => digest,
            DigestAlgorithm::Sha2_256 if digest.digest.len() == 64 => digest,
            DigestAlgorithm::Sha2_224 if digest.digest.len() == 60 => digest,
            DigestAlgorithm::Sha2_384 if digest.digest.len() == 96 => digest,
            DigestAlgorithm::Sha2_512 if digest.digest.len() == 128 => digest,
            // @todo disambiguate mismatch of length from unsupported algorithm
            digest_algo => return Err(Error::UnsupportedDigestAlgorithm(digest_algo)),
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
    pub path: PathBuf,
    /// The file mode of the file.
    pub mode: types::FileMode,
    /// Defines the owning user and group.
    pub ownership: FileOwnership,
    /// Clocks the last access time.
    pub modified_at: Timestamp,
    /// The size of this file, dirs have the inode size (which is insane)
    pub size: usize,
    /// Flags describing the file or directory into three groups.
    pub flags: FileFlags,
    // @todo SELinux context? how is that done?
    pub digest: Option<FileDigest>,
    /// Defines any capabilities on the file.
    pub caps: Option<String>,
    /// Defines a target of a symlink (if the file is a symbolic link).
    pub linkto: String,
    /// Integrity Measurement Architecture (IMA) signature.
    pub ima_signature: Option<String>,
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
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct IndexEntry<T: num::FromPrimitive> {
    pub(crate) tag: u32,
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
        let mut written = out.write(&self.tag.to_be_bytes())?;
        written += out.write(&self.data.type_as_u32().to_be_bytes())?;
        written += out.write(&self.offset.to_be_bytes())?;
        written += out.write(&self.num_items.to_be_bytes())?;
        debug_assert_eq!(
            INDEX_ENTRY_SIZE as usize, written,
            "there should be 16 bytes written"
        );
        Ok(())
    }

    pub(crate) fn new(tag: T, offset: i32, data: IndexData) -> IndexEntry<T> {
        IndexEntry {
            tag: tag.to_u32(),
            offset,
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
pub(crate) enum IndexData {
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

                let alignment = if store.len() % 2 != 0 {
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
                while store.len() % 4 > 0 {
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
                while store.len() % 8 > 0 {
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

    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            IndexData::StringTag(s) => Some(s),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn as_char_array(&self) -> Option<Vec<u8>> {
        match self {
            IndexData::Char(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    #[allow(unused)]
    pub(crate) fn as_u8_array(&self) -> Option<Vec<u8>> {
        match self {
            IndexData::Int8(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_u16_array(&self) -> Option<Vec<u16>> {
        match self {
            IndexData::Int16(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_u32(&self) -> Option<u32> {
        match self {
            IndexData::Int32(s) => s.first().copied(),
            _ => None,
        }
    }
    pub(crate) fn as_u32_array(&self) -> Option<Vec<u32>> {
        match self {
            IndexData::Int32(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_u64(&self) -> Option<u64> {
        match self {
            IndexData::Int64(s) => s.first().copied(),
            _ => None,
        }
    }

    pub(crate) fn as_u64_array(&self) -> Option<Vec<u64>> {
        match self {
            IndexData::Int64(s) => Some(s.to_vec()),
            _ => None,
        }
    }

    pub(crate) fn as_string_array(&self) -> Option<&[String]> {
        match self {
            IndexData::StringArray(d) | IndexData::I18NString(d) => Some(d),
            _ => None,
        }
    }

    pub(crate) fn as_i18n_str(&self) -> Option<&str> {
        match self {
            IndexData::I18NString(s) => {
                // @todo: an actual implementation that doesn't just get the first string from the table
                Some(&s[0])
            }
            _ => None,
        }
    }

    pub(crate) fn as_binary(&self) -> Option<&[u8]> {
        match self {
            IndexData::Bin(d) => Some(d.as_slice()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_region_tag() -> Result<(), Box<dyn std::error::Error>> {
        let region_entry = Header::create_region_tag(IndexSignatureTag::HEADER_SIGNATURES, 2, 400);

        let possible_binary = region_entry.data.as_binary();

        assert!(possible_binary.is_some(), "should be binary");

        let data = possible_binary.unwrap();

        let (_, entry) = IndexEntry::<IndexSignatureTag>::parse(data)?;

        assert_eq!(entry.tag, IndexSignatureTag::HEADER_SIGNATURES as u32);
        assert_eq!(
            entry.data.type_as_u32(),
            IndexData::Bin(Vec::new()).type_as_u32()
        );
        assert_eq!(-48, entry.offset);

        Ok(())
    }
}
