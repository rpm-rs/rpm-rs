//! Read/write RPM package payload archives.
//!
//! RPM package payloads come in two different flavors, CPIO and "stripped" CPIO.
//!
//! ## CPIO Format Details
//!
//! The newc (SVR4 "new ASCII") CPIO format uses a fixed 110-byte header followed by a
//! variable-length filename and file data. Two variants share the same structure:
//!
//! - **070701** ("new ASCII" / newc): no per-file checksum
//! - **070702** ("new CRC"): includes a per-file checksum (sum of all data bytes, mod 2^32)
//!
//! RPM generally uses the "newc" variant - without file checksums.
//!
//! ## Stripped CPIO Format (RPM-specific, magic 07070X)
//!
//! RPM v4.12+ uses a stripped-down CPIO variant for packages containing files > 4 GB.
//! The stripped header is only 14 bytes: 6-byte magic ("07070X") + 8-byte hex file index.
//! All file metadata is stored in the RPM header instead.
//!
//! ## Alignment / Padding
//!
//! All headers and file data are padded to 4-byte boundaries regardless of the header format.
//! Padding must be written after every entry's data, including the last entry before the trailer.

// The code in this file is partially copied from the `cpio` crate by Jonathan Creekmore
// (https://github.com/jcreekmore/cpio-rs) under the MIT license.
//
//     MIT License
//
//     Copyright (c) 2016 Jonathan Creekmore
//
//     Permission is hereby granted, free of charge, to any person obtaining a copy of this software
//     and associated documentation files (the "Software"),  to deal in the Software without restriction,
//     including without limitation the rights to use, copy, modify, merge, publish, distribute,
//     sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
//     furnished to do so, subject to the following conditions:
//
//     The above copyright notice and this permission notice shall be included in all copies or
//     substantial portions of the Software.
//
//     THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
//     BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  FITNESS FOR A PARTICULAR PURPOSE AND
//     NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
//     DAMAGES OR OTHER  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
//     FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS  IN THE SOFTWARE.
//
// It has been modified to match modifications which are used by the upstream RPM library.
// These modifications are described upstream as follows:
//
//     As cpio is limited to 4 GB (32 bit unsigned) file sizes, RPM since version 4.12
//     uses a stripped down version of cpio for packages with files > 4 GB. This format
//     uses 07070X as magic bytes and the file header otherwise only contains the index
//     number of the file in the RPM header as 8 byte hex string. The file metadata that
//     is normally found in a cpio file header - including the file name - is completely
//     omitted as it is stored in the RPM header already.
//
// Other modifications made to this library include:
//   * Several type renamings
//   * Reader::entry() removed, tests use a helper function
//   * Reader::new() now takes a slice of FileEntry, so that knows how large the files are for the purpose of reading them
//   * Seekable implementation and accompanying tests were deleted - we don't need it
//   * Reader and Writer modified to handle both standard CPIO and RPM-flavored stripped CPIO
//   * Return library-specific errors

#![allow(dead_code)]

use super::FileEntry;
use std::io::{self, Read, Write};
const HEADER_LEN: usize = 110; // 6 byte magic + 104 bytes for metadata

const STRIPPED_CPIO_HEADER_LEN: usize = 14; // 8 bytes metadata + 6 bytes magic

const MAGIC_NUMBER_NEWASCII: &[u8] = b"070701";
const MAGIC_NUMBER_NEWCRC: &[u8] = b"070702";

const STRIPPED_CPIO_MAGIC_NUMBER: &[u8] = b"07070X"; // Magic number changed to conform with RPM

const TRAILER_NAME: &str = "TRAILER!!!";

/// Whether this header is of the "new ascii" form (without checksum) or the "crc" form which
/// is structurally identical but includes a checksum, depending on the magic number present.
#[derive(Debug, PartialEq)]
enum CpioEntryType {
    Crc,
    Newc,
}

/// Whether the header entry is of a standard CPIO form or the RPM-specific archive form
#[derive(Debug, PartialEq)]
pub enum RpmPayloadEntry {
    Cpio(CpioEntry), // name, file_size
    Stripped(u32),   // file_index
}

/// Metadata about one entry from an archive.
#[derive(Debug, PartialEq)]
pub struct CpioEntry {
    entry_type: CpioEntryType,
    name: String,
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    file_size: u32,
    dev_major: u32,
    dev_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
    checksum: u32,
}

/// Reads one entry header/data from an archive.
pub struct Reader<R: Read> {
    inner: R,
    entry: RpmPayloadEntry,
    file_size: u64,
    bytes_read: u64,
}

/// Builds metadata for one entry to be written into an archive.
#[derive(Clone)]
pub struct Builder {
    name: String,
    ino: u32,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    mtime: u32,
    dev_major: u32,
    dev_minor: u32,
    rdev_major: u32,
    rdev_minor: u32,
}

/// Writes one entry header/data into an archive.
pub struct Writer<W: Write> {
    inner: W,
    written: u64,
    file_size: u64,
    header_size: usize,
    header: Vec<u8>,
}

/// Compute NUL padding bytes needed to align `len` to a 4-byte boundary.
///
/// Returns `None` if `len` is already aligned.
fn align_to_4(len: usize) -> Option<Vec<u8>> {
    let overhang = len % 4;
    if overhang != 0 {
        let repeat = 4 - overhang;
        Some(vec![0u8; repeat])
    } else {
        None
    }
}

pub enum ModeFileType {
    Symlink,
    Fifo,
    Char,
    Block,
    NetworkSpecial,
    Socket,
    Directory,
    Regular,
}

impl ModeFileType {
    const MASK: u32 = 0o170000;
}

impl From<ModeFileType> for u32 {
    fn from(m: ModeFileType) -> u32 {
        match m {
            ModeFileType::Fifo => 0o010000,
            ModeFileType::Char => 0o020000,
            ModeFileType::Directory => 0o040000,
            ModeFileType::Block => 0o060000,
            ModeFileType::Regular => 0o100000,
            ModeFileType::NetworkSpecial => 0o110000,
            ModeFileType::Symlink => 0o120000,
            ModeFileType::Socket => 0o140000,
        }
    }
}

fn read_hex_u32<R: Read>(reader: &mut R) -> io::Result<u32> {
    let mut bytes = [0u8; 8];
    reader.read_exact(&mut bytes)?;
    ::std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid utf-8 header field"))
        .and_then(|string| {
            u32::from_str_radix(string, 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid hex u32 header field")
            })
        })
}

impl CpioEntry {
    /// Returns the name of the file.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the inode number of the file. Sometimes this is just an index.
    pub fn ino(&self) -> u32 {
        self.ino
    }

    /// Returns the file's "mode" - the same as an inode "mode" field - containing permission bits
    /// and a bit of metadata about the type of file represented.
    pub fn mode(&self) -> u32 {
        self.mode
    }

    /// Returns the UID for this file's owner.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the GID for this file's group.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the number of links associated with this file.
    pub fn nlink(&self) -> u32 {
        self.nlink
    }

    /// Returns the modification time of this file.
    pub fn mtime(&self) -> u32 {
        self.mtime
    }

    /// Returns the size of this file, in bytes.
    pub fn file_size(&self) -> u32 {
        self.file_size
    }

    /// Returns the major component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_major(&self) -> u32 {
        self.dev_major
    }

    /// Returns the minor component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_minor(&self) -> u32 {
        self.dev_minor
    }

    /// Returns the major component of the rdev ID, describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_major(&self) -> u32 {
        self.rdev_major
    }

    /// Returns the minor component of the rdev ID, field describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_minor(&self) -> u32 {
        self.rdev_minor
    }

    /// Returns true if this is a trailer entry.
    pub fn is_trailer(&self) -> bool {
        self.name == TRAILER_NAME
    }

    /// Return the checksum of this entry.
    ///
    /// The checksum is calculated by summing the bytes in the file and taking the least
    /// significant 32 bits. Not all CPIO archives use checksums.
    pub fn checksum(&self) -> Option<u32> {
        match self.entry_type {
            CpioEntryType::Crc => Some(self.checksum),
            CpioEntryType::Newc => None,
        }
    }
}

impl<R: Read> Reader<R> {
    /// Parses metadata for the next entry in an archive, and returns a reader
    /// that will yield the entry data.
    pub fn new(mut inner: R, file_entries: &[FileEntry<'_>]) -> io::Result<Reader<R>> {
        // char    c_magic[6];
        let mut magic = [0u8; 6];
        inner.read_exact(&mut magic)?;
        let entry = match magic.as_slice() {
            MAGIC_NUMBER_NEWASCII | MAGIC_NUMBER_NEWCRC => {
                let entry_type = match magic.as_slice() {
                    MAGIC_NUMBER_NEWASCII => CpioEntryType::Newc,
                    MAGIC_NUMBER_NEWCRC => CpioEntryType::Crc,
                    _ => unreachable!("can't happen"),
                };

                // char    c_ino[8];
                let ino = read_hex_u32(&mut inner)?;
                // char    c_mode[8];
                let mode = read_hex_u32(&mut inner)?;
                // char    c_uid[8];
                let uid = read_hex_u32(&mut inner)?;
                // char    c_gid[8];
                let gid = read_hex_u32(&mut inner)?;
                // char    c_nlink[8];
                let nlink = read_hex_u32(&mut inner)?;
                // char    c_mtime[8];
                let mtime = read_hex_u32(&mut inner)?;
                // char    c_filesize[8];
                let file_size = read_hex_u32(&mut inner)?;
                // char    c_devmajor[8];
                let dev_major = read_hex_u32(&mut inner)?;
                // char    c_devminor[8];
                let dev_minor = read_hex_u32(&mut inner)?;
                // char    c_rdevmajor[8];
                let rdev_major = read_hex_u32(&mut inner)?;
                // char    c_rdevminor[8];
                let rdev_minor = read_hex_u32(&mut inner)?;
                // char    c_namesize[8];
                let name_len = read_hex_u32(&mut inner)? as usize;
                // char    c_checksum[8];
                let checksum = read_hex_u32(&mut inner)?;

                // NUL-terminated name with length `name_len` (including NUL byte).
                let mut name_bytes = vec![0u8; name_len];
                if name_bytes.len() > 4096 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Entry name is too long",
                    ));
                }
                inner.read_exact(&mut name_bytes)?;
                if name_bytes.last() != Some(&0) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Entry name was not NUL-terminated",
                    ));
                }
                name_bytes.pop();
                // dracut-cpio sometimes pads the name to the next filesystem block.
                // See https://github.com/dracutdevs/dracut/commit/a9c67046
                while name_bytes.last() == Some(&0) {
                    name_bytes.pop();
                }
                let name = String::from_utf8(name_bytes).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Entry name was not valid UTF-8")
                })?;

                // Pad out to a multiple of 4 bytes.
                if let Some(mut padding) = align_to_4(HEADER_LEN + name_len) {
                    inner.read_exact(&mut padding)?;
                }
                let entry = CpioEntry {
                    entry_type,
                    name,
                    ino,
                    mode,
                    uid,
                    gid,
                    nlink,
                    mtime,
                    file_size,
                    dev_major,
                    dev_minor,
                    rdev_major,
                    rdev_minor,
                    checksum,
                };

                RpmPayloadEntry::Cpio(entry)
            }
            STRIPPED_CPIO_MAGIC_NUMBER => {
                let file_index = read_hex_u32(&mut inner)?;

                // The stripped header is 14 bytes (6 magic + 8 index), padded to 16.
                if let Some(mut padding) = align_to_4(STRIPPED_CPIO_HEADER_LEN) {
                    inner.read_exact(&mut padding)?;
                }

                RpmPayloadEntry::Stripped(file_index)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid magic number",
                ));
            }
        };

        let file_size: u64 = match entry {
            RpmPayloadEntry::Cpio(ref c) => c.file_size as u64,
            RpmPayloadEntry::Stripped(idx) => {
                let idx = idx as usize;
                file_entries
                    .get(idx)
                    .map(|e| e.size as u64)
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "stripped CPIO file index {} out of range ({}  entries)",
                                idx,
                                file_entries.len()
                            ),
                        )
                    })?
            }
        };

        Ok(Reader {
            inner,
            entry,
            file_size,
            bytes_read: 0,
        })
    }

    /// Returns true if this is a trailer entry.
    pub fn is_trailer(&self) -> bool {
        match &self.entry {
            RpmPayloadEntry::Cpio(c) => c.is_trailer(),
            // This should never actually happen. In practice RPM always uses the CPIO
            // trailer, but, no reason not to be defensive I suppose.
            RpmPayloadEntry::Stripped(idx) => *idx == u32::MAX,
        }
    }

    /// Finishes reading this entry and returns the underlying reader in a
    /// position ready to read the next entry (if any).
    pub fn finish(mut self) -> io::Result<R> {
        let remaining = self.file_size - self.bytes_read;
        if remaining > 0 {
            io::copy(&mut self.inner.by_ref().take(remaining), &mut io::sink())?;
        }
        if let Some(mut padding) = align_to_4(self.file_size as usize) {
            self.inner.read_exact(&mut padding)?;
        }
        Ok(self.inner)
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let remaining = self.file_size - self.bytes_read;
        let limit = buf.len().min(remaining as usize);
        if limit > 0 {
            let num_bytes = self.inner.read(&mut buf[..limit])?;
            self.bytes_read += num_bytes as u64;
            Ok(num_bytes)
        } else {
            Ok(0)
        }
    }
}

impl Builder {
    /// Create the metadata for one CPIO entry
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ino: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            dev_major: 0,
            dev_minor: 0,
            rdev_major: 0,
            rdev_minor: 0,
        }
    }

    /// Set the inode number for this file. In modern times however, typically this is just a
    /// a unique index ID for the file, rather than the actual inode number.
    pub fn ino(mut self, ino: u32) -> Self {
        self.ino = ino;
        self
    }

    /// Set the file's "mode" - the same as an inode "mode" field - containing permission bits
    /// and a bit of metadata about the type of file represented.
    pub fn mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }

    /// Set this file's UID.
    pub fn uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }

    /// Set this file's GID.
    pub fn gid(mut self, gid: u32) -> Self {
        self.gid = gid;
        self
    }

    /// Set the number of links associated with this file.
    pub fn nlink(mut self, nlink: u32) -> Self {
        self.nlink = nlink;
        self
    }

    /// Set the modification time of this file.
    pub fn mtime(mut self, mtime: u32) -> Self {
        self.mtime = mtime;
        self
    }

    /// Set the major component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_major(mut self, dev_major: u32) -> Self {
        self.dev_major = dev_major;
        self
    }

    /// Set the minor component of the device ID, describing the device on which this file
    /// resides.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn dev_minor(mut self, dev_minor: u32) -> Self {
        self.dev_minor = dev_minor;
        self
    }

    /// Set the major component of the rdev ID, describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_major(mut self, rdev_major: u32) -> Self {
        self.rdev_major = rdev_major;
        self
    }

    /// Set the minor component of the rdev ID, field describes the device that this file
    /// (inode) represents.
    ///
    /// Device IDs are comprised of a major and minor component. The major component identifies
    /// the class of device, while the minor component identifies a specific device of that class.
    pub fn rdev_minor(mut self, rdev_minor: u32) -> Self {
        self.rdev_minor = rdev_minor;
        self
    }

    /// Set the mode file type of the entry
    pub fn set_mode_file_type(mut self, file_type: ModeFileType) -> Self {
        self.mode &= !ModeFileType::MASK;
        self.mode |= u32::from(file_type);
        self
    }

    /// Write out an entry to the provided writer in SVR4 "new ascii" CPIO format.
    pub fn write_cpio<W: Write>(self, w: W, file_size: u32) -> Writer<W> {
        let header = self.into_header(file_size, None);

        Writer {
            inner: w,
            written: 0,
            file_size: file_size as u64,
            header_size: header.len(),
            header,
        }
    }

    /// Write out an entry to the provided writer in SVR4 "new crc" CPIO format.
    pub fn write_crc<W: Write>(self, w: W, file_size: u32, file_checksum: u32) -> Writer<W> {
        let header = self.into_header(file_size, Some(file_checksum));

        Writer {
            inner: w,
            written: 0,
            file_size: file_size as u64,
            header_size: header.len(),
            header,
        }
    }

    /// Build a newc header from the entry metadata.
    fn into_header(self, file_size: u32, file_checksum: Option<u32>) -> Vec<u8> {
        let mut header = Vec::with_capacity(HEADER_LEN);

        // char    c_magic[6];
        if file_checksum.is_some() {
            header.extend(MAGIC_NUMBER_NEWCRC);
        } else {
            header.extend(MAGIC_NUMBER_NEWASCII);
        }
        // char    c_ino[8];
        header.extend(format!("{:08x}", self.ino).as_bytes());
        // char    c_mode[8];
        header.extend(format!("{:08x}", self.mode).as_bytes());
        // char    c_uid[8];
        header.extend(format!("{:08x}", self.uid).as_bytes());
        // char    c_gid[8];
        header.extend(format!("{:08x}", self.gid).as_bytes());
        // char    c_nlink[8];
        header.extend(format!("{:08x}", self.nlink).as_bytes());
        // char    c_mtime[8];
        header.extend(format!("{:08x}", self.mtime).as_bytes());
        // char    c_filesize[8];
        header.extend(format!("{:08x}", file_size).as_bytes());
        // char    c_devmajor[8];
        header.extend(format!("{:08x}", self.dev_major).as_bytes());
        // char    c_devminor[8];
        header.extend(format!("{:08x}", self.dev_minor).as_bytes());
        // char    c_rdevmajor[8];
        header.extend(format!("{:08x}", self.rdev_major).as_bytes());
        // char    c_rdevminor[8];
        header.extend(format!("{:08x}", self.rdev_minor).as_bytes());
        // char    c_namesize[8];
        let name_len = self.name.len() + 1;
        header.extend(format!("{:08x}", name_len).as_bytes());
        // char    c_check[8];
        header.extend(format!("{:08x}", file_checksum.unwrap_or(0)).as_bytes());

        // append the name to the end of the header
        header.extend(self.name.as_bytes());
        header.push(0u8);

        // pad out to a multiple of 4 bytes
        if let Some(pad) = align_to_4(HEADER_LEN + name_len) {
            header.extend(pad);
        }

        header
    }
}

/// Write a stripped CPIO entry header and return a `Writer` for the file data.
///
/// The returned `Writer` enforces that exactly `file_size` bytes are written,
/// and handles 4-byte alignment padding automatically on `finish()`.
///
/// `file_index` is the 0-based index into the RPM header tag arrays.
pub fn write_stripped_cpio<W: Write>(w: W, file_index: u32, file_size: u64) -> Writer<W> {
    let mut header = Vec::with_capacity(STRIPPED_CPIO_HEADER_LEN);

    // magic: 6 bytes
    header.extend(STRIPPED_CPIO_MAGIC_NUMBER);

    // file index: 8 bytes
    header.extend(format!("{:08x}", file_index).as_bytes());

    // pad out to a multiple of 4 bytes (14 + 2)
    if let Some(pad) = align_to_4(STRIPPED_CPIO_HEADER_LEN) {
        header.extend(pad);
    }

    Writer {
        inner: w,
        written: 0,
        file_size,
        header_size: header.len(),
        header,
    }
}

impl<W: Write> Writer<W> {
    pub fn finish(mut self) -> io::Result<W> {
        self.do_finish()?;
        Ok(self.inner)
    }

    fn try_write_header(&mut self) -> io::Result<()> {
        if !self.header.is_empty() {
            self.inner.write_all(&self.header)?;
            self.header.truncate(0);
        }
        Ok(())
    }

    fn do_finish(&mut self) -> io::Result<()> {
        self.try_write_header()?;

        if self.written != self.file_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "CPIO entry expected {} bytes but only {} were written",
                    self.file_size, self.written
                ),
            ));
        }

        // Pad file data to a 4-byte boundary. The padding is based on the combined
        // header+name+data length because header+name is already padded to 4 bytes,
        // and data starts at that boundary.
        if let Some(pad) = align_to_4(self.header_size + self.file_size as usize) {
            self.inner.write_all(&pad)?;
        }
        self.inner.flush()?;

        Ok(())
    }
}

impl<W: Write> Write for Writer<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.written + buf.len() as u64 <= self.file_size {
            self.try_write_header()?;

            let n = self.inner.write(buf)?;
            self.written += n as u64;
            Ok(n)
        } else {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "trying to write more than the specified file size",
            ))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Writes a trailer entry into an archive.
pub fn trailer<W: Write>(w: W) -> io::Result<W> {
    let b = Builder::new(TRAILER_NAME).nlink(1);
    let writer = b.write_cpio(w, 0);
    writer.finish()
}

#[cfg(test)]
mod cpio_tests {
    use super::*;
    use std::io::{Cursor, copy};

    fn entry<R: Read>(reader: &Reader<R>) -> &CpioEntry {
        match reader.entry {
            RpmPayloadEntry::Cpio(ref cpio) => cpio,
            _ => unreachable!(),
        }
    }

    /// Write a zero-size directory entry and verify its metadata (name, mode, nlink)
    /// survives the roundtrip.
    #[test]
    fn test_empty_file() {
        let output = vec![];

        let b = Builder::new("./empty_dir").mode(0o040755).nlink(2);
        let writer = b.write_cpio(output, 0);
        let output = writer.finish().unwrap();

        let output = trailer(output).unwrap();

        let reader = Reader::new(output.as_slice(), &[]).unwrap();
        assert_eq!(entry(&reader).name(), "./empty_dir");
        assert_eq!(entry(&reader).file_size(), 0);
        assert_eq!(entry(&reader).mode(), 0o040755);
        assert_eq!(entry(&reader).nlink(), 2);
        let reader = Reader::new(reader.finish().unwrap(), &[]).unwrap();
        assert!(reader.is_trailer());
    }

    /// Verify that all CPIO header metadata fields (ino, mode, uid, gid, nlink,
    /// mtime, file_size) and file content survive a write-then-read roundtrip.
    #[test]
    fn test_cpio_roundtrip() {
        let data: &[u8] = b"content";
        let length = data.len() as u32;
        let mut input = Cursor::new(data);

        let b = Builder::new("./myfile")
            .ino(42)
            .mode(0o100755)
            .uid(500)
            .gid(500)
            .nlink(1)
            .mtime(1_600_000_000);
        let mut writer = b.write_cpio(vec![], length);
        copy(&mut input, &mut writer).unwrap();
        let output = trailer(writer.finish().unwrap()).unwrap();

        let mut reader = Reader::new(output.as_slice(), &[]).unwrap();
        assert_eq!(entry(&reader).name(), "./myfile");
        assert_eq!(entry(&reader).ino(), 42);
        assert_eq!(entry(&reader).mode(), 0o100755);
        assert_eq!(entry(&reader).uid(), 500);
        assert_eq!(entry(&reader).gid(), 500);
        assert_eq!(entry(&reader).nlink(), 1);
        assert_eq!(entry(&reader).mtime(), 1_600_000_000);
        assert_eq!(entry(&reader).file_size(), length);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data);
        let reader = Reader::new(reader.finish().unwrap(), &[]).unwrap();
        assert!(reader.is_trailer());
    }

    /// Write two files into a CPIO archive and read them back, verifying
    /// filenames, sizes, metadata (ino, uid, gid, mode), and contents.
    #[test]
    fn test_multi_file() {
        // Set up our input files
        let data1: &[u8] = b"Hello, World";
        let length1 = data1.len() as u32;
        let mut input1 = Cursor::new(data1);

        let data2: &[u8] = b"Hello, World 2";
        let length2 = data2.len() as u32;
        let mut input2 = Cursor::new(data2);

        // Set up our output file
        let output = vec![];

        // Set up the descriptor of our input file
        let b = Builder::new("./hello_world")
            .ino(1)
            .uid(1000)
            .gid(1000)
            .mode(0o100644);
        // and get a writer for that input file
        let mut writer = b.write_cpio(output, length1);

        // Copy the input file into our CPIO archive
        copy(&mut input1, &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Set up the descriptor of our second input file
        let b = Builder::new("./hello_world2")
            .ino(2)
            .uid(1000)
            .gid(1000)
            .mode(0o100644);
        // and get a writer for that input file
        let mut writer = b.write_cpio(output, length2);

        // Copy the second input file into our CPIO archive
        copy(&mut input2, &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Finish up by writing the trailer for the archive
        let output = trailer(output).unwrap();

        // Now read the archive back in and make sure we get the same data.
        let mut reader = Reader::new(output.as_slice(), &[]).unwrap();
        assert_eq!(entry(&reader).name(), "./hello_world");
        assert_eq!(entry(&reader).file_size(), length1);
        assert_eq!(entry(&reader).ino(), 1);
        assert_eq!(entry(&reader).uid(), 1000);
        assert_eq!(entry(&reader).gid(), 1000);
        assert_eq!(entry(&reader).mode(), 0o100644);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data1);

        let mut reader = Reader::new(reader.finish().unwrap(), &[]).unwrap();
        assert_eq!(entry(&reader).name(), "./hello_world2");
        assert_eq!(entry(&reader).file_size(), length2);
        assert_eq!(entry(&reader).ino(), 2);
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data2);

        let reader = Reader::new(reader.finish().unwrap(), &[]).unwrap();
        assert!(reader.is_trailer());
    }

    /// Verify that finishing a writer before writing the declared number of bytes
    /// returns an `InvalidInput` error.
    #[test]
    fn test_finish_with_short_write() {
        let data: &[u8] = b"short";
        let mut input = Cursor::new(data);

        // Declare 100 bytes but only write 5
        let b = Builder::new("./file");
        let mut writer = b.write_cpio(vec![], 100);
        copy(&mut input, &mut writer).unwrap();
        let err = writer.finish().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// Verify that writing more bytes than the declared file size returns an
    /// `UnexpectedEof` error.
    #[test]
    fn test_write_beyond_file_size() {
        let data: &[u8] = b"this is way too much data";
        let mut input = Cursor::new(data);

        // Declare 5 bytes but try to write 25
        let b = Builder::new("./file");
        let mut writer = b.write_cpio(vec![], 5);
        let err = copy(&mut input, &mut writer).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Write multiple files with sizes 1, 2, 3, 5, and 7 bytes to exercise all
    /// possible 4-byte alignment padding amounts (3, 2, 1, 3, 1), then read them
    /// all back and verify contents.
    #[test]
    fn test_odd_size_padding() {
        let sizes: Vec<usize> = vec![1, 2, 3, 5, 7];
        let output = vec![];
        let mut out = output;

        for (i, &size) in sizes.iter().enumerate() {
            let data = vec![b'A' + i as u8; size];
            let b = Builder::new(&format!("./file{}", i))
                .ino(i as u32 + 1)
                .mode(0o100644);
            let mut writer = b.write_cpio(out, size as u32);
            copy(&mut Cursor::new(&data), &mut writer).unwrap();
            out = writer.finish().unwrap();
        }
        out = trailer(out).unwrap();

        // Read them all back and verify contents
        let mut slice = out.as_slice();
        for (i, &size) in sizes.iter().enumerate() {
            let expected = vec![b'A' + i as u8; size];
            let mut reader = Reader::new(slice, &[]).unwrap();
            assert_eq!(entry(&reader).name(), format!("./file{}", i));
            assert_eq!(entry(&reader).file_size(), size as u32);
            let mut contents = vec![];
            copy(&mut reader, &mut contents).unwrap();
            assert_eq!(contents, expected);
            slice = reader.finish().unwrap();
        }
        let reader = Reader::new(slice, &[]).unwrap();
        assert!(reader.is_trailer());
    }
}

#[cfg(test)]
mod stripped_cpio_tests {
    use super::*;
    use std::borrow::Cow;
    use std::io::{Cursor, copy};

    fn make_file_entry(path: &str, size: usize) -> super::super::FileEntry<'static> {
        super::super::FileEntry {
            dirname: Cow::Owned(String::new()),
            basename: Cow::Owned(path.to_owned()),
            size,
            mode: crate::FileMode::regular(0o644),
            user: Cow::Borrowed("root"),
            group: Cow::Borrowed("root"),
            modified_at: crate::Timestamp(0),
            flags: crate::FileFlags::empty(),
            digest: None,
            caps: None,
            linkto: None,
            ima_signature: None,
        }
    }

    /// Write a zero-size stripped CPIO entry and verify it roundtrips correctly.
    #[test]
    fn test_empty_file() {
        let file_entries = vec![make_file_entry("empty", 0)];

        let writer = write_stripped_cpio(vec![], 0, 0);
        let output = writer.finish().unwrap();
        let output = trailer(output).unwrap();

        let reader = Reader::new(output.as_slice(), &file_entries).unwrap();
        match &reader.entry {
            RpmPayloadEntry::Stripped(idx) => assert_eq!(*idx, 0),
            _ => panic!("expected stripped entry"),
        }
        let reader = Reader::new(reader.finish().unwrap(), &file_entries).unwrap();
        assert!(reader.is_trailer());
    }

    /// Write two stripped CPIO entries and a trailer, then read them back,
    /// verifying file indices and contents survive the roundtrip.
    #[test]
    fn test_stripped_cpio_roundtrip() {
        let data1: &[u8] = b"file one";
        let len1 = data1.len() as u64;
        let data2: &[u8] = b"file two content";
        let len2 = data2.len() as u64;

        let file_entries = vec![
            make_file_entry("file1", len1 as usize),
            make_file_entry("file2", len2 as usize),
        ];

        // Write two stripped entries
        let output = vec![];
        let mut writer = write_stripped_cpio(output, 0, len1);
        copy(&mut Cursor::new(data1), &mut writer).unwrap();
        let output = writer.finish().unwrap();

        let mut writer = write_stripped_cpio(output, 1, len2);
        copy(&mut Cursor::new(data2), &mut writer).unwrap();
        let output = writer.finish().unwrap();

        // Write a standard newc trailer (same as regular CPIO archives)
        let output = trailer(output).unwrap();

        // Read them back
        let mut reader = Reader::new(output.as_slice(), &file_entries).unwrap();
        match &reader.entry {
            RpmPayloadEntry::Stripped(idx) => assert_eq!(*idx, 0),
            _ => panic!("expected stripped entry"),
        }
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data1);

        let mut reader = Reader::new(reader.finish().unwrap(), &file_entries).unwrap();
        match &reader.entry {
            RpmPayloadEntry::Stripped(idx) => assert_eq!(*idx, 1),
            _ => panic!("expected stripped entry"),
        }
        let mut contents = vec![];
        copy(&mut reader, &mut contents).unwrap();
        assert_eq!(contents, data2);

        // Verify the trailer is read correctly
        let reader = Reader::new(reader.finish().unwrap(), &file_entries).unwrap();
        assert!(reader.is_trailer());
    }

    /// Write multiple stripped entries with sizes 1, 2, 3, 5, and 7 bytes to
    /// exercise all possible 4-byte alignment padding amounts (3, 2, 1, 3, 1),
    /// then read them all back and verify contents.
    #[test]
    fn test_odd_size_padding() {
        let sizes: Vec<usize> = vec![1, 2, 3, 5, 7];
        let file_entries: Vec<_> = sizes
            .iter()
            .enumerate()
            .map(|(i, &size)| make_file_entry(&format!("file{}", i), size))
            .collect();

        let mut out = vec![];
        for (i, &size) in sizes.iter().enumerate() {
            let data = vec![b'A' + i as u8; size];
            let mut writer = write_stripped_cpio(out, i as u32, size as u64);
            copy(&mut Cursor::new(&data), &mut writer).unwrap();
            out = writer.finish().unwrap();
        }
        out = trailer(out).unwrap();

        // Read them all back and verify contents
        let mut slice = out.as_slice();
        for (i, &size) in sizes.iter().enumerate() {
            let expected = vec![b'A' + i as u8; size];
            let mut reader = Reader::new(slice, &file_entries).unwrap();
            match &reader.entry {
                RpmPayloadEntry::Stripped(idx) => assert_eq!(*idx, i as u32),
                _ => panic!("expected stripped entry"),
            }
            let mut contents = vec![];
            copy(&mut reader, &mut contents).unwrap();
            assert_eq!(contents, expected);
            slice = reader.finish().unwrap();
        }
        let reader = Reader::new(slice, &file_entries).unwrap();
        assert!(reader.is_trailer());
    }

    /// Verify that reading a stripped CPIO entry whose file index exceeds the
    /// length of the file_entries slice returns an `InvalidData` error.
    #[test]
    fn test_out_of_range_file_index() {
        let file_entries = vec![make_file_entry("only_file", 10)];

        // Write a stripped entry with index 5, but file_entries only has 1 element
        let data: &[u8] = b"irrelevant";
        let mut writer = write_stripped_cpio(vec![], 5, data.len() as u64);
        copy(&mut Cursor::new(data), &mut writer).unwrap();
        let output = writer.finish().unwrap();

        match Reader::new(output.as_slice(), &file_entries) {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidData),
            Ok(_) => panic!("expected error for out-of-range file index"),
        }
    }
}
