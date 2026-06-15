//! Access and extract RPM package payload contents (files, directories, symlinks).

use std::{fs, io, io::Read, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{constants::*, decompress_stream, errors::*};

use super::headers::*;
use super::package::{Package, PackageMetadata};
use super::payload;

#[cfg(unix)]
fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<(), Error> {
    std::os::unix::fs::symlink(original, link)?;
    Ok(())
}

#[cfg(windows)]
fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<(), Error> {
    let original = original.as_ref();

    let Ok(metadata) = original.metadata() else {
        // Windows symlink creation requires the target to exist and be accessible.
        // Relative symlinks (e.g., "../dir") or targets outside the extraction directory
        // will fail, so we silently skip them to allow extraction to continue.
        // This matches RPM's behavior where symlinks are informational metadata.
        return Ok(());
    };

    if metadata.is_dir() {
        std::os::windows::fs::symlink_dir(original, link)?;
    } else {
        std::os::windows::fs::symlink_file(original, link)?;
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn symlink(_original: &Path, _link: &Path) -> Result<(), Error> {
    Err(Error::UnsupportedSymlink)
}

impl Package {
    /// Iterate over the file contents of the package payload
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// for entry in package.files()? {
    ///     let file = entry?;
    ///     // do something with file.content
    ///     println!("{} is {} bytes", file.metadata.path().display(), file.content.len());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn files(&self) -> Result<FileIterator<'_>, Error> {
        let file_entries = self.metadata.get_file_entries()?;
        let archive = decompress_stream(
            self.metadata.get_payload_compressor()?,
            io::Cursor::new(&self.payload),
        )?;

        Ok(FileIterator {
            file_entries,
            archive,
            count: 0,
        })
    }

    /// Extract all contents of the package payload to a given directory.
    ///
    /// # Implementation
    ///
    /// The if the directory is nested, its parent directories must already exist. If the
    /// directory itself already exists, the operation will fail. All extracted files will be
    /// dropped relative to the provided directory (it will not install any files).
    ///
    /// ## Platform-specific behavior
    ///
    /// **Windows**: Symbolic links are only created if their target exists at extraction time.
    /// Symlinks with relative targets (e.g., `../dir`) or targets outside the extraction
    /// directory will be silently skipped. This is because Windows symlink creation requires
    /// the target to exist and be accessible.
    ///
    /// **Unix**: All symbolic links are created regardless of whether their target exists.
    ///
    /// # Examples
    ///
    /// ```text
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// package.extract(&package.metadata.get_name()?)?;
    /// ```
    pub fn extract(&self, dest: impl AsRef<Path>) -> Result<(), Error> {
        fs::create_dir(&dest)?;

        let dirs = self
            .metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_DIRNAMES)?;

        // pull every base directory name in the package and create the directory in advance
        for dir in &dirs {
            let dir_path = dest
                .as_ref()
                .join(Path::new(dir).strip_prefix("/").unwrap_or(dest.as_ref()));
            fs::create_dir_all(&dir_path)?;
        }

        let mut archive = decompress_stream(
            self.metadata.get_payload_compressor()?,
            io::Cursor::new(&self.payload),
        )?;
        let file_entries = self.metadata.get_file_entries()?;

        for file_entry in file_entries.iter() {
            // Ghost files are not present in the payload archive and should not be created
            if file_entry.flags.contains(FileFlags::GHOST) {
                continue;
            }

            let mut entry_reader = payload::Reader::new(&mut archive, &file_entries)?;
            if entry_reader.is_trailer() {
                return Ok(());
            }
            let entry_path = file_entry.path();
            let file_path = dest
                .as_ref()
                .join(entry_path.strip_prefix("/").unwrap_or(dest.as_ref()));
            match file_entry.file_type() {
                FileType::Dir => {
                    fs::create_dir_all(&file_path)?;
                    #[cfg(unix)]
                    {
                        let perms = fs::Permissions::from_mode(file_entry.permissions().into());
                        fs::set_permissions(&file_path, perms)?;
                    }
                }
                FileType::Regular => {
                    let mut f = fs::File::create(&file_path)?;
                    io::copy(&mut entry_reader, &mut f)?;
                    #[cfg(unix)]
                    {
                        let perms = fs::Permissions::from_mode(file_entry.permissions().into());
                        f.set_permissions(perms)?;
                    }
                }
                FileType::SymbolicLink => {
                    // broken symlinks (common for debuginfo handling) are perceived as not existing by "exists()"
                    if file_path.exists() || file_path.symlink_metadata().is_ok() {
                        fs::remove_file(&file_path)?;
                    }
                    symlink(file_entry.linkto().unwrap_or(""), &file_path)?;
                }
                // Skip file types we don't handle (e.g. device nodes, FIFOs, sockets)
                _ => {}
            }
            entry_reader.finish()?;
        }

        Ok(())
    }
}

pub struct FileIterator<'a> {
    file_entries: Vec<FileEntry<'a>>,
    archive: Box<dyn io::Read + 'a>,
    count: usize,
}

#[derive(Debug)]
pub struct RpmFile<'a> {
    pub metadata: FileEntry<'a>,
    pub content: Vec<u8>,
}

impl<'a> RpmFile<'a> {
    pub fn into_owned(self) -> RpmFile<'static> {
        RpmFile {
            metadata: self.metadata.into_owned(),
            content: self.content,
        }
    }
}

impl<'a> Iterator for FileIterator<'a> {
    type Item = Result<RpmFile<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count >= self.file_entries.len() {
            return None;
        }

        // @todo: probably safe to hand out a reference instead of cloning, just a bit more painful
        let file_entry = self.file_entries[self.count].clone();
        self.count += 1;

        // Ghost files are not in the payload archive, so return them immediately with empty content
        if file_entry.flags.contains(FileFlags::GHOST) {
            return Some(Ok(RpmFile {
                metadata: file_entry,
                content: Vec::new(),
            }));
        }

        let reader = payload::Reader::new(&mut self.archive, &self.file_entries);

        match reader {
            Ok(mut entry_reader) => {
                if entry_reader.is_trailer() {
                    return None;
                }

                let mut content = Vec::new();

                if let Err(e) = entry_reader.read_to_end(&mut content) {
                    return Some(Err(Error::Io(e)));
                }
                if let Err(e) = entry_reader.finish() {
                    return Some(Err(Error::Io(e)));
                }

                Some(Ok(RpmFile {
                    metadata: file_entry,
                    content,
                }))
            }
            Err(e) => Some(Err(Error::Io(e))),
        }
    }
}

impl ExactSizeIterator for FileIterator<'_> {
    fn len(&self) -> usize {
        self.file_entries.len() - self.count
    }
}

/// A streaming reader for an RPM package payload.
///
/// Unlike [`Package`], this avoids loading the entire payload into memory.
/// Call [`next_file`](Self::next_file) repeatedly to walk the archive one entry at a time.
///
/// Ghost files (not present in the payload archive) are returned with an empty
/// body, matching the behaviour of [`Package::files`].
///
/// # Note on iteration
///
/// `PackageReader` does not implement [`Iterator`] because each
/// [`StreamingRpmFile`] mutably borrows the reader until it is dropped or
/// [`StreamingRpmFile::finish`] is called. Use a `while let` loop:
///
/// ```
/// # #[cfg(feature = "payload")]
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::io::Read;
///
/// let mut reader = rpm::PackageReader::open(
///     "tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm",
/// )?;
/// println!("Package: {}", reader.metadata.get_nevra()?);
///
/// while let Some(mut file) = reader.next_file()? {
///     let mut buf = Vec::new();
///     file.read_to_end(&mut buf)?;
///     println!("  {} ({} bytes)", file.metadata.path().display(), buf.len());
/// }
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "payload"))]
/// # fn main() {}
/// ```
#[cfg(feature = "payload")]
pub struct PackageReader {
    /// Package headers and metadata.
    pub metadata: PackageMetadata,
    file_entries: Vec<FileEntry<'static>>,
    archive: Box<dyn Read>,
    count: usize,
}

#[cfg(feature = "payload")]
impl PackageReader {
    /// Open an RPM package file for streaming payload access.
    ///
    /// Only the package headers are read upfront; payload bytes are decompressed
    /// on demand as you call [`next_file`](Self::next_file).
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let file = fs::File::open(path.as_ref())?;
        let mut buf_reader = io::BufReader::new(file);
        let metadata = PackageMetadata::parse(&mut buf_reader)?;
        let compression = metadata.get_payload_compressor()?;
        let file_entries = metadata
            .get_file_entries()?
            .into_iter()
            .map(|e| e.into_owned())
            .collect();
        let archive = decompress_stream(compression, buf_reader)?;
        Ok(PackageReader {
            metadata,
            file_entries,
            archive,
            count: 0,
        })
    }

    /// Return the next file from the payload, or `None` at end of archive.
    ///
    /// Ghost files are returned with an empty body (they are not present in the
    /// payload archive, so no bytes are read from the stream for them).
    ///
    /// The returned [`StreamingRpmFile`] holds a mutable borrow on the underlying
    /// decompression stream. Drop it or call [`StreamingRpmFile::finish`] before
    /// calling `next_file` again.
    pub fn next_file(&mut self) -> Result<Option<StreamingRpmFile<'_>>, Error> {
        if self.count >= self.file_entries.len() {
            return Ok(None);
        }

        let metadata = self.file_entries[self.count].clone();
        self.count += 1;

        // Ghost files are not present in the payload archive; return them with
        // no reader (reads will immediately return Ok(0)).
        if metadata.flags.contains(FileFlags::GHOST) {
            return Ok(Some(StreamingRpmFile {
                metadata,
                reader: None,
            }));
        }

        let reader =
            payload::Reader::new(&mut self.archive, &self.file_entries).map_err(Error::Io)?;

        if reader.is_trailer() {
            return Ok(None);
        }

        Ok(Some(StreamingRpmFile {
            metadata,
            reader: Some(reader),
        }))
    }
}

/// A single file from an RPM package payload, readable without buffering the full archive.
///
/// Implements [`Read`](io::Read) to stream the file's bytes. Any unread bytes are
/// drained on [`drop`] (best-effort; errors are silenced). Call [`finish`](Self::finish)
/// explicitly if you need to propagate drain errors.
#[cfg(feature = "payload")]
pub struct StreamingRpmFile<'a> {
    /// Metadata for this file (path, permissions, timestamps, digest, …).
    pub metadata: FileEntry<'static>,
    // None for ghost files and after finish() is called.
    reader: Option<payload::Reader<&'a mut Box<dyn Read>>>,
}

#[cfg(feature = "payload")]
impl StreamingRpmFile<'_> {
    /// Drain any unread bytes and return any IO error encountered.
    ///
    /// This is optional — [`Drop`] drains automatically — but calling `finish`
    /// explicitly lets you propagate errors that would otherwise be silenced.
    /// After this call, further reads return `Ok(0)`.
    pub fn finish(&mut self) -> io::Result<()> {
        if let Some(reader) = self.reader.take() {
            reader.finish()?;
        }
        Ok(())
    }
}

#[cfg(feature = "payload")]
impl io::Read for StreamingRpmFile<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.reader.as_mut() {
            Some(r) => r.read(buf),
            None => Ok(0),
        }
    }
}

#[cfg(feature = "payload")]
impl Drop for StreamingRpmFile<'_> {
    fn drop(&mut self) {
        // Best-effort drain; errors are silenced. Use finish() to propagate them.
        if let Some(reader) = self.reader.take() {
            let _ = reader.finish();
        }
    }
}

/// These tests cover payload + metadata integration, but they do equality tests on
/// non-public fields / types, so they can't be actual integration tests, even though
/// they otherwise would make more sense as integration tests.
#[cfg(test)]
mod test_payload_integration {
    use crate::*;
    use pretty_assertions::assert_eq;
    use sha2::{Digest, Sha256};
    use std::borrow::Cow;
    use std::io::Read;

    pub mod pkgs {
        pub mod v4 {
            pub const RPM_EMPTY: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v4/rpm-empty-0-0.x86_64.rpm"
            );
            pub const RPM_BASIC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm"
            );

            pub mod src {
                pub const RPM_EMPTY_SRC: &str = concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/assets/SRPMS/v4/rpm-empty-0-0.src.rpm"
                );
            }
        }

        pub mod v6 {
            pub const RPM_EMPTY: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v6/rpm-empty-0-0.x86_64.rpm"
            );
            pub const RPM_BASIC: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm"
            );
            pub const RPM_FILE_ATTRS: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v6/rpm-file-attrs-1.0-1.noarch.rpm"
            );
            pub const RPM_FILE_TYPES: &str = concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/assets/RPMS/v6/rpm-file-types-1.0-1.noarch.rpm"
            );

            pub mod compressed {
                pub const RPM_BASIC_GZIP: &str = concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/assets/RPMS/v6/gzip/rpm-basic-2.3.4-5.el9.noarch.rpm"
                );
                pub const RPM_BASIC_ZSTD: &str = concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/assets/RPMS/v6/zstd/rpm-basic-2.3.4-5.el9.noarch.rpm"
                );
                pub const RPM_BASIC_XZ: &str = concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/assets/RPMS/v6/xz/rpm-basic-2.3.4-5.el9.noarch.rpm"
                );
            }

            pub mod src {
                pub const RPM_EMPTY_SRC: &str = concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/assets/SRPMS/v6/rpm-empty-0-0.src.rpm"
                );
            }
        }
    }

    /// SOURCE_DATE_EPOCH used for building fixture packages (from build_packages.sh)
    /// This timestamp is April 9, 2023 19:29:19 UTC
    pub const FIXTURE_SOURCE_DATE: u32 = 1681068559;

    /// Helper to calculate SHA256 digest of content and return as hex string
    fn calculate_sha256(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    /// Test that Package::files() correctly extracts file contents from an
    /// uncompressed RPM package.
    #[test]
    fn test_files_v6_uncompressed() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::RPM_BASIC)?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from a
    /// gzip-compressed RPM package.
    #[test]
    #[cfg(feature = "gzip-compression")]
    fn test_files_v6_gzip() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::compressed::RPM_BASIC_GZIP)?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from a
    /// zstd-compressed RPM package.
    #[test]
    #[cfg(feature = "zstd-compression")]
    fn test_files_v6_zstd() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::compressed::RPM_BASIC_ZSTD)?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from an
    /// xz-compressed RPM package.
    #[test]
    #[cfg(feature = "xz-compression")]
    fn test_files_v6_xz() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::compressed::RPM_BASIC_XZ)?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from a v4 RPM package,
    /// verifying that v4 and v6 formats produce identical results.
    #[test]
    fn test_files_v4_uncompressed() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v4::RPM_BASIC)?;
        test_basic_package_files(&package)
    }

    /// Shared test logic for verifying file extraction across all compression types.
    #[track_caller]
    fn test_basic_package_files(package: &Package) -> Result<(), Box<dyn std::error::Error>> {
        // Verify all three file APIs return consistent data and get files for content verification
        let files = assert_file_apis_consistent(package)?;

        // Extract package and verify extracted files match files() API results
        let temp_dir = tempfile::tempdir()?;
        let extract_path = temp_dir.path().join("rpm-basic");
        package.extract(&extract_path)?;
        verify_extracted_files(&extract_path, &files)?;

        // Load expected file contents from source files
        let expected_config = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/example_config.toml"
        ));
        let expected_script = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/multiplication_tables.py"
        ));
        let expected_hello = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/module/hello.py"
        ));
        let expected_xml = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/example_data.xml"
        ));
        let expected_init = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/module/__init__.py"
        ));

        // File 0: /etc/rpm-basic/example_config.toml
        assert_eq!(files[0].content, expected_config);
        assert_eq!(
            files[0].metadata,
            FileEntry {
                dirname: Cow::from("/etc/rpm-basic/"),
                basename: Cow::from("example_config.toml"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[0].content.len(),
                flags: FileFlags::CONFIG,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[0].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 1: /usr/bin/rpm-basic
        assert_eq!(files[1].content, expected_script);
        assert_eq!(
            files[1].metadata,
            FileEntry {
                dirname: Cow::from("/usr/bin/"),
                basename: Cow::from("rpm-basic"),
                mode: FileMode::regular(0o0644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[1].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[1].content)),
                    algo: DigestAlgorithm::Sha2_256
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 2: /usr/lib/rpm-basic (directory)
        assert_eq!(
            files[2].metadata,
            FileEntry {
                dirname: Cow::from("/usr/lib/"),
                basename: Cow::from("rpm-basic"),
                mode: FileMode::dir(0o0755),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[2].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 3: /usr/lib/rpm-basic/module (directory)
        assert_eq!(
            files[3].metadata,
            FileEntry {
                dirname: Cow::from("/usr/lib/rpm-basic/"),
                basename: Cow::from("module"),
                mode: FileMode::dir(0o0755),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[3].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 4: /usr/lib/rpm-basic/module/__init__.py
        assert_eq!(files[4].content, expected_init);
        assert_eq!(
            files[4].metadata,
            FileEntry {
                dirname: Cow::from("/usr/lib/rpm-basic/module/"),
                basename: Cow::from("__init__.py"),
                mode: FileMode::regular(0o0644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[4].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[4].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 5: /usr/lib/rpm-basic/module/hello.py
        assert_eq!(files[5].content, expected_hello);
        assert_eq!(
            files[5].metadata,
            FileEntry {
                dirname: Cow::from("/usr/lib/rpm-basic/module/"),
                basename: Cow::from("hello.py"),
                mode: FileMode::regular(0o0644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[5].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[5].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 6: /usr/share/doc/rpm-basic (directory)
        assert_eq!(
            files[6].metadata,
            FileEntry {
                dirname: Cow::from("/usr/share/doc/"),
                basename: Cow::from("rpm-basic"),
                mode: FileMode::dir(0o755),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[6].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 7: /usr/share/doc/rpm-basic/README
        // README is generated in spec file: echo "No more half measures, Walter." > README
        assert_eq!(files[7].content, b"No more half measures, Walter.\n");
        assert_eq!(
            files[7].metadata,
            FileEntry {
                dirname: Cow::from("/usr/share/doc/rpm-basic/"),
                basename: Cow::from("README"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[7].content.len(),
                flags: FileFlags::DOC,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[7].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 8: /usr/share/rpm-basic/example_data.xml
        assert_eq!(files[8].content, expected_xml);
        assert_eq!(
            files[8].metadata,
            FileEntry {
                dirname: Cow::from("/usr/share/rpm-basic/"),
                basename: Cow::from("example_data.xml"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[8].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[8].content)),
                    algo: DigestAlgorithm::Sha2_256
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 9: /var/log/rpm-basic/basic.log (ghost file - not in payload)
        assert_eq!(
            files[9].metadata,
            FileEntry {
                dirname: Cow::from("/var/log/rpm-basic/"),
                basename: Cow::from("basic.log"),
                mode: FileMode::regular(0),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[9].content.len(),
                flags: FileFlags::GHOST,
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 10: /var/tmp/rpm-basic (directory after ghost file)
        assert_eq!(
            files[10].metadata,
            FileEntry {
                dirname: Cow::from("/var/tmp/"),
                basename: Cow::from("rpm-basic"),
                mode: FileMode::dir(0o0755),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[10].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        Ok(())
    }

    /// Helper function to verify that extracted files on disk match the files from files() API.
    #[track_caller]
    fn verify_extracted_files(
        extract_path: &std::path::Path,
        files: &[RpmFile],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for file in files {
            let entry_path = file.metadata.path();
            let file_path = extract_path.join(entry_path.strip_prefix("/").unwrap_or(&entry_path));

            if file.metadata.flags().contains(FileFlags::GHOST) {
                // Ghost files should NOT be created during extraction
                assert!(
                    !file_path.exists(),
                    "Ghost file {:?} should NOT exist on disk",
                    entry_path
                );
            } else {
                match file.metadata.file_type() {
                    FileType::Dir => {
                        assert!(
                            file_path.exists() && file_path.is_dir(),
                            "Directory {:?} should exist",
                            entry_path
                        );
                    }
                    FileType::Regular => {
                        assert!(
                            file_path.exists() && file_path.is_file(),
                            "Regular file {:?} should exist",
                            entry_path
                        );
                        let disk_content = std::fs::read(&file_path)?;
                        assert_eq!(
                            disk_content, file.content,
                            "Content mismatch for {:?}",
                            entry_path
                        );
                    }
                    FileType::SymbolicLink => {
                        // On Unix, verify symlinks are created properly
                        #[cfg(unix)]
                        {
                            assert!(
                                file_path.exists() || file_path.symlink_metadata().is_ok(),
                                "Symlink {:?} should exist",
                                entry_path
                            );
                            let metadata = file_path.symlink_metadata()?;
                            assert!(
                                metadata.file_type().is_symlink(),
                                "Path {:?} should be a symlink",
                                entry_path
                            );
                        }
                        // On Windows, symlinks are only created if their target exists.
                        // Relative symlinks or symlinks to paths outside the extraction
                        // directory are silently skipped, so we don't verify them.
                    }
                    _ => {
                        // Other file types (device nodes, FIFOs, etc.) are not extracted
                    }
                }
            }
        }
        Ok(())
    }

    /// Helper function to verify that files(), get_file_entries(), and get_file_paths()
    /// all return consistent data in the same order. Returns the files Vec for further assertions.
    #[track_caller]
    fn assert_file_apis_consistent(
        package: &Package,
    ) -> Result<Vec<RpmFile<'_>>, Box<dyn std::error::Error>> {
        let files: Vec<RpmFile> = package.files()?.collect::<Result<Vec<_>, _>>()?;
        let metadata_entries = package.metadata.get_file_entries()?;
        let file_paths = package.metadata.get_file_paths()?;

        assert_eq!(
            files.len(),
            metadata_entries.len(),
            "files() should return {} entries (matching get_file_entries()), but got {}",
            metadata_entries.len(),
            files.len()
        );
        assert_eq!(
            file_paths.len(),
            metadata_entries.len(),
            "get_file_paths() should return {} entries (matching get_file_entries()), but got {}",
            metadata_entries.len(),
            file_paths.len()
        );

        // Verify that all three APIs return data in the same order
        for (i, ((file, meta), path)) in files
            .iter()
            .zip(metadata_entries.iter())
            .zip(file_paths.iter())
            .enumerate()
        {
            assert_eq!(
                file.metadata.path(),
                meta.path(),
                "Path mismatch at index {}: files() has {:?} but get_file_entries() has {:?}",
                i,
                file.metadata.path(),
                meta.path()
            );
            assert_eq!(
                file.metadata.path(),
                *path,
                "Path mismatch at index {}: files() has {:?} but get_file_paths() has {:?}",
                i,
                file.metadata.path(),
                path
            );
            assert_eq!(
                file.metadata, *meta,
                "Full metadata mismatch at index {}: files() differs from get_file_entries()",
                i
            );
        }

        Ok(files)
    }

    /// Test file extraction for rpm-file-attrs package, verifying various file
    /// attributes (symlinks, different owners, capabilities, file flags).
    #[test]
    fn test_file_attrs() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::RPM_FILE_ATTRS)?;

        // Verify all three file APIs return consistent data and get files for content verification
        let files = assert_file_apis_consistent(&package)?;
        assert_eq!(files.len(), 26);

        // Extract package and verify extracted files match files() API results
        let temp_dir = tempfile::tempdir()?;
        let extract_path = temp_dir.path().join("rpm-file-attrs");
        package.extract(&extract_path)?;
        verify_extracted_files(&extract_path, &files)?;

        // File 0: /opt/rpm-file-attrs (directory)
        assert_eq!(
            files[0].metadata,
            FileEntry {
                dirname: Cow::from("/opt/"),
                basename: Cow::from("rpm-file-attrs"),
                mode: FileMode::dir(0o755),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[0].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 1: /opt/rpm-file-attrs/artifact
        assert_eq!(files[1].content, b"artifact\n");
        assert_eq!(
            files[1].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("artifact"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[1].content.len(),
                flags: FileFlags::ARTIFACT,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[1].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 2: /opt/rpm-file-attrs/config
        assert_eq!(files[2].content, b"config\n");
        assert_eq!(
            files[2].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("config"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[2].content.len(),
                flags: FileFlags::CONFIG,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[2].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 3: /opt/rpm-file-attrs/config_noreplace
        assert_eq!(files[3].content, b"config_noreplace\n");
        assert_eq!(
            files[3].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("config_noreplace"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[3].content.len(),
                flags: FileFlags::CONFIG | FileFlags::NOREPLACE,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[3].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 4: /opt/rpm-file-attrs/different-owner-and-group
        assert_eq!(files[4].content, b"different-owner-and-group\n");
        assert_eq!(
            files[4].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("different-owner-and-group"),
                mode: FileMode::regular(0o655),
                user: Cow::from("jane"),
                group: Cow::from("bob"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[4].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[4].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 5: /opt/rpm-file-attrs/dir (directory)
        assert_eq!(
            files[5].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("dir"),
                mode: FileMode::dir(0o755),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[5].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 6: /opt/rpm-file-attrs/dir/normal
        assert_eq!(files[6].content, b"file-in-a-dir\n");
        assert_eq!(
            files[6].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/dir/"),
                basename: Cow::from("normal"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[6].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[6].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 7: /opt/rpm-file-attrs/doc
        assert_eq!(files[7].content, b"doc\n");
        assert_eq!(
            files[7].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("doc"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 4,
                flags: FileFlags::DOC,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[7].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 8: /opt/rpm-file-attrs/empty_caps
        assert_eq!(files[8].content, b"empty_caps\n");
        assert_eq!(
            files[8].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("empty_caps"),
                mode: FileMode::regular(0o655),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 11,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[8].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("=")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 9: /opt/rpm-file-attrs/empty_caps2
        assert_eq!(files[9].content, b"empty_caps2\n");
        assert_eq!(
            files[9].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("empty_caps2"),
                mode: FileMode::regular(0o655),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 12,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[9].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("=")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 10: /opt/rpm-file-attrs/example-binary
        assert_eq!(files[10].content, b"example-binary\n");
        assert_eq!(
            files[10].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("example-binary"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 15,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[10].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 11: /opt/rpm-file-attrs/example-confidential-file
        assert_eq!(files[11].content, b"example-confidential-file\n");
        assert_eq!(
            files[11].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("example-confidential-file"),
                mode: FileMode::regular(0o600),
                user: Cow::from("jane"),
                group: Cow::from("jane"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 26,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[11].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 12: /opt/rpm-file-attrs/ghost (ghost file - not in payload)
        assert_eq!(
            files[12].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("ghost"),
                mode: FileMode::regular(0),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 0,
                flags: FileFlags::GHOST,
                digest: None,
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[12].content.len(), 0);

        // File 13: /opt/rpm-file-attrs/license
        assert_eq!(files[13].content, b"license\n");
        assert_eq!(
            files[13].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("license"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 8,
                flags: FileFlags::LICENSE,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[13].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 14: /opt/rpm-file-attrs/missingok
        assert_eq!(files[14].content, b"missingok\n");
        assert_eq!(
            files[14].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("missingok"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 10,
                flags: FileFlags::MISSINGOK,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[14].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 15: /opt/rpm-file-attrs/normal
        assert_eq!(files[15].content, b"normal\n");
        assert_eq!(
            files[15].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("normal"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 7,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[15].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 16: /opt/rpm-file-attrs/readme
        assert_eq!(files[16].content, b"readme\n");
        assert_eq!(
            files[16].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("readme"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 7,
                flags: FileFlags::README,
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[16].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 17: /opt/rpm-file-attrs/symlink (symlink to normal)
        assert_eq!(files[17].content, b"normal");
        assert_eq!(
            files[17].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("symlink"),
                mode: FileMode::symbolic_link(0o777),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 6,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some(Cow::from("")),
                linkto: Some(Cow::from("normal")),
                ima_signature: None,
            }
        );
        assert_eq!(files[17].content, b"normal");
        assert_eq!(files[17].content.len(), 6);
        assert_eq!(files[17].metadata.size, 6);

        // File 18: /opt/rpm-file-attrs/symlink_dir (directory)
        assert_eq!(
            files[18].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("symlink_dir"),
                mode: FileMode::dir(0o755),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[18].content.len(), 0);

        // File 19: /opt/rpm-file-attrs/symlink_dir/dir (symlink to ../dir)
        assert_eq!(files[19].content, b"../dir");
        assert_eq!(
            files[19].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/symlink_dir/"),
                basename: Cow::from("dir"),
                mode: FileMode::symbolic_link(0o777),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 6,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some(Cow::from("")),
                linkto: Some(Cow::from("../dir")),
                ima_signature: None,
            }
        );
        assert_eq!(files[19].content, b"../dir");
        assert_eq!(files[19].content.len(), 6);
        assert_eq!(files[19].metadata.size, 6);

        // File 20: /opt/rpm-file-attrs/verify_all
        assert_eq!(files[20].content, b"verify_all\n");
        assert_eq!(
            files[20].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("verify_all"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 11,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[20].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 21: /opt/rpm-file-attrs/verify_none
        assert_eq!(files[21].content, b"verify_none\n");
        assert_eq!(
            files[21].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("verify_none"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 12,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[21].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 22: /opt/rpm-file-attrs/verify_not
        assert_eq!(files[22].content, b"verify_not\n");
        assert_eq!(
            files[22].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("verify_not"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 11,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[22].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 23: /opt/rpm-file-attrs/verify_some
        assert_eq!(files[23].content, b"verify_some\n");
        assert_eq!(
            files[23].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("verify_some"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 12,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[23].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 24: /opt/rpm-file-attrs/with_caps
        assert_eq!(files[24].content, b"with_caps\n");
        assert_eq!(
            files[24].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-attrs/"),
                basename: Cow::from("with_caps"),
                mode: FileMode::regular(0o655),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 10,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[24].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("cap_sys_ptrace,cap_sys_admin=ep")),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 25: /usr/lib/sysusers.d/rpm-file-attrs.conf
        let expected_sysusers = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/rpm-file-attrs-sysusers.conf"
        ));
        assert_eq!(files[25].content, expected_sysusers);
        assert_eq!(
            files[25].metadata,
            FileEntry {
                dirname: Cow::from("/usr/lib/sysusers.d/"),
                basename: Cow::from("rpm-file-attrs.conf"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: expected_sysusers.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[25].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some(Cow::from("")),
                linkto: None,
                ima_signature: None,
            }
        );
        Ok(())
    }

    /// Test file extraction for rpm-file-types package, focusing on unusual file
    /// names (spaces, special characters) and binary content (PNG image).
    #[test]
    fn test_file_types() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::RPM_FILE_TYPES)?;

        // Verify all three file APIs return consistent data and get files for content verification
        let files = assert_file_apis_consistent(&package)?;
        assert_eq!(files.len(), 3);

        // Extract package and verify extracted files match files() API results
        let temp_dir = tempfile::tempdir()?;
        let extract_path = temp_dir.path().join("rpm-file-types");
        package.extract(&extract_path)?;
        verify_extracted_files(&extract_path, &files)?;

        // Load expected file contents from source files
        let expected_empty = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/empty_file"
        ));
        let expected_spaces = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/file with spaces & special (chars).txt"
        ));
        let expected_png = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/rpm-rs-logo.png"
        ));

        // File 0: /opt/rpm-file-types/empty_file
        assert_eq!(
            files[0].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-types/"),
                basename: Cow::from("empty_file"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 0,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[0].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[0].content, expected_empty);
        assert_eq!(files[0].content.len(), 0);
        assert_eq!(files[0].metadata.size, 0);

        // File 1: /opt/rpm-file-types/file with spaces & special (chars).txt
        assert_eq!(
            files[1].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-types/"),
                basename: Cow::from("file with spaces & special (chars).txt"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 31,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[1].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[1].content, expected_spaces);
        assert_eq!(files[1].content.len(), expected_spaces.len());
        assert_eq!(files[1].metadata.size, expected_spaces.len());
        assert_eq!(files[1].content.len(), 31);

        // File 2: /opt/rpm-file-types/rpm-rs-logo.png (binary content)
        assert_eq!(
            files[2].metadata,
            FileEntry {
                dirname: Cow::from("/opt/rpm-file-types/"),
                basename: Cow::from("rpm-rs-logo.png"),
                mode: FileMode::regular(0o644),
                user: Cow::from("root"),
                group: Cow::from("root"),
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 2017,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: Cow::from(calculate_sha256(&files[2].content)),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[2].content, expected_png);
        assert_eq!(files[2].content.len(), expected_png.len());
        assert_eq!(files[2].metadata.size, expected_png.len());
        assert_eq!(files[2].content.len(), 2017);
        // Verify PNG magic bytes
        assert_eq!(&files[2].content[0..8], b"\x89PNG\r\n\x1a\n");

        Ok(())
    }

    /// Test file extraction for rpm-empty package (no files).
    #[test]
    fn test_empty_package() -> Result<(), Box<dyn std::error::Error>> {
        let v4 = Package::open(pkgs::v4::RPM_EMPTY)?;
        let v6 = Package::open(pkgs::v6::RPM_EMPTY)?;

        for package in [&v4, &v6] {
            // Verify all three file APIs return consistent data
            let files = assert_file_apis_consistent(package)?;
            assert_eq!(files.len(), 0);
        }

        Ok(())
    }

    /// Test file extraction for rpm-empty source package (contains rpm-empty.spec).
    #[test]
    fn test_empty_source_package() -> Result<(), Box<dyn std::error::Error>> {
        let v4 = Package::open(pkgs::v4::src::RPM_EMPTY_SRC)?;
        let v6 = Package::open(pkgs::v6::src::RPM_EMPTY_SRC)?;

        for package in [&v4, &v6] {
            // Verify all three file APIs return consistent data and get files for content verification
            let files = assert_file_apis_consistent(package)?;
            assert_eq!(files.len(), 1);

            // File 0: rpm-empty.spec
            assert_eq!(
                files[0].metadata,
                FileEntry {
                    dirname: Cow::from(""),
                    basename: Cow::from("rpm-empty.spec"),
                    mode: FileMode::regular(0o644),
                    user: Cow::from("root"),
                    group: Cow::from("root"),
                    modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                    size: 162,
                    flags: FileFlags::SPECFILE,
                    digest: Some(FileDigest {
                        digest: Cow::from(calculate_sha256(&files[0].content)),
                        algo: DigestAlgorithm::Sha2_256,
                    }),
                    caps: None,
                    linkto: None,
                    ima_signature: None,
                }
            );
            assert_eq!(files[0].metadata.size, 162);
            assert_eq!(files[0].content.len(), 162);

            // Verify spec file content contains expected fields
            let spec_content = std::str::from_utf8(&files[0].content)?;
            assert!(spec_content.contains("Name:           rpm-empty"));
            assert!(spec_content.contains("Version:        0"));
            assert!(spec_content.contains("License:        LGPL"));
        }

        Ok(())
    }

    /// Test that PackageReader produces the same files (including ghosts) as
    /// Package::files(), without loading the payload into memory upfront.
    #[test]
    fn test_package_reader_matches_files_api() -> Result<(), Box<dyn std::error::Error>> {
        for path in [pkgs::v4::RPM_BASIC, pkgs::v6::RPM_BASIC] {
            let package = Package::open(path)?;
            let expected: Vec<RpmFile> = package.files()?.collect::<Result<_, _>>()?;

            let mut reader = PackageReader::open(path)?;
            let mut actual = Vec::new();

            while let Some(mut file) = reader.next_file()? {
                let mut content = Vec::new();
                file.read_to_end(&mut content)?;
                actual.push((file.metadata.path().to_owned(), content));
            }

            assert_eq!(
                actual.len(),
                expected.len(),
                "file count mismatch for {path}"
            );
            for (i, ((actual_path, actual_content), expected_file)) in
                actual.iter().zip(&expected).enumerate()
            {
                assert_eq!(
                    actual_path,
                    &expected_file.metadata.path(),
                    "path mismatch at index {i}"
                );
                assert_eq!(
                    actual_content,
                    &expected_file.content,
                    "content mismatch for {}",
                    actual_path.display()
                );
            }
        }
        Ok(())
    }

    /// Test that dropping a StreamingRpmFile before fully reading it still allows
    /// reading the subsequent file correctly (unread bytes are drained on drop).
    #[test]
    fn test_package_reader_partial_read_then_drop() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::RPM_BASIC)?;
        let expected: Vec<RpmFile> = package.files()?.collect::<Result<_, _>>()?;

        let mut reader = PackageReader::open(pkgs::v6::RPM_BASIC)?;

        // Drop the first file without reading it — drain must happen automatically.
        let _ = reader.next_file()?.expect("first file");

        // The second file must still be readable and correct.
        let mut second = reader.next_file()?.expect("second file");
        let mut content = Vec::new();
        second.read_to_end(&mut content)?;

        assert_eq!(content, expected[1].content);
        Ok(())
    }

    /// Test that StreamingRpmFile::finish() propagates drain errors and that
    /// ghost files (reader == None) are handled correctly.
    #[test]
    fn test_package_reader_finish_and_ghost() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open(pkgs::v6::RPM_BASIC)?;
        let expected: Vec<RpmFile> = package.files()?.collect::<Result<_, _>>()?;
        let ghost_count = expected
            .iter()
            .filter(|f| f.metadata.flags().contains(FileFlags::GHOST))
            .count();
        assert!(ghost_count > 0, "fixture must have at least one ghost file");

        let mut reader = PackageReader::open(pkgs::v6::RPM_BASIC)?;
        let mut ghost_seen = 0usize;
        let mut i = 0usize;

        while let Some(mut file) = reader.next_file()? {
            if file.metadata.flags().contains(FileFlags::GHOST) {
                // Ghost files: read returns 0 bytes immediately.
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                assert!(buf.is_empty(), "ghost file must have empty content");
                // Explicit finish on a ghost file must be a no-op.
                file.finish()?;
                ghost_seen += 1;
            } else {
                // Use explicit finish() instead of drop for non-ghost files.
                let mut buf = Vec::new();
                file.read_to_end(&mut buf)?;
                assert_eq!(buf, expected[i].content);
                file.finish()?;
            }
            i += 1;
        }

        assert_eq!(ghost_seen, ghost_count);
        Ok(())
    }
}
