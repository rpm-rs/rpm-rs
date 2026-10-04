//! Shared RPM payload construction and derived header metadata.

use super::*;
use sha2::Digest;

/// Build an RPM payload without supplying ordinary package metadata.
///
/// File additions use the same staging rules as [`PackageBuilder`]. The caller
/// supplies the remaining header tags separately when assembling a package.
#[derive(Default)]
pub struct PayloadBuilder {
    inner: FileStaging,
    consumed: bool,
}

impl PayloadBuilder {
    /// Create a payload builder with RPM v4 defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Select the RPM format, compressor, timestamps, and digest algorithm.
    pub fn using_config(&mut self, config: BuildConfig) -> &mut Self {
        self.inner.config = config;
        self
    }

    /// Set default ownership and permissions for subsequently staged files.
    pub fn default_file_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) -> &mut Self {
        self.inner.set_default_file_attrs(permissions, user, group);
        self
    }

    /// Set default ownership and permissions for subsequently staged directories.
    pub fn default_dir_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) -> &mut Self {
        self.inner.set_default_dir_attrs(permissions, user, group);
        self
    }

    /// Stage an on-disk regular file.
    pub fn with_file(
        &mut self,
        source: impl AsRef<Path>,
        options: impl Into<FileOptions>,
    ) -> Result<&mut Self, Error> {
        self.inner.with_file(source, options)?;
        Ok(self)
    }

    /// Stage an in-memory regular file.
    pub fn with_file_contents(
        &mut self,
        content: impl Into<Vec<u8>>,
        options: impl Into<FileOptions>,
    ) -> Result<&mut Self, Error> {
        self.inner.with_file_contents(content, options)?;
        Ok(self)
    }

    /// Stage an empty directory entry.
    pub fn with_dir_entry(&mut self, options: impl Into<FileOptions>) -> Result<&mut Self, Error> {
        self.inner.with_dir_entry(options)?;
        Ok(self)
    }

    /// Stage a symbolic-link entry.
    pub fn with_symlink(&mut self, options: impl Into<FileOptions>) -> Result<&mut Self, Error> {
        self.inner.with_symlink(options)?;
        Ok(self)
    }

    /// Stage a ghost entry, which has no archive member.
    pub fn with_ghost(&mut self, options: impl Into<FileOptions>) -> Result<&mut Self, Error> {
        self.inner.with_ghost(options)?;
        Ok(self)
    }

    /// Recursively stage a directory tree with the usual builder customization.
    pub fn with_dir<F>(
        &mut self,
        source_dir: impl AsRef<Path>,
        dest_prefix: impl AsRef<str>,
        customize: F,
    ) -> Result<&mut Self, Error>
    where
        F: Fn(FileOptionsBuilder) -> FileOptionsBuilder,
    {
        self.inner.with_dir(source_dir, dest_prefix, customize)?;
        Ok(self)
    }

    /// Build the payload once, leaving all unrelated header tags to the caller.
    pub fn build(&mut self) -> Result<PayloadBuildResult, Error> {
        if self.consumed {
            return Err(Error::BuilderReuse);
        }
        self.consumed = true;
        self.inner.prepare_payload()
    }
}

impl PayloadBuildResult {
    /// Return the resolved files in RPM header order.
    pub fn files(&self) -> &[BuiltFile] {
        &self.files
    }

    /// Return groups of regular file paths sharing a package device and inode.
    pub fn hardlinks(&self) -> Vec<Vec<String>> {
        let mut groups = BTreeMap::<(u32, u32), Vec<String>>::new();
        for file in &self.files {
            if file.mode.file_type() == FileType::Regular && !file.flags.contains(FileFlags::GHOST)
            {
                groups
                    .entry((file.device, file.inode))
                    .or_default()
                    .push(file.path.clone());
            }
        }
        groups
            .into_values()
            .filter(|group| group.len() > 1)
            .collect()
    }

    /// Generate file tags from the resolved staging options and payload.
    ///
    /// This includes editable values such as modes, mtimes, owners, and flags
    /// selected before building. A `FILELANGS` array is emitted when at least
    /// one file has an explicit language; otherwise it remains caller-owned.
    /// Other positional arrays remain under the caller's control.
    pub fn file_header_entries(&self) -> Vec<HeaderEntry> {
        let mut entries = Vec::new();
        let large = self.format != RpmFormat::V4 || self.installed_size > u32::MAX as u64;
        if large {
            entries.push(HeaderEntry::new(
                IndexTag::RPMTAG_LONGSIZE as u32,
                IndexData::Int64(vec![self.installed_size]),
            ));
        } else {
            entries.push(HeaderEntry::new(
                IndexTag::RPMTAG_SIZE as u32,
                IndexData::Int32(vec![self.installed_size as u32]),
            ));
        }
        if !self.files.is_empty() {
            let mut directories = BTreeSet::new();
            for file in &self.files {
                directories.insert(file.directory.clone());
            }
            let directories = directories.into_iter().collect::<Vec<_>>();
            let values = |f: fn(&BuiltFile) -> u32| self.files.iter().map(f).collect::<Vec<_>>();
            let strings =
                |f: fn(&BuiltFile) -> String| self.files.iter().map(f).collect::<Vec<_>>();
            entries.push(HeaderEntry::new(
                if large {
                    IndexTag::RPMTAG_LONGFILESIZES
                } else {
                    IndexTag::RPMTAG_FILESIZES
                } as u32,
                if large {
                    IndexData::Int64(self.files.iter().map(|file| file.size).collect())
                } else {
                    IndexData::Int32(values(|file| file.size as u32))
                },
            ));
            entries.extend([
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEMODES as u32,
                    IndexData::Int16(self.files.iter().map(|file| file.mode.raw_mode()).collect()),
                ),
                // st_rdev only applies to device nodes, which this builder rejects.
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILERDEVS as u32,
                    IndexData::Int16(vec![0; self.files.len()]),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEMTIMES as u32,
                    IndexData::Int32(values(|file| file.modified_at.into())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEDIGESTS as u32,
                    IndexData::StringArray(strings(|file| file.digest.clone())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILELINKTOS as u32,
                    IndexData::StringArray(strings(|file| file.linkto.clone())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEFLAGS as u32,
                    IndexData::Int32(values(|file| file.flags.bits())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEUSERNAME as u32,
                    IndexData::StringArray(strings(|file| file.user.clone())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEGROUPNAME as u32,
                    IndexData::StringArray(strings(|file| file.group.clone())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEDEVICES as u32,
                    IndexData::Int32(values(|file| file.device)),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEINODES as u32,
                    IndexData::Int32(values(|file| file.inode)),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_DIRINDEXES as u32,
                    IndexData::Int32(
                        self.files
                            .iter()
                            .map(|file| {
                                directories
                                    .binary_search(&file.directory)
                                    .expect("directory exists")
                                    as u32
                            })
                            .collect(),
                    ),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_FILEVERIFYFLAGS as u32,
                    IndexData::Int32(values(|file| file.verify_flags.bits())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_BASENAMES as u32,
                    IndexData::StringArray(strings(|file| file.basename.clone())),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_DIRNAMES as u32,
                    IndexData::StringArray(directories),
                ),
            ]);
            if self.files.iter().any(|file| file.caps.is_some()) {
                entries.push(HeaderEntry::new(
                    IndexTag::RPMTAG_FILECAPS as u32,
                    IndexData::StringArray(
                        self.files
                            .iter()
                            .map(|file| {
                                file.caps
                                    .as_ref()
                                    .map_or_else(String::new, ToString::to_string)
                            })
                            .collect(),
                    ),
                ));
            }
            if self.files.iter().any(|file| file.language.is_some()) {
                entries.push(HeaderEntry::new(
                    IndexTag::RPMTAG_FILELANGS as u32,
                    IndexData::StringArray(
                        self.files
                            .iter()
                            .map(|file| file.language.clone().unwrap_or_default())
                            .collect(),
                    ),
                ));
            }
        }
        entries.push(HeaderEntry::new(
            IndexTag::RPMTAG_FILEDIGESTALGO as u32,
            IndexData::Int32(vec![self.file_digest_algorithm as u32]),
        ));
        entries.sort_by_key(|entry| entry.tag);
        entries
    }

    /// Generate payload digest, compressor, and format tags from the built bytes.
    pub fn payload_header_entries(&self) -> Vec<HeaderEntry> {
        // RPM uses string arrays for the older SHA-256 payload tags, but plain
        // strings for the newer SHA-512 and SHA3-256 tags.
        let mut entries = vec![
            HeaderEntry::new(
                IndexTag::RPMTAG_PAYLOADSHA256 as u32,
                IndexData::StringArray(vec![self.compressed_digests.sha256.clone()]),
            ),
            HeaderEntry::new(
                IndexTag::RPMTAG_PAYLOADSHA256ALT as u32,
                IndexData::StringArray(vec![self.archive_digests.sha256.clone()]),
            ),
            // rpmbuild writes PAYLOADFLAGS even for an uncompressed payload.
            HeaderEntry::new(
                IndexTag::RPMTAG_PAYLOADFLAGS as u32,
                IndexData::StringTag(self.compression_flags.clone()),
            ),
        ];
        if self.format == RpmFormat::V4 {
            // PAYLOADSHA256ALGO is obsolete and is omitted from v6 packages.
            entries.push(HeaderEntry::new(
                IndexTag::RPMTAG_PAYLOADSHA256ALGO as u32,
                IndexData::Int32(vec![DigestAlgorithm::Sha2_256 as u32]),
            ));
        } else {
            entries.extend([
                HeaderEntry::new(IndexTag::RPMTAG_RPMFORMAT as u32, IndexData::Int32(vec![6])),
                HeaderEntry::new(
                    IndexTag::RPMTAG_PAYLOADSIZE as u32,
                    IndexData::Int64(vec![self.compressed_payload.len() as u64]),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_PAYLOADSIZEALT as u32,
                    IndexData::Int64(vec![self.archive_size]),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_PAYLOAD_SHA3_256 as u32,
                    IndexData::StringTag(self.compressed_digests.sha3_256.clone()),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_PAYLOAD_SHA3_256_ALT as u32,
                    IndexData::StringTag(self.archive_digests.sha3_256.clone()),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_PAYLOAD_SHA512 as u32,
                    IndexData::StringTag(self.compressed_digests.sha512.clone()),
                ),
                HeaderEntry::new(
                    IndexTag::RPMTAG_PAYLOAD_SHA512_ALT as u32,
                    IndexData::StringTag(self.archive_digests.sha512.clone()),
                ),
            ]);
        }
        if self.compression != CompressionType::None {
            entries.push(HeaderEntry::new(
                IndexTag::RPMTAG_PAYLOADCOMPRESSOR as u32,
                IndexData::StringTag(self.compression.to_string()),
            ));
        }
        entries.sort_by_key(|entry| entry.tag);
        entries
    }

    /// Generate the file and payload tags to apply when rebuilding a package.
    ///
    /// Staged file metadata replaces corresponding values in the prior header.
    /// File languages are included only when explicitly staged. Other
    /// caller-owned positional arrays must be kept aligned with the file list.
    pub fn rebuild_header_entries(&self) -> Vec<HeaderEntry> {
        let mut entries = self.file_header_entries();
        entries.extend(self.payload_header_entries());
        entries.sort_by_key(|entry| entry.tag);
        entries
    }

    /// Replace file and payload tags in a raw main-header editor.
    ///
    /// File metadata is taken from the options used to stage each file. Apply
    /// edits there before building, since v4 CPIO also stores modes and mtimes.
    /// This leaves unrelated and unknown tags alone. The caller must update
    /// other positional arrays, including unstaged file languages, when the
    /// file list's membership or order changes,
    /// and must update or remove file classification and dependency metadata
    /// when changed contents or RPM format make those values stale.
    pub fn apply_to_header(&self, editor: &mut HeaderEditor<IndexTag>) {
        use IndexTag::*;
        let entries = self.rebuild_header_entries();
        // These tags belong to the payload builder, even when this particular
        // build omits them. Include mutually exclusive v4/v6 and short/long
        // variants, optional file and compressor tags, and archive-size tags
        // that we invalidate but do not regenerate. Other positional tags,
        // such as FILECLASS, remain the caller's responsibility. Unstaged
        // FILELANGS also remains caller-owned; explicitly staged languages are
        // upserted from the generated entries.
        const OWNED_TAGS: &[IndexTag] = &[
            RPMTAG_SIZE,
            RPMTAG_LONGSIZE,
            RPMTAG_ARCHIVESIZE,
            RPMTAG_LONGARCHIVESIZE,
            RPMTAG_FILESIZES,
            RPMTAG_LONGFILESIZES,
            RPMTAG_FILEMODES,
            RPMTAG_FILERDEVS,
            RPMTAG_FILEMTIMES,
            RPMTAG_FILEDIGESTS,
            RPMTAG_FILELINKTOS,
            RPMTAG_FILEFLAGS,
            RPMTAG_FILEUSERNAME,
            RPMTAG_FILEGROUPNAME,
            RPMTAG_FILEDEVICES,
            RPMTAG_FILEINODES,
            RPMTAG_DIRINDEXES,
            RPMTAG_BASENAMES,
            RPMTAG_DIRNAMES,
            RPMTAG_FILEVERIFYFLAGS,
            RPMTAG_FILECAPS,
            RPMTAG_FILEDIGESTALGO,
            RPMTAG_PAYLOADSHA256,
            RPMTAG_PAYLOADSHA256ALT,
            RPMTAG_PAYLOADSHA256ALGO,
            RPMTAG_PAYLOAD_SHA3_256,
            RPMTAG_PAYLOAD_SHA3_256_ALT,
            RPMTAG_PAYLOAD_SHA512,
            RPMTAG_PAYLOAD_SHA512_ALT,
            RPMTAG_PAYLOADSIZE,
            RPMTAG_PAYLOADSIZEALT,
            RPMTAG_PAYLOADCOMPRESSOR,
            RPMTAG_PAYLOADFLAGS,
            RPMTAG_RPMFORMAT,
        ];
        // FILELANGS is upserted only when explicitly staged; otherwise an
        // existing array remains caller-owned and must not be removed here.
        debug_assert!(entries.iter().all(|entry| {
            entry.tag == RPMTAG_FILELANGS as u32
                || OWNED_TAGS.iter().any(|tag| *tag as u32 == entry.tag)
        }));
        for &tag in OWNED_TAGS {
            // Upsert replaces emitted tags; only tags absent from the new
            // result need removal from the old header.
            if !entries.iter().any(|entry| entry.tag == tag as u32) {
                editor.remove(tag as u32);
            }
        }
        editor.extend(entries);
    }
}

impl FileStaging {
    /// Build the archive and its positional file results, without package metadata.
    pub(super) fn prepare_payload(&mut self) -> Result<PayloadBuildResult, Error> {
        self.validate_file_metadata()?;
        let digest_kind = match self.config.file_digest_algorithm {
            DigestAlgorithm::Sha2_256 => HashKind::Sha256,
            DigestAlgorithm::Sha2_512 => HashKind::Sha512,
            DigestAlgorithm::Sha3_256 => HashKind::Sha3_256,
            _ => {
                return Err(Error::InvalidFileOptions {
                    method: "BuildConfig::file_digest_algorithm",
                    reason: "this file digest algorithm is not supported for payload construction",
                });
            }
        };
        // Build the hardlink plan from explicit declarations and automatic
        // filesystem identities before assigning header inode numbers.
        #[allow(unused_mut)]
        let mut hardlinks = hardlinks::Plan::from_explicit_declarations(&self.files)?;
        #[cfg(unix)]
        hardlinks.add_filesystem_identities(&self.source_identities, &self.files)?;

        let installed_size = hardlinks.installed_size(&self.files)?;
        let large = installed_size > u32::MAX as u64 || self.config.format != RpmFormat::V4;
        // Hash the raw archive while streaming it into the compressor; keeping
        // a second uncompressed copy would be particularly costly for large RPMs.
        let mut compressor: Compressor = self.config.compression.try_into()?;
        let mut archive = ChecksummingWriter::new(
            &mut compressor,
            &[HashKind::Sha256, HashKind::Sha512, HashKind::Sha3_256],
        );
        let mut files = Vec::with_capacity(self.files.len());
        // The BTreeMap order is the positional file order in the RPM header.
        for (inode, (path, entry)) in (1u32..).zip(self.files.iter()) {
            let ghost = entry.flags.contains(FileFlags::GHOST);
            let mode = entry.mode.file_type();
            if mode == FileType::Other {
                return Err(Error::InvalidFileOptions {
                    method: "PayloadBuilder::build",
                    reason: "device, FIFO, and socket payload entries are not supported",
                });
            }
            let size = entry.source.size()?;
            let modified_at = match self.config.source_date {
                Some(date) if date < entry.modified_at => date,
                _ => entry.modified_at,
            };
            // Ghosts have no archive entry. Non-regular files have no file digest,
            // while every hardlink member reports the digest of the shared data.
            let mut digest = String::new();
            if !ghost && mode == FileType::Regular {
                let mut sink = io::sink();
                let mut writer = ChecksummingWriter::new(&mut sink, &[digest_kind]);
                io::copy(&mut entry.source.try_into_bufread()?, &mut writer)?;
                digest = writer.into_digests().0[&digest_kind].to_string();
            }
            let verify_flags = if ghost {
                entry.verify_flags
                    & !(FileVerifyFlags::FILEDIGEST
                        | FileVerifyFlags::FILESIZE
                        | FileVerifyFlags::LINKTO
                        | FileVerifyFlags::MTIME)
            } else {
                entry.verify_flags
            };
            let member = hardlinks.member(path);
            files.push(BuiltFile {
                path: path.trim_start_matches('.').to_string(),
                directory: entry.dir.clone(),
                basename: entry.base_name.clone(),
                size,
                digest,
                mode: entry.mode,
                modified_at,
                linkto: entry.link.clone(),
                flags: entry.flags,
                verify_flags,
                user: entry.user.clone(),
                group: entry.group.clone(),
                language: entry.language.clone(),
                // Ghosts have no backing file, so their synthetic st_dev is zero.
                device: if ghost { 0 } else { 1 },
                inode: member.map_or(inode, |member| member.inode),
                caps: entry.caps.clone(),
                payload_size: if !ghost && member.is_none_or(|member| member.has_content) {
                    size
                } else {
                    0
                },
            });
        }

        let paths = self.files.keys().cloned().collect::<Vec<_>>();
        // Write ordinary CPIO entries before hardlink sets. Within each set,
        // rpmbuild writes empty earlier members and the data on the last one.
        for path in hardlinks.payload_order(&self.files) {
            let index = paths
                .binary_search(&path)
                .expect("payload path came from file map");
            let file = &files[index];
            let member = hardlinks.member(&path);
            let payload_size = file.payload_size;
            // Stripped CPIO names a header file index; classic CPIO carries its
            // own metadata and cannot represent file sizes over 4 GiB.
            let mut writer = if large {
                payload::write_stripped_cpio(&mut archive, index as u32, payload_size)
            } else {
                payload::Builder::new(&path)
                    .mode(file.mode.raw_mode().into())
                    .ino(file.inode)
                    .nlink(member.map_or(1, |member| member.link_count))
                    .mtime(file.modified_at.into())
                    .uid(self.uid.unwrap_or(0))
                    .gid(self.gid.unwrap_or(0))
                    .write_cpio(&mut archive, payload_size as u32)
            };
            if payload_size > 0 {
                io::copy(
                    &mut self.files[&path].source.try_into_bufread()?,
                    &mut writer,
                )?;
            }
            writer.finish()?;
        }
        payload::trailer(&mut archive)?;
        let (archive_hashes, archive_size) = archive.into_digests();
        let compressed_payload = compressor.finish_compression()?;
        let compressed_digests = PayloadDigests {
            sha256: hex::encode(sha2::Sha256::digest(&compressed_payload)),
            sha512: hex::encode(sha2::Sha512::digest(&compressed_payload)),
            sha3_256: hex::encode(sha3::Sha3_256::digest(&compressed_payload)),
        };
        let archive_digests = PayloadDigests {
            sha256: archive_hashes[&HashKind::Sha256].clone(),
            sha512: archive_hashes[&HashKind::Sha512].clone(),
            sha3_256: archive_hashes[&HashKind::Sha3_256].clone(),
        };
        let compression_flags = match self.config.compression {
            CompressionWithLevel::None => String::new(),
            CompressionWithLevel::Gzip(level) => level.to_string(),
            CompressionWithLevel::Zstd(level) => level.to_string(),
            CompressionWithLevel::Xz(level) => level.to_string(),
            CompressionWithLevel::Bzip2(level) => level.to_string(),
        };
        Ok(PayloadBuildResult {
            compressed_payload,
            files,
            installed_size,
            archive_size: archive_size as u64,
            compression: self.config.compression.compression_type(),
            format: self.config.format,
            file_digest_algorithm: self.config.file_digest_algorithm,
            compressed_digests,
            archive_digests,
            compression_flags,
        })
    }
}
