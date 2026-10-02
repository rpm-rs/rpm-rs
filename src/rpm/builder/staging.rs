//! Shared staging and validation of package files.

use super::*;

/// File inputs shared by normal and raw-header package construction.
#[derive(Default)]
pub(super) struct FileStaging {
    pub(super) config: BuildConfig,
    pub(super) uid: Option<u32>,
    pub(super) gid: Option<u32>,
    // Header file entries are sorted by path; hardlink sets may require a
    // different CPIO order so their completing member carries the bytes.
    pub(super) files: BTreeMap<String, PackageFileEntry>,
    /// Default ownership and permissions for regular files (like `%defattr`).
    pub(super) default_file_attrs: FileDefaults,
    /// Default ownership and permissions for directories (like `%defattr`).
    pub(super) default_dir_attrs: FileDefaults,
    /// On-disk identities used for automatic hardlink detection on Unix.
    #[cfg(unix)]
    pub(super) source_identities: HashMap<String, (u64, u64, PathBuf)>,
}

impl FileStaging {
    /// Update defaults for subsequently staged regular files.
    pub(super) fn set_default_file_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) {
        if let Some(permissions) = permissions {
            self.default_file_attrs.permissions = Some(permissions);
        }
        if let Some(user) = user {
            self.default_file_attrs.user = Some(user);
        }
        if let Some(group) = group {
            self.default_file_attrs.group = Some(group);
        }
    }

    /// Update defaults for subsequently staged directory entries.
    pub(super) fn set_default_dir_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) {
        if let Some(permissions) = permissions {
            self.default_dir_attrs.permissions = Some(permissions);
        }
        if let Some(user) = user {
            self.default_dir_attrs.user = Some(user);
        }
        if let Some(group) = group {
            self.default_dir_attrs.group = Some(group);
        }
    }

    /// Reject strings which cannot safely be stored in RPM file-list tags.
    pub(super) fn validate_file_metadata(&self) -> Result<(), Error> {
        for (path, entry) in &self.files {
            super::super::util::reject_control_chars("file path", path)?;
            super::super::util::reject_control_chars("file user", &entry.user)?;
            super::super::util::reject_control_chars("file group", &entry.group)?;
            super::super::util::reject_control_chars("file symlink target", &entry.link)?;
        }
        Ok(())
    }

    /// Stage an on-disk regular file.
    pub fn with_file(
        &mut self,
        source: impl AsRef<Path>,
        options: impl Into<FileOptions>,
    ) -> Result<&mut Self, Error> {
        let metadata = fs::metadata(source.as_ref())?;
        #[allow(unused_mut)]
        let mut options = options.into();

        if options.mode.file_type() != FileType::Regular {
            return Err(Error::InvalidFileOptions {
                method: "with_file",
                reason: "expected regular file mode (use FileOptions::new() or .mode() with a regular file mode); use with_dir_entry() for directories or with_symlink() for symlinks",
            });
        }
        if options.flag.contains(FileFlags::GHOST) {
            return Err(Error::InvalidFileOptions {
                method: "with_file",
                reason: "ghost files should not have content; use with_ghost() instead",
            });
        }

        #[cfg(unix)]
        if options.use_default_permissions {
            // Apply builder defaults if available, otherwise inherit from filesystem
            let defaults = if options.mode.file_type() == FileType::Dir {
                &self.default_dir_attrs
            } else {
                &self.default_file_attrs
            };
            if let Some(perms) = defaults.permissions {
                options.mode.set_permissions(perms);
            } else {
                options.mode = FileMode::try_from(metadata.permissions().mode() as i32)
                    .expect("OS file permissions should always be a valid mode");
            }
            options.use_default_permissions = false;
        }
        let modified_at = metadata.modified()?.try_into()?;
        self.add_data(
            ContentSource::Path(source.as_ref().to_path_buf()),
            modified_at,
            options,
            false,
            #[cfg(unix)]
            Some(&metadata),
        )?;
        Ok(self)
    }

    /// Add a file to the package without needing an existing file.
    ///
    /// Helpful if files are being generated on-demand, and you don't want to write them to disk.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package")
    ///     .with_file_contents(
    ///         "
    /// [check]
    /// date = true
    /// time = true
    /// ",
    ///         rpm::FileOptions::new("/etc/awesome/config.toml").config(),
    ///     )?
    ///      .with_file_contents(
    ///         // the contents of the file is "hello world!". It doesn't need to be UTF-8, binary data works too.
    ///         "hello world!",
    ///         // you can set permissions, capabilities and custom user too
    ///         rpm::FileOptions::new("/etc/awesome/second.toml").permissions(0o744).caps("cap_sys_admin=pe")?.user("hugo"),
    ///     )?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_file_contents(
        &mut self,
        content: impl Into<Vec<u8>>,
        options: impl Into<FileOptions>,
    ) -> Result<&mut Self, Error> {
        let options = options.into();

        if options.mode.file_type() != FileType::Regular {
            return Err(Error::InvalidFileOptions {
                method: "with_file_contents",
                reason: "expected regular file mode (use FileOptions::new()); use with_dir_entry() for directories or with_symlink() for symlinks",
            });
        }
        if options.flag.contains(FileFlags::GHOST) {
            return Err(Error::InvalidFileOptions {
                method: "with_file_contents",
                reason: "ghost files should not have content; use with_ghost() instead",
            });
        }

        self.add_data(
            ContentSource::Raw(content.into()),
            self.config.source_date.unwrap_or(Timestamp::now()),
            options,
            false,
            #[cfg(unix)]
            None,
        )?;
        Ok(self)
    }

    /// Add a directory entry to the package.
    ///
    /// Unlike files added via [`with_file()`](Self::with_file), directory entries do not
    /// require a content source. This allows you to create empty directories and set
    /// their ownership and permissions.
    ///
    /// This method does NOT add any files to the directory.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package")
    ///     .with_dir_entry(
    ///         rpm::FileOptions::dir("/var/log/myapp").user("myuser").permissions(0o750),
    ///     )?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_dir_entry(&mut self, options: impl Into<FileOptions>) -> Result<&mut Self, Error> {
        let options = options.into();

        if options.mode.file_type() != FileType::Dir {
            return Err(Error::InvalidFileOptions {
                method: "with_dir_entry",
                reason: "expected directory file mode (use FileOptions::dir())",
            });
        }

        self.add_data(
            ContentSource::None,
            self.config.source_date.unwrap_or(Timestamp::now()),
            options,
            false,
            #[cfg(unix)]
            None,
        )?;
        Ok(self)
    }

    /// Add a symbolic link entry to the package.
    ///
    /// Unlike files added via [`with_file()`](Self::with_file), symlinks do not require
    /// a content source. The symlink target should be specified via
    /// [`FileOptions::symlink()`].
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package")
    ///     .with_symlink(
    ///         rpm::FileOptions::symlink("/usr/bin/awesome_link", "/usr/bin/awesome"),
    ///     )?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_symlink(&mut self, options: impl Into<FileOptions>) -> Result<&mut Self, Error> {
        let options = options.into();

        if options.mode.file_type() != FileType::SymbolicLink {
            return Err(Error::InvalidFileOptions {
                method: "with_symlink",
                reason: "expected symbolic link file mode (use FileOptions::symlink())",
            });
        }
        if options.symlink.is_empty() {
            return Err(Error::InvalidFileOptions {
                method: "with_symlink",
                reason: "symlink target must not be empty (use FileOptions::symlink(dest, target))",
            });
        }

        self.add_data(
            ContentSource::Raw(options.symlink.clone().into_bytes()),
            self.config.source_date.unwrap_or(Timestamp::now()),
            options,
            false,
            #[cfg(unix)]
            None,
        )?;
        Ok(self)
    }

    /// Add a FIFO, device, or socket entry to the package.
    pub fn with_special_file(
        &mut self,
        options: impl Into<FileOptions>,
    ) -> Result<&mut Self, Error> {
        let options = options.into();
        if !matches!(
            options.mode.file_type(),
            FileType::Fifo | FileType::CharacterDevice | FileType::BlockDevice | FileType::Socket
        ) {
            return Err(Error::InvalidFileOptions {
                method: "with_special_file",
                reason: "expected FIFO, character-device, block-device, or socket mode",
            });
        }
        if options.flag.contains(FileFlags::GHOST) {
            return Err(Error::InvalidFileOptions {
                method: "with_special_file",
                reason: "ghost special files should use with_ghost() instead",
            });
        }

        self.add_data(
            ContentSource::None,
            self.config.source_date.unwrap_or(Timestamp::now()),
            options,
            false,
            #[cfg(unix)]
            None,
        )?;
        Ok(self)
    }

    /// Add a ghost file or directory entry to the package.
    ///
    /// Ghost entries are not included in the package payload, but their metadata
    /// (ownership, permissions, etc.) is tracked by RPM. This is commonly used for
    /// files created at runtime (e.g. log files, PID files).
    ///
    /// Use [`FileOptions::ghost()`] for ghost files or [`FileOptions::ghost_dir()`]
    /// for ghost directories.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package")
    ///     .with_ghost(
    ///         rpm::FileOptions::ghost("/var/log/myapp/app.log").user("myuser"),
    ///     )?
    ///     .with_ghost(
    ///         rpm::FileOptions::ghost_dir("/var/run/myapp").permissions(0o755),
    ///     )?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_ghost(&mut self, options: impl Into<FileOptions>) -> Result<&mut Self, Error> {
        let options = options.into();

        if !options.flag.contains(FileFlags::GHOST) {
            return Err(Error::InvalidFileOptions {
                method: "with_ghost",
                reason: "expected ghost flag to be set (use FileOptions::ghost() or FileOptions::ghost_dir())",
            });
        }

        self.add_data(
            ContentSource::None,
            self.config.source_date.unwrap_or(Timestamp::now()),
            options,
            false,
            #[cfg(unix)]
            None,
        )?;
        Ok(self)
    }

    /// Recursively add all files from a source directory into the package.
    ///
    /// Each file under `source_dir` is mapped to the corresponding path under
    /// `dest_prefix`. For example, if `source_dir` is `"./build/output"` and
    /// `dest_prefix` is `"/usr/share/myapp"`, then `./build/output/data/foo.txt`
    /// becomes `/usr/share/myapp/data/foo.txt`.
    ///
    /// Directory entries are automatically created for each subdirectory encountered.
    /// Symlinks are added as symlink entries (not followed).
    ///
    /// The `customize` callback receives a [`FileOptionsBuilder`] for each entry (file,
    /// directory, or symlink) and must return the modified builder. Use it to apply
    /// uniform metadata to every entry — e.g. marking all files as `%doc` or `%config`.
    ///
    /// Entries added by this method are considered "bulk-added" and can be overridden
    /// by explicit methods like [`with_file()`](Self::with_file) regardless of call order.
    /// If the same path was already added (explicitly or by a previous bulk operation),
    /// it is silently skipped.
    ///
    /// ```no_run
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some package")
    ///     // Override a specific file before the bulk add
    ///     .with_file(
    ///         "./build/etc/special.conf",
    ///         rpm::FileOptions::new("/etc/myapp/special.conf").config().noreplace(),
    ///     )?
    ///     // Bulk-add everything; special.conf is skipped since it was already added
    ///     .with_dir("./build/etc", "/etc/myapp", |o| o.config())?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_dir<P, D, F>(
        &mut self,
        source_dir: P,
        dest_prefix: D,
        customize: F,
    ) -> Result<&mut Self, Error>
    where
        P: AsRef<Path>,
        D: AsRef<str>,
        F: Fn(FileOptionsBuilder) -> FileOptionsBuilder,
    {
        self.add_dir_recursive(source_dir.as_ref(), dest_prefix.as_ref(), &customize)?;
        Ok(self)
    }

    /// Stage a directory tree while applying the caller's file-option customizations.
    fn add_dir_recursive<F>(
        &mut self,
        source_dir: &Path,
        dest_prefix: &str,
        customize: &F,
    ) -> Result<(), Error>
    where
        F: Fn(FileOptionsBuilder) -> FileOptionsBuilder,
    {
        // Add the directory entry itself
        #[allow(unused_mut)]
        let mut dir_options: FileOptions = customize(FileOptions::dir(dest_prefix)).into();
        #[cfg(unix)]
        if dir_options.use_default_permissions {
            if let Some(perms) = self.default_dir_attrs.permissions {
                dir_options.mode.set_permissions(perms);
            } else {
                let dir_metadata = source_dir.symlink_metadata()?;
                dir_options.mode = FileMode::try_from(dir_metadata.permissions().mode() as i32)
                    .expect("OS file permissions should always be a valid mode");
            }
            dir_options.use_default_permissions = false;
        }
        self.add_data(
            ContentSource::None,
            self.config.source_date.unwrap_or(Timestamp::now()),
            dir_options,
            true,
            #[cfg(unix)]
            None,
        )?;

        for entry in fs::read_dir(source_dir)? {
            let entry = entry?;
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            let dest = format!("{}/{}", dest_prefix, file_name_str);
            // Use symlink_metadata (lstat) so we don't follow symlinks
            let metadata = entry.path().symlink_metadata()?;
            let file_type = metadata.file_type();

            if file_type.is_dir() {
                self.add_dir_recursive(&entry.path(), &dest, customize)?;
            } else if file_type.is_symlink() {
                let link_target = fs::read_link(entry.path())?;
                let options = customize(FileOptions::symlink(&dest, link_target.to_string_lossy()));
                self.add_data(
                    ContentSource::None,
                    self.config.source_date.unwrap_or(Timestamp::now()),
                    options.into(),
                    true,
                    #[cfg(unix)]
                    None,
                )?;
            } else {
                let modified_at: Timestamp = metadata.modified()?.try_into()?;
                #[allow(unused_mut)]
                let mut options: FileOptions = customize(FileOptions::new(&dest)).into();

                #[cfg(unix)]
                if options.use_default_permissions {
                    if let Some(perms) = self.default_file_attrs.permissions {
                        options.mode.set_permissions(perms);
                    } else {
                        options.mode = FileMode::try_from(metadata.permissions().mode() as i32)
                            .expect("OS file permissions should always be a valid mode");
                    }
                    options.use_default_permissions = false;
                }

                #[cfg(unix)]
                if matches!(
                    options.mode.file_type(),
                    FileType::CharacterDevice | FileType::BlockDevice
                ) {
                    use std::os::unix::fs::MetadataExt;
                    options.rdev = metadata.rdev() as u16;
                }

                let source = match options.mode.file_type() {
                    FileType::Fifo
                    | FileType::CharacterDevice
                    | FileType::BlockDevice
                    | FileType::Socket => ContentSource::None,
                    _ => ContentSource::Path(entry.path()),
                };

                self.add_data(
                    source,
                    modified_at,
                    options,
                    true,
                    #[cfg(unix)]
                    Some(&metadata),
                )?;
            }
        }

        Ok(())
    }

    /// Normalize and register one file input, applying defaults and replacement rules.
    fn add_data(
        &mut self,
        content_source: ContentSource,
        modified_at: Timestamp,
        mut options: FileOptions,
        bulk: bool,
        #[cfg(unix)] source_metadata: Option<&fs::Metadata>,
    ) -> Result<(), Error> {
        let modified_at = options.modified_at.unwrap_or(modified_at);

        // Apply builder-level defaults for ownership and permissions where
        // the FileOptions hasn't been explicitly overridden.
        let defaults = if options.mode.file_type() == FileType::Dir {
            &self.default_dir_attrs
        } else {
            &self.default_file_attrs
        };
        if options.user.is_none() {
            options.user = Some(defaults.user.clone().unwrap_or_else(|| "root".to_string()));
        }
        if options.group.is_none() {
            options.group = Some(defaults.group.clone().unwrap_or_else(|| "root".to_string()));
        }
        if options.use_default_permissions
            && let Some(perms) = defaults.permissions
        {
            options.mode.set_permissions(perms);
        }

        if options.hardlink_identity.as_deref() == Some("") {
            return Err(Error::InvalidFileOptions {
                method: "FileOptionsBuilder::hardlink",
                reason: "hardlink identity must not be empty",
            });
        }
        if options.hardlink_identity.is_some()
            && (options.mode.file_type() != FileType::Regular
                || options.flag.contains(FileFlags::GHOST))
        {
            return Err(Error::InvalidFileOptions {
                method: "FileOptionsBuilder::hardlink",
                reason: "hardlink identity is only valid for non-ghost regular files",
            });
        }

        let dest = options.destination;
        if !dest.starts_with("./") && !dest.starts_with('/') {
            return Err(Error::InvalidDestinationPath {
                path: dest,
                desc: "invalid start, expected / or ./",
            });
        }
        if dest == "/" || dest == "./" {
            return Err(Error::InvalidDestinationPath {
                path: dest,
                desc: "cannot package the root directory itself",
            });
        }

        // Normalize the path: collapse repeated slashes and remove trailing slashes.
        // This prevents entries like "/usr//bin/foo" and "/usr/bin/foo" from being
        // treated as distinct, and "/var/log/myapp/" from failing to split into
        // dir + basename correctly.
        let normalized = super::super::util::normalize_path(&dest);

        let pb = PathBuf::from(normalized.clone());

        let parent = pb.parent().ok_or_else(|| Error::InvalidDestinationPath {
            path: normalized.clone(),
            desc: "no parent directory found",
        })?;

        let root_child = matches!(parent.to_str(), Some("/" | "."));
        let (cpio_path, dir) = if normalized.starts_with('.') {
            (
                normalized.to_string(),
                // strip_prefix() should never fail because we've checked the special cases already
                if root_child {
                    "/".to_string()
                } else {
                    format!("/{}/", parent.strip_prefix(".").unwrap().to_string_lossy())
                },
            )
        } else {
            (
                format!(".{}", normalized),
                if root_child {
                    "/".to_string()
                } else {
                    format!("{}/", parent.to_string_lossy())
                },
            )
        };

        // Directories cannot carry %config, %doc, or %license attributes in RPM.
        // These flags are silently stripped rather than rejected, as this matches RPM behavior.
        if options.mode.file_type() == FileType::Dir {
            options
                .flag
                .remove(FileFlags::CONFIG | FileFlags::DOC | FileFlags::LICENSE);
        }

        if let Some(existing) = self.files.get(&cpio_path) {
            if bulk {
                // Bulk operations skip entries that were already added (either explicitly
                // or by a previous bulk operation). This allows explicit with_file() calls
                // to take precedence regardless of ordering.
                //
                // NOTE: when two bulk operations overlap (e.g. with_dir for "/etc"
                // then with_dir for "/etc/myapp" with different options), the first
                // bulk add wins. If we need more sophisticated merging (e.g. a more-specific
                // bulk operation overriding a less-specific one), that would require tracking
                // additional provenance such as the depth or specificity of the bulk source.
                return Ok(());
            }
            if !existing.bulk_added {
                // Two explicit adds of the same path is an error.
                return Err(Error::InvalidDestinationPath {
                    path: normalized,
                    desc: "duplicate file entry; the same path was added to the package twice",
                });
            }
            // An explicit add replaces a bulk-added entry (fall through to insert below).
        }

        // Populate source_identities for automatic hardlink detection on Unix.
        // Only track files without explicit hardlink_identity to avoid conflicts.
        // Check BEFORE moving hardlink_identity into the entry.
        #[cfg(unix)]
        let should_track_identity =
            source_metadata.is_some() && options.hardlink_identity.is_none();

        #[cfg(unix)]
        let source_path = match &content_source {
            ContentSource::Path(path) if should_track_identity => Some(fs::canonicalize(path)?),
            _ => None,
        };

        // An explicit entry can replace a bulk-added entry. Remove the old source
        // identity so automatic detection reflects the replacement entry.
        #[cfg(unix)]
        self.source_identities.remove(&cpio_path);

        let entry = PackageFileEntry {
            // file_name() should never fail because we've checked the special cases already
            base_name: pb.file_name().unwrap().to_string_lossy().to_string(),
            source: content_source,
            flags: options.flag,
            user: options.user.expect("user should be resolved by now"),
            group: options.group.expect("group should be resolved by now"),
            mode: options.mode,
            link: options.symlink,
            modified_at,
            dir: dir.clone(),
            caps: options.caps,
            verify_flags: options.verify_flags,
            rdev: options.rdev,
            hardlink_identity: options.hardlink_identity,
            bulk_added: bulk,
        };

        #[cfg(unix)]
        if should_track_identity {
            use std::os::unix::fs::MetadataExt;
            let meta = source_metadata.unwrap(); // Safe because we checked is_some() above
            self.source_identities.insert(
                cpio_path.clone(),
                (
                    meta.dev(),
                    meta.ino(),
                    source_path.expect("tracked source path"),
                ),
            );
        }

        self.files.insert(cpio_path, entry);
        Ok(())
    }
}
