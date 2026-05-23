#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryInto;
use std::io::Read;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{fs, io};

use std::fmt::Debug;
use std::path::{Path, PathBuf};

use base64::prelude::*;
use digest::Digest;
use rpm_version::Evr;

use super::compressor::Compressor;
use super::headers::*;
use super::payload;
use super::util::{ChecksummingWriter, HashKind};
use crate::errors::*;
use crate::{Timestamp, constants::*};

#[cfg(feature = "signature-meta")]
use crate::signature;

use crate::Package;
use crate::PackageMetadata;

use crate::{CompressionType, CompressionWithLevel, RpmFormat};

#[derive(Copy, Clone, PartialEq)]
pub struct BuildConfig {
    format: RpmFormat,
    compression: CompressionWithLevel,
    source_date: Option<Timestamp>,
    reserved_space: Option<u32>,
}

impl From<RpmFormat> for BuildConfig {
    fn from(value: RpmFormat) -> Self {
        match value {
            RpmFormat::V4 => Self::v4(),
            RpmFormat::V6 => Self::v6(),
        }
    }
}

impl Default for BuildConfig {
    fn default() -> Self {
        Self::v4()
    }
}

impl BuildConfig {
    /// Use "RPM v4" defaults for the RPM - may impact compatibility
    pub fn v4() -> Self {
        Self {
            format: RpmFormat::V4,
            compression: CompressionWithLevel::default(),
            source_date: None,
            reserved_space: Some(SignatureHeaderBuilder::DEFAULT_RESERVED_SPACE),
        }
    }

    /// Use "RPM v6" defaults for the RPM - may impact compatibility
    pub fn v6() -> Self {
        Self {
            format: RpmFormat::V6,
            compression: CompressionWithLevel::default(),
            source_date: None,
            reserved_space: Some(SignatureHeaderBuilder::DEFAULT_RESERVED_SPACE),
        }
    }

    /// Set a fixed timestamp for reproducible builds.
    ///
    /// When set, this timestamp will be used for:
    /// - Build time (`RPMTAG_BUILDTIME`)
    /// - File modification times (`RPMTAG_FILEMTIMES`)
    /// - Package signature timestamp
    ///
    /// This is equivalent to setting the `SOURCE_DATE_EPOCH` environment variable
    /// for tools like `rpmbuild`, enabling reproducible/deterministic package builds.
    ///
    /// It is recommended to use the timestamp of the last commit in your VCS.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let build_config = rpm::BuildConfig::default().source_date(1_600_000_000);
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "some baz package")
    ///     .using_config(build_config)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn source_date(mut self, t: impl TryInto<Timestamp, Error = impl Debug>) -> Self {
        self.source_date = Some(t.try_into().unwrap());
        self
    }

    /// Set the compression type and/or level to be used for the payload of the built package
    ///
    /// Passing a `CompressionType` value will use a default compression level which has been
    /// optimized for package size over compression time.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let build_config = rpm::BuildConfig::default().compression(rpm::CompressionType::Gzip);
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "some baz package")
    ///     .using_config(build_config)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// If you would like to specify a custom compression level (for faster package builds, at the
    /// expense of package size), pass a `CompressionWithLevel` value instead.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let build_config = rpm::BuildConfig::default().compression(rpm::CompressionWithLevel::Zstd(3));
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "some baz package")
    ///     .using_config(build_config)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// For Gzip compression, the expected range is 0 to 9, with a default value of 9.
    /// For Xz compression, the expected range is 0 to 9, with a default value of 9.
    /// For Zstd compression, the expected range is 1 to 22, with a default value of 19.
    ///
    /// If this method is not called, the payload will be Gzip compressed by default. This may
    /// change in future versions of the library.
    pub fn compression(mut self, compression: impl Into<CompressionWithLevel>) -> Self {
        self.compression = compression.into();
        self
    }

    /// Set the amount of reserved space (in bytes) in the signature header
    /// for later adding signatures in-place (without rewriting the payload).
    ///
    /// Defaults to `Some(4128)`. Set to `None` to omit reserved space
    /// entirely, producing a smaller package when in-place re-signing is
    /// not needed.
    pub fn reserved_space(mut self, size: Option<u32>) -> Self {
        self.reserved_space = size;
        self
    }
}

/// Default ownership and permissions applied to file entries when not explicitly overridden.
///
/// Similar to `%defattr` in RPM spec files.
#[derive(Clone, Debug, Default)]
pub struct FileDefaults {
    pub user: Option<String>,
    pub group: Option<String>,
    pub permissions: Option<u16>,
}

/// Internal representation of a trigger for the builder.
///
/// Each entry represents one trigger script with one condition.
/// Multiple entries with the same script can share a script index
/// (compound triggers), but the simple API creates one entry per trigger.
struct PackageTriggerEntry {
    /// Combined flags: trigger type (TRIGGERIN, TRIGGERUN, etc.) OR'd with
    /// optional version comparison flags (LESS, GREATER, EQUAL).
    /// For example, `%triggerin -- bash > 5.0` would have `TRIGGERIN | GREATER`.
    flags: DependencyFlags,
    /// Target package name (for package triggers) or path (for file triggers)
    name: String,
    /// Version constraint (empty string if unconstrained)
    version: String,
    /// The script to execute
    script: Scriptlet,
}

/// Create an RPM file by specifying metadata and files using the builder pattern.
#[derive(Default)]
pub struct PackageBuilder {
    config: BuildConfig,

    name: String,
    epoch: Option<u32>,
    version: String,
    license: String,
    arch: String,
    uid: Option<u32>, // @todo: nothing is actually setting these or allowing setting them, they fall back to default
    gid: Option<u32>,
    summary: String,
    desc: Option<String>,
    release: String,

    // File entries need to be sorted. The entries need to be in the same order as they come
    // in the cpio payload. Otherwise rpm will not be able to resolve those paths.
    // key is the directory, values are complete paths
    files: BTreeMap<String, PackageFileEntry>,
    directories: BTreeSet<String>,
    requires: Vec<Dependency>,
    obsoletes: Vec<Dependency>,
    provides: Vec<Dependency>,
    conflicts: Vec<Dependency>,
    recommends: Vec<Dependency>,
    suggests: Vec<Dependency>,
    enhances: Vec<Dependency>,
    supplements: Vec<Dependency>,
    order_with_requires: Vec<Dependency>,

    pre_inst_script: Option<Scriptlet>,
    post_inst_script: Option<Scriptlet>,
    pre_uninst_script: Option<Scriptlet>,
    post_uninst_script: Option<Scriptlet>,
    pre_trans_script: Option<Scriptlet>,
    post_trans_script: Option<Scriptlet>,
    pre_untrans_script: Option<Scriptlet>,
    post_untrans_script: Option<Scriptlet>,
    verify_script: Option<Scriptlet>,

    triggers: Vec<PackageTriggerEntry>,
    file_triggers: Vec<PackageTriggerEntry>,
    trans_file_triggers: Vec<PackageTriggerEntry>,

    /// The author name with email followed by a dash with the version
    /// `Max Mustermann <max@example.com> - 0.1-1`
    changelog_names: Vec<String>,
    changelog_entries: Vec<String>,
    changelog_times: Vec<Timestamp>,

    vendor: Option<String>,
    packager: Option<String>,
    group: Option<String>,
    url: Option<String>,
    vcs: Option<String>,
    cookie: Option<String>,

    build_host: Option<String>,

    /// Default ownership and permissions for regular file entries (like `%defattr` in spec files).
    default_file_attrs: FileDefaults,
    /// Default ownership and permissions for directory entries (like the dirmode in `%defattr`).
    default_dir_attrs: FileDefaults,

    /// Whether `build()` or `build_and_sign()` has already been called.
    consumed: bool,
}

impl PackageBuilder {
    /// Create a new package, providing the required metadata.
    ///
    /// Additional metadata is added using the builder pattern. However `name`, `version`, `license`,
    /// `arch`, and `summary` are mandatory and must be provided.
    ///
    /// `name` - The name of the software being packaged. It should not contain any whitespace.
    /// `version` - The version of the software being packaged. It should be as close as possible to
    ///     the format of the original software's version.
    /// `license` - The license terms applicable to the software being packaged (preferably using SPDX)
    /// `arch` - The architecture that the package was built for, or "noarch" if not architecture specific
    /// `summary` - A short and concise description of the package.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package").build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(name: &str, version: &str, license: &str, arch: &str, summary: &str) -> Self {
        Self {
            name: name.to_string(),
            epoch: None,
            version: version.to_string(),
            license: license.to_string(),
            arch: arch.to_string(),
            summary: summary.to_string(),
            release: "1".to_string(),
            ..Default::default()
        }
    }

    /// Use a particular common configuration when generating the packages
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package")
    ///     .using_config(rpm::BuildConfig::v4().compression(rpm::CompressionType::Gzip))
    ///     .build();
    /// # Ok(())
    /// # }
    /// ```
    pub fn using_config(&mut self, config: impl Into<BuildConfig>) -> &mut Self {
        self.config = config.into();
        self
    }

    /// Set the package epoch.
    ///
    /// The main scenario in which this is used is if the version numbering scheme of the packaged
    /// software changes in such a way that "new" versions are seen as older than packages under
    /// the old versioning scheme. Packages with bigger epochs are always treated as newer than
    /// packages with smaller epochs, so it can be used as an override, forcing the new packages to
    /// be seen as newer.
    ///
    /// However, because of this, the epoch of a package must never decrease, and shouldn't be set
    /// unless required.
    pub fn epoch(&mut self, epoch: u32) -> &mut Self {
        self.epoch = Some(epoch);
        self
    }

    /// Set the package release. Exactly what this value represents depends on the
    /// distribution's packaging protocols, but often the components are:
    ///
    /// * an integer representing the number of builds that have been performed with this version
    /// * a short-form representation of the distribution name and version
    /// * whether this is a pre-release version
    /// * source control information
    ///
    /// The distribution's packaging protocols should be followed when constructing this value.
    ///
    /// Examples:
    ///
    /// * 1.el8
    /// * 3.fc38
    /// * 5.el9_2.alma
    /// * 0.20230715gitabcdef
    pub fn release(&mut self, release: impl Into<String>) -> &mut Self {
        self.release = release.into();
        self
    }

    /// Set the URL for the package. Most often this is the website of the upstream project being
    /// packaged
    pub fn url(&mut self, content: impl Into<String>) -> &mut Self {
        self.url = Some(content.into());
        self
    }

    /// Set the version control URL of the upstream project
    pub fn vcs(&mut self, content: impl Into<String>) -> &mut Self {
        self.vcs = Some(content.into());
        self
    }

    /// Define a detailed, multiline, description of what the packaged software does
    pub fn description(&mut self, desc: impl Into<String>) -> &mut Self {
        self.desc = Some(desc.into());
        self
    }

    /// Set the package vendor - the name of the organization that is producing the package.
    pub fn vendor(&mut self, content: impl Into<String>) -> &mut Self {
        self.vendor = Some(content.into());
        self
    }

    /// Set the packager, the name of the person producing the package. This is often not present,
    /// or set to the same value as the vendor
    pub fn packager(&mut self, content: impl Into<String>) -> &mut Self {
        self.packager = Some(content.into());
        self
    }

    /// Set the package group (this is deprecated in most packaging guidelines)
    pub fn group(&mut self, content: impl Into<String>) -> &mut Self {
        self.group = Some(content.into());
        self
    }

    /// Define the name of the build host.
    ///
    /// Commonly used in conjunction with the `gethostname` crate.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MPL-2.0", "x86_64", "some bar package")
    ///     .build_host(gethostname::gethostname().to_str().ok_or("Funny hostname")?)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn build_host(&mut self, build_host: impl AsRef<str>) -> &mut Self {
        self.build_host = Some(build_host.as_ref().to_owned());
        self
    }

    /// Define a value that can be used for associating several package builds as being part of
    /// one operation
    ///
    /// You can use any value, but the standard format is "${build_host} ${build_time}"
    pub fn cookie(&mut self, cookie: impl AsRef<str>) -> &mut Self {
        self.cookie = Some(cookie.as_ref().to_owned());
        self
    }

    /// Set default ownership and permissions for regular file entries.
    ///
    /// These defaults are applied to any file added via [`with_file()`](Self::with_file),
    /// [`with_file_contents()`](Self::with_file_contents), or [`with_dir()`](Self::with_dir)
    /// where the user/group/permissions have not been explicitly set on the [`FileOptions`].
    ///
    /// Pass `None` for any field to leave its current default unchanged (like `-` in `%defattr`).
    ///
    /// Can be called multiple times — each call changes the defaults for subsequent additions,
    /// similar to positional `%defattr` in RPM spec files.
    pub fn default_file_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) -> &mut Self {
        if let Some(p) = permissions {
            self.default_file_attrs.permissions = Some(p);
        }
        if let Some(u) = user {
            self.default_file_attrs.user = Some(u);
        }
        if let Some(g) = group {
            self.default_file_attrs.group = Some(g);
        }
        self
    }

    /// Set default ownership and permissions for directory entries.
    ///
    /// These defaults are applied to any directory added via [`with_dir_entry()`](Self::with_dir_entry)
    /// or [`with_dir()`](Self::with_dir) where the user/group/permissions
    /// have not been explicitly set on the [`FileOptions`].
    ///
    /// Pass `None` for any field to leave its current default unchanged (like `-` in `%defattr`).
    ///
    /// Can be called multiple times — each call changes the defaults for subsequent additions.
    pub fn default_dir_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) -> &mut Self {
        if let Some(p) = permissions {
            self.default_dir_attrs.permissions = Some(p);
        }
        if let Some(u) = user {
            self.default_dir_attrs.user = Some(u);
        }
        if let Some(g) = group {
            self.default_dir_attrs.group = Some(g);
        }
        self
    }

    /// Add an entry to the package changelog.
    ///
    /// The a changelog entry consists of an entry name (which includes author, email followed by
    /// a dash followed by a version number), description, and the date and time of the change.
    /// ```
    /// # #[cfg(feature = "chrono")]
    /// # || -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package")
    ///     .add_changelog_entry(
    ///         "Alfred J. Quack <quack@example.com> - 0.1-27",
    ///         r#" - Obsolete `fn foo`, in favor of `fn bar`.
    /// - Secondly."#,
    ///         1_681_411_811,
    ///     )
    ///     .add_changelog_entry(
    ///         "Gambl B. Xen <gbx@example.com> - 0.1-26",
    ///         " - Add enumerator.",
    ///         rpm::chrono::DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").unwrap(),
    ///     )
    ///     .build()?;
    /// # Ok(())
    /// # }();
    /// ```
    pub fn add_changelog_entry(
        &mut self,
        name: impl AsRef<str>,
        entry: impl AsRef<str>,
        timestamp: impl TryInto<Timestamp, Error = impl Debug>,
    ) -> &mut Self {
        self.changelog_names.push(name.as_ref().to_owned());
        self.changelog_entries.push(entry.as_ref().to_owned());
        self.changelog_times.push(timestamp.try_into().unwrap());
        self
    }

    /// Add a file to the package.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "Apache-2.0", "x86_64", "some baz package")
    ///     .with_file(
    ///         "./awesome-config.toml",
    ///         rpm::FileOptions::new("/etc/awesome/config.toml").config(),
    ///     )?
    ///     // file mode is inherited from source file
    ///     .with_file(
    ///         "./awesome-bin",
    ///         rpm::FileOptions::new("/usr/bin/awesome"),
    ///     )?
    ///      .with_file(
    ///         "./awesome-config.toml",
    ///         // you can set permissions, capabilities and custom user too
    ///         rpm::FileOptions::new("/etc/awesome/second.toml").permissions(0o744).caps("cap_sys_admin=pe")?.user("hugo"),
    ///     )?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
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

                self.add_data(
                    ContentSource::Path(entry.path()),
                    modified_at,
                    options,
                    true,
                )?;
            }
        }

        Ok(())
    }

    fn add_data(
        &mut self,
        content_source: ContentSource,
        modified_at: Timestamp,
        mut options: FileOptions,
        bulk: bool,
    ) -> Result<(), Error> {
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
        let normalized = super::util::normalize_path(&dest);

        let pb = PathBuf::from(normalized.clone());

        let parent = pb.parent().ok_or_else(|| Error::InvalidDestinationPath {
            path: normalized.clone(),
            desc: "no parent directory found",
        })?;

        let (cpio_path, dir) = if normalized.starts_with('.') {
            (
                normalized.to_string(),
                // strip_prefix() should never fail because we've checked the special cases already
                format!("/{}/", parent.strip_prefix(".").unwrap().to_string_lossy()),
            )
        } else {
            (
                format!(".{}", normalized),
                format!("{}/", parent.to_string_lossy()),
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
            bulk_added: bulk,
        };

        self.directories.insert(dir);
        self.files.insert(cpio_path, entry);
        Ok(())
    }

    /// Set a script to be executed just before the package is installed or upgraded.
    ///
    /// See: %pre from specfile syntax
    #[inline]
    pub fn pre_install_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.pre_inst_script = Some(content.into());
        self
    }

    /// Set a script to be executed just after the package is installed or upgraded.
    ///
    /// See: %post from specfile syntax
    #[inline]
    pub fn post_install_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.post_inst_script = Some(content.into());
        self
    }

    /// Set a script to be executed just before package removal during uninstallation or upgrade.
    ///
    /// See: %preun from specfile syntax
    #[inline]
    pub fn pre_uninstall_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.pre_uninst_script = Some(content.into());
        self
    }

    /// Set a script to be executed just after package removal during uninstallation or upgrade.
    ///
    /// See: %postun from specfile syntax
    #[inline]
    pub fn post_uninstall_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.post_uninst_script = Some(content.into());
        self
    }

    /// Set a script to be executed before a transaction in which the package is installed or
    /// upgraded. This happens before any packages have been installed / upgraded / removed.
    ///
    /// See: %pretrans from specfile syntax
    #[inline]
    pub fn pre_trans_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.pre_trans_script = Some(content.into());
        self
    }

    /// Set a script to be executed after a transaction in which the package has been installed
    /// or upgraded. This happens after all packages in the transaction have been installed /
    /// upgraded / removed.
    ///
    /// See: %posttrans from specfile syntax
    #[inline]
    pub fn post_trans_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.post_trans_script = Some(content.into());
        self
    }

    /// Set a script to be executed before a transaction in which the package is being removed or
    /// upgraded. This happens before any packages have been installed / upgraded / removed.
    ///
    /// See: %preuntrans from specfile syntax
    #[inline]
    pub fn pre_untrans_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.pre_untrans_script = Some(content.into());
        self
    }

    /// Set a script to be executed after a transaction in which the package is being removed or
    /// upgraded. This happens after all packages in the transaction have been installed /
    /// upgraded / removed.
    ///
    /// See: %posttrans from specfile syntax
    #[inline]
    pub fn post_untrans_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.post_untrans_script = Some(content.into());
        self
    }

    /// Set a script to be executed during package verification, post-installation or using
    /// `rpm --verify`
    ///
    /// See: `%verifyscript` from specfile syntax
    #[inline]
    pub fn verify_script(&mut self, content: impl Into<Scriptlet>) -> &mut Self {
        self.verify_script = Some(content.into());
        self
    }

    // todo: consider whether a dedicated VersionConstraint type is justified
    // instead of Option<(DependencyFlags, &str)> for the version condition parameter.

    /// Add a `%triggerin` script that fires just after the target package is installed.
    ///
    /// `target` is the package name to trigger on (e.g. `"bash"`). `condition`
    /// optionally restricts which versions of the target will activate the
    /// trigger, corresponding to the `-- target [op version]` syntax in spec
    /// files. For example, `Some((DependencyFlags::GREATER, "5.0"))` matches
    /// `%triggerin -- bash > 5.0` and will only fire when the installed version
    /// of bash is greater than 5.0.
    pub fn trigger_in(
        &mut self,
        target: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERIN | cmp,
            name: target.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%triggerun` script that fires just before the target package is removed.
    ///
    /// See [`trigger_in`](Self::trigger_in) for details on `target` and `condition`.
    pub fn trigger_un(
        &mut self,
        target: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERUN | cmp,
            name: target.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%triggerpostun` script that fires just after the target package is removed.
    ///
    /// See [`trigger_in`](Self::trigger_in) for details on `target` and `condition`.
    pub fn trigger_postun(
        &mut self,
        target: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERPOSTUN | cmp,
            name: target.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%triggerprein` script that fires just before the target package is installed.
    ///
    /// See [`trigger_in`](Self::trigger_in) for details on `target` and `condition`.
    pub fn trigger_prein(
        &mut self,
        target: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERPREIN | cmp,
            name: target.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%filetriggerin` script that fires when a file is installed under the given path.
    ///
    /// `path` is the directory prefix to watch (e.g. `"/usr/lib"`). `condition`
    /// optionally restricts which versions of the package owning the file will
    /// activate the trigger (see [`trigger_in`](Self::trigger_in)).
    pub fn file_trigger_in(
        &mut self,
        path: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.file_triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERIN | cmp,
            name: path.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%filetriggerun` script that fires when a file is removed from the given path.
    ///
    /// See [`file_trigger_in`](Self::file_trigger_in) for details on `path` and `condition`.
    pub fn file_trigger_un(
        &mut self,
        path: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.file_triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERUN | cmp,
            name: path.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%filetriggerpostun` script that fires after a file is removed from the given path.
    ///
    /// See [`file_trigger_in`](Self::file_trigger_in) for details on `path` and `condition`.
    pub fn file_trigger_postun(
        &mut self,
        path: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.file_triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERPOSTUN | cmp,
            name: path.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%transfiletriggerin` script that fires when a file is installed under the given path
    /// (runs once per transaction rather than once per package).
    ///
    /// See [`file_trigger_in`](Self::file_trigger_in) for details on `path` and `condition`.
    pub fn trans_file_trigger_in(
        &mut self,
        path: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.trans_file_triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERIN | cmp,
            name: path.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%transfiletriggerun` script that fires when a file is removed from the given path
    /// (runs once per transaction rather than once per package).
    ///
    /// See [`file_trigger_in`](Self::file_trigger_in) for details on `path` and `condition`.
    pub fn trans_file_trigger_un(
        &mut self,
        path: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.trans_file_triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERUN | cmp,
            name: path.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a `%transfiletriggerpostun` script that fires after a file is removed from the given
    /// path (runs once per transaction rather than once per package).
    ///
    /// See [`file_trigger_in`](Self::file_trigger_in) for details on `path` and `condition`.
    pub fn trans_file_trigger_postun(
        &mut self,
        path: &str,
        condition: Option<(DependencyFlags, &str)>,
        script: impl Into<Scriptlet>,
    ) -> &mut Self {
        let (cmp, ver) = unpack_version_condition(condition);
        self.trans_file_triggers.push(PackageTriggerEntry {
            flags: DependencyFlags::TRIGGERPOSTUN | cmp,
            name: path.to_owned(),
            version: ver,
            script: script.into(),
        });
        self
    }

    /// Add a "provides" dependency
    ///
    /// These are aliases or capabilities provided by this package which other packages can reference.
    pub fn provides(&mut self, dep: Dependency) -> &mut Self {
        self.provides.push(dep);
        self
    }

    /// Add a "requires" dependency
    ///
    /// These are packages or capabilities which must be present in order for the package to be
    /// installed.
    pub fn requires(&mut self, dep: Dependency) -> &mut Self {
        self.requires.push(dep);
        self
    }

    /// Add a "conflicts" dependency
    ///
    /// These are packages which must not be present in order for the package to be installed.
    pub fn conflicts(&mut self, dep: Dependency) -> &mut Self {
        self.conflicts.push(dep);
        self
    }

    /// Add an "obsoletes" dependency
    ///
    /// These are packages this package supercedes - if this package is installed, packages
    /// listed as "obsoletes" will be be automatically removed (if they are present).
    pub fn obsoletes(&mut self, dep: Dependency) -> &mut Self {
        self.obsoletes.push(dep);
        self
    }

    /// Get a list of dependencies which this package "recommends"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat them
    /// as though they were "requires".  Unlike "requires" however, if installing a package listed
    /// as a "recommends" would cause errors, it may be ignored without error.
    pub fn recommends(&mut self, dep: Dependency) -> &mut Self {
        self.recommends.push(dep);
        self
    }

    /// Get a list of dependencies which this package "suggests"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// them to the user to be optionally installed.
    pub fn suggests(&mut self, dep: Dependency) -> &mut Self {
        self.suggests.push(dep);
        self
    }

    /// Get a list of reverse-dependencies which this package "enhances"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// this package to the user to be optionally installed when a package matching the "enhances"
    /// dependency is installed.
    pub fn enhances(&mut self, dep: Dependency) -> &mut Self {
        self.enhances.push(dep);
        self
    }

    /// Get a list of reverse-dependencies which this package "supplements"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat this
    /// package as if it were a "requires" when the matching package is installed. Unlike a
    /// "requires" however, if installing it would cause errors, it can be ignored ignored
    /// without error.
    pub fn supplements(&mut self, dep: Dependency) -> &mut Self {
        self.supplements.push(dep);
        self
    }

    /// Add an ordering hint for package installation/upgrade.
    ///
    /// OrderWithRequires specifies dependencies that should be used for ordering during
    /// installation/upgrade, but does not add them to the regular Requires list.
    /// This is useful for breaking dependency cycles while maintaining proper installation order.
    ///
    /// See: `OrderWithRequires` from specfile syntax
    pub fn order_with_requires(&mut self, dep: Dependency) -> &mut Self {
        self.order_with_requires.push(dep);
        self
    }

    /// Build the package
    pub fn build(&mut self) -> Result<Package, Error> {
        let fmt = self.config.format;
        let reserved_space: Option<u32> = self.config.reserved_space;
        if self.consumed {
            return Err(Error::BuilderReuse);
        }
        let builder = std::mem::take(self);
        self.consumed = true;
        let (lead, header_idx_tag, content) = builder.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;
        let sig_header = {
            let mut builder = SignatureHeaderBuilder::new()
                .format(fmt)
                .reserved_space(reserved_space);

            // V6 packages shouldn't populate the content length header.
            if fmt == RpmFormat::V4 {
                builder = builder.set_content_length(header.len() as u64 + content.len() as u64);
            }

            builder.calculate_digests(&header).build()?
        };

        let metadata = PackageMetadata {
            lead,
            signature: sig_header,
            header: header_idx_tag,
        };

        let pkg = Package {
            metadata,
            payload: content,
        };
        Ok(pkg)
    }

    /// Build the package and sign it with the provided signer
    ///
    /// If `source_date` was configured, that timestamp will be used during generation of the signature
    /// rather than the current one - which makes "reproducible builds" easier.
    ///
    /// See `signature::Signing` for more details.
    #[cfg(feature = "signature-meta")]
    pub fn build_and_sign<S>(&mut self, signer: S) -> Result<Package, Error>
    where
        S: signature::Signing<Signature = Vec<u8>>,
    {
        let source_date = self.config.source_date;
        let now = Timestamp::now();
        let signature_timestamp = match source_date {
            Some(source_date_epoch) if source_date_epoch < now => source_date_epoch,
            _ => now,
        };

        // There's a little bit of duplicate work going on - the header is serialized twice, the header
        // checksum is calculated twice - but the overhead is small enough that it's not worth making
        // the codepath more complicated
        let mut pkg = self.build()?;
        pkg.sign_with_timestamp(signer, signature_timestamp)?;

        Ok(pkg)
    }

    /// prepare all rpm headers including content
    ///
    /// Validate all user-provided metadata before building. Control characters
    /// in metadata cause problems in downstream consumers like XML repository metadata.
    fn pre_build_validation(&self) -> Result<(), Error> {
        use super::util::{reject_control_chars, validate_name, validate_version};

        validate_name(&self.name)?;
        validate_version("version", &self.version)?;
        validate_version("release", &self.release)?;
        reject_control_chars("license", &self.license)?;
        reject_control_chars("arch", &self.arch)?;
        reject_control_chars("summary", &self.summary)?;
        if let Some(ref desc) = self.desc {
            reject_control_chars("description", desc)?;
        }
        if let Some(ref url) = self.url {
            reject_control_chars("url", url)?;
        }
        if let Some(ref vcs) = self.vcs {
            reject_control_chars("vcs", vcs)?;
        }
        if let Some(ref vendor) = self.vendor {
            reject_control_chars("vendor", vendor)?;
        }
        if let Some(ref build_host) = self.build_host {
            reject_control_chars("build_host", build_host)?;
        }
        if let Some(ref cookie) = self.cookie {
            reject_control_chars("cookie", cookie)?;
        }
        if let Some(ref packager) = self.packager {
            reject_control_chars("packager", packager)?;
        }
        if let Some(ref group) = self.group {
            reject_control_chars("group", group)?;
        }
        for (path, entry) in &self.files {
            reject_control_chars("file path", path)?;
            reject_control_chars("file user", &entry.user)?;
            reject_control_chars("file group", &entry.group)?;
            reject_control_chars("file symlink target", &entry.link)?;
        }
        for name in &self.changelog_names {
            reject_control_chars("changelog name", name)?;
        }
        for entry in &self.changelog_entries {
            reject_control_chars("changelog entry", entry)?;
        }
        let all_deps = [
            &self.requires,
            &self.provides,
            &self.conflicts,
            &self.obsoletes,
            &self.recommends,
            &self.suggests,
            &self.enhances,
            &self.supplements,
        ];
        for deps in all_deps {
            for dep in deps {
                reject_control_chars("dependency name", &dep.name)?;
                reject_control_chars("dependency version", &dep.version)?;
            }
        }
        Ok(())
    }

    /// @todo split this into multiple `fn`s, one per `IndexTag`-group.
    fn prepare_data(mut self) -> Result<(Lead, Header<IndexTag>, Vec<u8>), Error> {
        self.pre_build_validation()?;

        // signature depends on header and payload. So we build these two first.
        // then the signature. Then we stitch all together.
        // Lead is not important. just build it here

        let lead = Lead::new(&self.name);

        // Calculate the sha256 of the archive as we write it into the compressor, so that we don't
        // need to keep two copies in memory simultaneously.
        let mut compressor: Compressor = self.config.compression.try_into()?;
        let mut archive = ChecksummingWriter::new(
            &mut compressor,
            &[HashKind::Sha256, HashKind::Sha512, HashKind::Sha3_256],
        );

        let mut ino_index = 1;

        let files_len = self.files.len();
        let mut file_sizes = Vec::with_capacity(files_len);
        let mut file_modes = Vec::with_capacity(files_len);
        let mut file_caps = Vec::with_capacity(files_len);
        let mut file_rdevs = Vec::with_capacity(files_len);
        let mut file_mtimes = Vec::with_capacity(files_len);
        let mut file_hashes = Vec::with_capacity(files_len);
        let mut file_linktos = Vec::with_capacity(files_len);
        let mut file_flags = Vec::with_capacity(files_len);
        let mut file_usernames = Vec::with_capacity(files_len);
        let mut file_groupnames = Vec::with_capacity(files_len);
        let mut file_devices = Vec::with_capacity(files_len);
        let mut file_inodes = Vec::with_capacity(files_len);
        let mut file_langs = Vec::with_capacity(files_len);
        let mut file_verify_flags = Vec::with_capacity(files_len);
        let mut dir_indixes = Vec::with_capacity(files_len);
        let mut base_names = Vec::with_capacity(files_len);
        let mut users_to_create = HashSet::new();
        let mut groups_to_create = HashSet::new();

        let mut combined_file_sizes: u64 = 0;
        let mut uses_file_capabilities = false;

        for (_, entry) in self.files.iter() {
            combined_file_sizes += entry.source.size()?;
        }

        let uses_large_files =
            combined_file_sizes > u32::MAX.into() || self.config.format != RpmFormat::V4;

        // Entries are sorted by path (BTreeMap iteration order) and duplicates are rejected
        // in add_data(). Paths are also normalized there (collapsing slashes, stripping trailing
        // slashes) to ensure deduplication works correctly.
        for (file_index, (cpio_path, entry)) in self.files.iter_mut().enumerate() {
            if entry.caps.is_some() {
                uses_file_capabilities = true;
            }
            if &entry.user != "root" {
                users_to_create.insert(entry.user.clone());
            }
            if &entry.group != "root" {
                groups_to_create.insert(entry.group.clone());
            }
            let is_ghost = entry.flags.contains(FileFlags::GHOST);
            // Ghost files should report size 0 in headers since they have no payload content
            let file_size = entry.source.size()?;
            file_sizes.push(file_size);
            file_modes.push(entry.mode.into());
            file_caps.push(entry.caps.to_owned());
            // The device ID that this file *represents* (st_rdev).
            // Only meaningful for block/character device special files; always 0 otherwise.
            file_rdevs.push(0);
            // The device ID of the filesystem *containing* the file (st_dev), normalized to 1 or 0.
            // Ghost files have no backing file, so their st_dev is 0.
            file_devices.push(if is_ghost { 0 } else { 1 });
            let mtime = match self.config.source_date {
                Some(d) if d < entry.modified_at => d,
                _ => entry.modified_at,
            };
            file_mtimes.push(mtime.into());
            file_linktos.push(entry.link.to_owned());
            file_flags.push(entry.flags.bits());
            file_usernames.push(entry.user.to_owned());
            file_groupnames.push(entry.group.to_owned());
            file_inodes.push(ino_index);
            file_langs.push("".to_string());
            // safe because indexes cannot change after this as the RpmBuilder is consumed
            // the dir is guaranteed to be there - or else there is a logic error
            let index = self
                .directories
                .iter()
                .position(|d| d == &entry.dir)
                .unwrap();
            dir_indixes.push(index as u32);
            base_names.push(entry.base_name.to_owned());
            // Ghost files have certain verify flags cleared
            let verify = if is_ghost {
                FileVerifyFlags::from_bits_retain(
                    entry.verify_flags.bits()
                        & !(FileVerifyFlags::FILEDIGEST
                            | FileVerifyFlags::FILESIZE
                            | FileVerifyFlags::LINKTO
                            | FileVerifyFlags::MTIME)
                            .bits(),
                )
            } else {
                entry.verify_flags
            };
            file_verify_flags.push(verify.bits());

            // Ghost files are not included in the CPIO payload and have no digest.
            // Non-regular files (dirs, symlinks) also have empty digests per RPM convention.
            if is_ghost {
                file_hashes.push(String::new());
                ino_index += 1;
                continue;
            }

            let mut writer = if !uses_large_files {
                payload::Builder::new(cpio_path)
                    .mode(entry.mode.into())
                    .ino(ino_index)
                    .nlink(1)
                    .mtime(mtime.into())
                    .uid(self.uid.unwrap_or(0))
                    .gid(self.gid.unwrap_or(0))
                    .write_cpio(&mut archive, entry.source.size()? as u32)
            } else {
                payload::write_stripped_cpio(&mut archive, file_index as u32, entry.source.size()?)
            };
            // Only regular files have digests; dirs and symlinks get empty strings
            if entry.mode.file_type() == FileType::Regular {
                let mut hash_writer = ChecksummingWriter::new(&mut writer, &[HashKind::Sha256]);
                io::copy(&mut entry.source.try_into_bufread()?, &mut hash_writer)?;
                let hash_value_map = hash_writer.into_digests().0;
                writer.finish()?;
                if let Some(hash_value) = hash_value_map.get(&HashKind::Sha256) {
                    file_hashes.push(hash_value.to_string());
                }
            } else {
                io::copy(&mut entry.source.try_into_bufread()?, &mut writer)?;
                writer.finish()?;
                file_hashes.push(String::new());
            }
            ino_index += 1;
        }
        payload::trailer(&mut archive)?;

        // Auto-provide version uses EVR format: [epoch:]version-release
        let epoch_str = self.epoch.map(|e| e.to_string()).unwrap_or_default();
        let evr = Evr::new(&epoch_str, &self.version, &self.release).to_string();

        self.provides.push(Dependency::eq(self.name.clone(), &evr));
        // Add NAME(ISA) provide for non-noarch packages, matching RPM's %_isa macro behavior.
        // RPM converts the canonical arch name to an ISA string (e.g. x86_64 -> x86-64).
        if let Some(isa) = arch_to_isa(&self.arch) {
            self.provides
                .push(Dependency::eq(format!("{}({})", self.name, isa), &evr));
        }

        // If any file has the config flag, auto-generate config(NAME) provides and requires
        if file_flags.iter().any(|f| f & FileFlags::CONFIG.bits() != 0) {
            self.provides.push(Dependency::config(&self.name, &evr));
            self.requires.push(Dependency::config(&self.name, &evr));
        }

        if self.config.format == RpmFormat::V4 {
            self.requires
                .push(Dependency::rpmlib("CompressedFileNames", "3.0.4-1"));

            self.requires
                .push(Dependency::rpmlib("FileDigests", "4.6.0-1"));

            self.requires
                .push(Dependency::rpmlib("PayloadFilesHavePrefix", "4.0-1"));
        }

        if self.config.compression.compression_type() == CompressionType::Zstd {
            self.requires
                .push(Dependency::rpmlib("PayloadIsZstd", "5.4.18-1"));
        }

        if uses_file_capabilities {
            self.requires
                .push(Dependency::rpmlib("FileCaps", "4.6.1-1".to_owned()));
        }

        if uses_large_files && !self.files.is_empty() {
            self.requires
                .push(Dependency::rpmlib("LargeFiles", "4.12.0-1".to_owned()));
        }

        let has_rich_deps = [
            &self.requires,
            &self.provides,
            &self.conflicts,
            &self.obsoletes,
            &self.recommends,
            &self.suggests,
            &self.enhances,
            &self.supplements,
            &self.order_with_requires,
        ]
        .iter()
        .any(|deps| deps.iter().any(|d| d.name.starts_with('(')));
        if has_rich_deps {
            self.requires
                .push(Dependency::rpmlib("RichDependencies", "4.12.0-1"));
        }

        // user() and group() virtual provides require RPM >= 4.19 (sysusers support).
        // V4 RPMs may target older distros, so use Recommends there for compatibility.
        for user in &users_to_create {
            if self.config.format == RpmFormat::V6 {
                self.requires.push(Dependency::user(user));
            } else {
                self.recommends.push(Dependency::user(user));
            }
        }

        for group in &groups_to_create {
            if self.config.format == RpmFormat::V6 {
                self.requires.push(Dependency::group(group));
            } else {
                self.recommends.push(Dependency::group(group));
            }
        }

        // Auto-generate user(), group(), and groupmember() dependencies from
        // sysusers.d config files, matching RPM 4.19+ behavior.
        //
        // Each sysusers.d line type produces different dependencies:
        //   'u'/'u!' (create user)  -> provides: user(name)=ver, group(name)
        //   'g'      (create group) -> provides: group(name)=ver
        //   'm'      (add to group) -> provides: groupmember(user/group)=ver
        //                              requires: user(name), group(name)
        //
        // We track (file_index, dep_type, dependency) so that the DEPENDSDICT
        // mapping can later record which file generated each dependency.
        // dep_type is b'P' for provides or b'R' for requires.
        let mut file_deps: Vec<(usize, u8, Dependency)> = Vec::new();
        for (file_index, (path, entry)) in self.files.iter().enumerate() {
            if !path.starts_with("./usr/lib/sysusers.d/") || !path.ends_with(".conf") {
                continue;
            }
            let mut content = String::new();
            entry
                .source
                .try_into_bufread()?
                .read_to_string(&mut content)?;

            for line in content.lines() {
                let fields: Vec<&str> = line.split_whitespace().collect();
                let kind = match fields.first() {
                    Some(&k @ ("u" | "u!" | "g" | "m")) => k,
                    _ => continue,
                };
                let name = match fields.get(1) {
                    Some(n) => *n,
                    None => continue,
                };

                // RPM base64-encodes the normalized line (fields rejoined with single spaces)
                // and NUL-pads the input to avoid '=' padding chars in the output, since '='
                // has special meaning in RPM dependency version syntax.
                let normalized = fields.join(" ");
                let len = normalized.len();
                let pad_len = (3 - len % 3) % 3;
                let mut line_bytes = normalized.into_bytes();
                line_bytes.resize(len + pad_len, 0);
                let version = BASE64_STANDARD_NO_PAD.encode(&line_bytes);

                match kind {
                    // 'u' and 'u!' both create a user; 'u!' tells systemd-sysusers
                    // to fully lock the account, but the provides are the same.
                    "u" | "u!" => {
                        let dep = Dependency {
                            name: format!("user({})", name),
                            flags: DependencyFlags::EQUAL | DependencyFlags::FIND_PROVIDES,
                            version,
                        };
                        file_deps.push((file_index, b'P', dep.clone()));
                        self.provides.push(dep);
                        // Creating a user implicitly creates a group with the same name
                        let dep = Dependency {
                            name: format!("group({})", name),
                            flags: DependencyFlags::FIND_PROVIDES,
                            version: "".to_owned(),
                        };
                        file_deps.push((file_index, b'P', dep.clone()));
                        self.provides.push(dep);
                    }
                    "g" => {
                        let dep = Dependency {
                            name: format!("group({})", name),
                            flags: DependencyFlags::EQUAL | DependencyFlags::FIND_PROVIDES,
                            version,
                        };
                        file_deps.push((file_index, b'P', dep.clone()));
                        self.provides.push(dep);
                    }
                    "m" => {
                        // 'm' adds a user to a group, generating a versioned
                        // groupmember(user/group) provide and user()/group() requires.
                        let groupname = match fields.get(2) {
                            Some(g) => *g,
                            None => continue,
                        };
                        let dep = Dependency {
                            name: format!("groupmember({}/{})", name, groupname),
                            flags: DependencyFlags::EQUAL | DependencyFlags::FIND_PROVIDES,
                            version,
                        };
                        file_deps.push((file_index, b'P', dep.clone()));
                        self.provides.push(dep);
                        let dep = Dependency::user(name);
                        file_deps.push((file_index, b'R', dep.clone()));
                        self.requires.push(dep);
                        let dep = Dependency::group(groupname);
                        file_deps.push((file_index, b'R', dep.clone()));
                        self.requires.push(dep);
                    }
                    _ => unreachable!(),
                }
            }
        }

        // Auto-generate interpreter requires for scriptlets.
        // Each scriptlet with a program generates a require with INTERP | <phase>.
        // The explicit `-p` case (e.g. `%post -p /bin/sh`) also adds a bare INTERP require.
        // Done before sorting so that the DEPENDSDICT lookup uses final indices.
        {
            let scriptlet_phases: &[(&Option<Scriptlet>, DependencyFlags)] = &[
                (&self.pre_inst_script, DependencyFlags::SCRIPT_PRE),
                (&self.post_inst_script, DependencyFlags::SCRIPT_POST),
                (&self.pre_uninst_script, DependencyFlags::SCRIPT_PREUN),
                (&self.post_uninst_script, DependencyFlags::SCRIPT_POSTUN),
                (&self.pre_trans_script, DependencyFlags::PRETRANS),
                (&self.post_trans_script, DependencyFlags::POSTTRANS),
                (&self.verify_script, DependencyFlags::SCRIPT_VERIFY),
            ];
            for (scriptlet, phase_flag) in scriptlet_phases {
                if let Some(script) = scriptlet {
                    let interp = script
                        .program
                        .as_ref()
                        .and_then(|p| p.first())
                        .map(|s| s.as_str())
                        .unwrap_or("/bin/sh");
                    let dep = Dependency {
                        name: interp.to_owned(),
                        flags: DependencyFlags::INTERP | *phase_flag,
                        version: String::new(),
                    };
                    if !self.requires.contains(&dep) {
                        self.requires.push(dep);
                    }
                }
            }
        }

        let mut provide_names = Vec::new();
        let mut provide_flags = Vec::new();
        let mut provide_versions = Vec::new();

        // Sort dependency arrays by (name, EVR, flags) to match what RPM does.
        // All dependency types use the same sort.
        sort_deps(&mut self.provides);
        sort_deps(&mut self.requires);

        // Build the file-to-dependency mapping stored in three parallel tags:
        //   FILEDEPENDSX  - per-file start offset into DEPENDSDICT
        //   FILEDEPENDSN  - per-file count of entries in DEPENDSDICT
        //   DEPENDSDICT   - packed (type, index) entries linking files to deps
        //
        // Each DEPENDSDICT entry is a u32 with the dependency type character
        // (e.g. b'P' for provides, b'R' for requires) in the high byte and
        // the index into that type's sorted dependency array in the low 24 bits.
        let mut file_depends_x: Vec<u32> = vec![0; files_len];
        let mut file_depends_n: Vec<u32> = vec![0; files_len];
        let mut depends_dict: Vec<u32> = Vec::new();

        if !file_deps.is_empty() {
            // Sort by file index, then versioned deps before unversioned
            // (matching RPM's dedup behavior for file-level dependencies).
            file_deps.sort_by(|(fi_a, _, dep_a), (fi_b, _, dep_b)| {
                fi_a.cmp(fi_b).then_with(|| {
                    let a_versioned = !dep_a.version.is_empty();
                    let b_versioned = !dep_b.version.is_empty();
                    b_versioned.cmp(&a_versioned) // versioned first
                })
            });

            for (file_idx, dep_type, dep) in &file_deps {
                // Look up this dependency's post-sort index in the appropriate array
                let dep_array = match *dep_type {
                    b'P' => &self.provides,
                    b'R' => &self.requires,
                    _ => unreachable!(),
                };
                let dep_idx = dep_array
                    .iter()
                    .position(|d| d == dep)
                    .expect("file dependency not found after sort");

                // DEPENDSDICT entries pack a dependency type tag in the high byte
                // and the index into that type's array in the low 24 bits.
                let dict_entry = (*dep_type as u32) << 24 | (dep_idx as u32 & 0x00ff_ffff);

                // Record this file's starting offset in DEPENDSDICT on its first
                // dependency, and bump its entry count for each subsequent one.
                if file_depends_n[*file_idx] == 0 {
                    file_depends_x[*file_idx] = depends_dict.len() as u32;
                }
                file_depends_n[*file_idx] += 1;
                depends_dict.push(dict_entry);
            }
        }

        for d in self.provides.into_iter() {
            provide_names.push(d.name);
            provide_flags.push(d.flags.bits());
            provide_versions.push(d.version);
        }

        let mut obsolete_names = Vec::new();
        let mut obsolete_flags = Vec::new();
        let mut obsolete_versions = Vec::new();

        sort_deps(&mut self.obsoletes);
        for d in self.obsoletes.into_iter() {
            obsolete_names.push(d.name);
            obsolete_flags.push(d.flags.bits());
            obsolete_versions.push(d.version);
        }

        let mut require_names = Vec::new();
        let mut require_flags = Vec::new();
        let mut require_versions = Vec::new();

        for d in self.requires.into_iter() {
            require_names.push(d.name);
            require_flags.push(d.flags.bits());
            require_versions.push(d.version);
        }

        let mut conflicts_names = Vec::new();
        let mut conflicts_flags = Vec::new();
        let mut conflicts_versions = Vec::new();

        sort_deps(&mut self.conflicts);
        for d in self.conflicts.into_iter() {
            conflicts_names.push(d.name);
            conflicts_flags.push(d.flags.bits());
            conflicts_versions.push(d.version);
        }

        let mut recommends_names = Vec::new();
        let mut recommends_flags = Vec::new();
        let mut recommends_versions = Vec::new();

        sort_deps(&mut self.recommends);
        for d in self.recommends.into_iter() {
            recommends_names.push(d.name);
            recommends_flags.push(d.flags.bits());
            recommends_versions.push(d.version);
        }

        let mut suggests_names = Vec::new();
        let mut suggests_flags = Vec::new();
        let mut suggests_versions = Vec::new();

        sort_deps(&mut self.suggests);
        for d in self.suggests.into_iter() {
            suggests_names.push(d.name);
            suggests_flags.push(d.flags.bits());
            suggests_versions.push(d.version);
        }

        let mut enhances_names = Vec::new();
        let mut enhances_flags = Vec::new();
        let mut enhances_versions = Vec::new();

        sort_deps(&mut self.enhances);
        for d in self.enhances.into_iter() {
            enhances_names.push(d.name);
            enhances_flags.push(d.flags.bits());
            enhances_versions.push(d.version);
        }

        let mut supplements_names = Vec::new();
        let mut supplements_flags = Vec::new();
        let mut supplements_versions = Vec::new();

        sort_deps(&mut self.supplements);
        for d in self.supplements.into_iter() {
            supplements_names.push(d.name);
            supplements_flags.push(d.flags.bits());
            supplements_versions.push(d.version);
        }

        let mut order_names = Vec::new();
        let mut order_flags = Vec::new();
        let mut order_versions = Vec::new();

        sort_deps(&mut self.order_with_requires);
        for d in self.order_with_requires.into_iter() {
            order_names.push(d.name);
            order_flags.push(d.flags.bits());
            order_versions.push(d.version);
        }

        // Compute SOURCENEVR for v6 packages (do it early because the values get moved)
        let source_nevr = if self.config.format == RpmFormat::V6 {
            Some(if let Some(epoch_val) = self.epoch {
                format!(
                    "{}-{}:{}-{}",
                    self.name, epoch_val, self.version, self.release
                )
            } else {
                format!("{}-{}-{}", self.name, self.version, self.release)
            })
        } else {
            None
        };

        let mut actual_records = vec![
            // Existence of this tag is how rpm decides whether or not a package is a source rpm or binary rpm
            // If the SOURCERPM tag is set, then the package is seen as a binary rpm.
            IndexEntry::new(
                IndexTag::RPMTAG_SOURCERPM,
                IndexData::StringTag("(none)".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_HEADERI18NTABLE,
                IndexData::StringArray(vec!["C".to_string()]),
            ),
            IndexEntry::new(IndexTag::RPMTAG_NAME, IndexData::StringTag(self.name)),
            IndexEntry::new(
                IndexTag::RPMTAG_RPMVERSION,
                IndexData::StringTag(format!("rpm-rs {}", env!("CARGO_PKG_VERSION"))),
            ),
            // @todo: write RPMTAG_PLATFORM?
            IndexEntry::new(IndexTag::RPMTAG_VERSION, IndexData::StringTag(self.version)),
            IndexEntry::new(IndexTag::RPMTAG_RELEASE, IndexData::StringTag(self.release)),
            IndexEntry::new(
                IndexTag::RPMTAG_DESCRIPTION,
                IndexData::I18NString(vec![self.desc.unwrap_or_else(|| self.summary.clone())]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_SUMMARY,
                IndexData::I18NString(vec![self.summary]),
            ),
            if uses_large_files {
                IndexEntry::new(
                    IndexTag::RPMTAG_LONGSIZE,
                    IndexData::Int64(vec![combined_file_sizes]),
                )
            } else {
                let combined_file_sizes = combined_file_sizes
                    .try_into()
                    .expect("combined_file_sizes should be smaller than 4 GiB");
                IndexEntry::new(
                    IndexTag::RPMTAG_SIZE,
                    IndexData::Int32(vec![combined_file_sizes]),
                )
            },
            IndexEntry::new(IndexTag::RPMTAG_LICENSE, IndexData::StringTag(self.license)),
            IndexEntry::new(
                IndexTag::RPMTAG_OS,
                IndexData::StringTag("linux".to_string()),
            ),
            // @todo: Fedora packaging guidelines recommend against using %group <https://fedoraproject.org/wiki/RPMGroups>
            // If it's legacy and safe to drop entirely let's do so. rpmbuild still writes it in the header though.
            IndexEntry::new(
                IndexTag::RPMTAG_GROUP,
                IndexData::I18NString(vec![
                    self.group
                        .clone()
                        .unwrap_or_else(|| "Unspecified".to_string()),
                ]),
            ),
            IndexEntry::new(IndexTag::RPMTAG_ARCH, IndexData::StringTag(self.arch)),
            IndexEntry::new(
                IndexTag::RPMTAG_ENCODING,
                IndexData::StringTag("utf-8".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFORMAT,
                IndexData::StringTag("cpio".to_string()),
            ),
        ];

        // Only add epoch if explicitly set (even if 0)
        if let Some(e) = self.epoch {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_EPOCH,
                IndexData::Int32(vec![e]),
            ));
        }

        let now = Timestamp::now();
        let build_time = match self.config.source_date {
            Some(t) if t < now => t,
            _ => now,
        };
        actual_records.push(IndexEntry::new(
            IndexTag::RPMTAG_BUILDTIME,
            IndexData::Int32(vec![build_time.into()]),
        ));

        if let Some(build_host) = self.build_host {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_BUILDHOST,
                IndexData::StringTag(build_host),
            ));
        }

        // if we have an empty RPM, we have to leave out all file related index entries.
        if !self.files.is_empty() {
            let size_entry = if uses_large_files {
                IndexEntry::new(IndexTag::RPMTAG_LONGFILESIZES, IndexData::Int64(file_sizes))
            } else {
                let file_sizes = file_sizes
                    .into_iter()
                    .map(u32::try_from)
                    .collect::<Result<_, _>>()
                    .expect(
                        "combined_file_sizes and thus all file sizes \
                         should be smaller than 4 GiB",
                    );
                IndexEntry::new(IndexTag::RPMTAG_FILESIZES, IndexData::Int32(file_sizes))
            };
            actual_records.extend([
                size_entry,
                IndexEntry::new(IndexTag::RPMTAG_FILEMODES, IndexData::Int16(file_modes)),
                IndexEntry::new(IndexTag::RPMTAG_FILERDEVS, IndexData::Int16(file_rdevs)),
                IndexEntry::new(IndexTag::RPMTAG_FILEMTIMES, IndexData::Int32(file_mtimes)),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDIGESTS,
                    IndexData::StringArray(file_hashes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILELINKTOS,
                    IndexData::StringArray(file_linktos),
                ),
                IndexEntry::new(IndexTag::RPMTAG_FILEFLAGS, IndexData::Int32(file_flags)),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEUSERNAME,
                    IndexData::StringArray(file_usernames),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEGROUPNAME,
                    IndexData::StringArray(file_groupnames),
                ),
                IndexEntry::new(IndexTag::RPMTAG_FILEDEVICES, IndexData::Int32(file_devices)),
                IndexEntry::new(IndexTag::RPMTAG_FILEINODES, IndexData::Int32(file_inodes)),
                IndexEntry::new(IndexTag::RPMTAG_DIRINDEXES, IndexData::Int32(dir_indixes)),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILELANGS,
                    IndexData::StringArray(file_langs),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEVERIFYFLAGS,
                    IndexData::Int32(file_verify_flags),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_BASENAMES,
                    IndexData::StringArray(base_names),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_DIRNAMES,
                    IndexData::StringArray(self.directories.into_iter().collect()),
                ),
            ]);
            if file_caps.iter().any(|caps| caps.is_some()) {
                actual_records.extend([IndexEntry::new(
                    IndexTag::RPMTAG_FILECAPS,
                    IndexData::StringArray(
                        file_caps
                            .iter()
                            .map(|f| match f {
                                Some(caps) => caps.to_string(),
                                None => "".to_string(),
                            })
                            .collect::<Vec<String>>(),
                    ),
                )])
            }
        }

        // RPM always adds this tag, even if the package has no files. We will do the same.
        actual_records.push(IndexEntry::new(
            IndexTag::RPMTAG_FILEDIGESTALGO,
            IndexData::Int32(vec![DigestAlgorithm::Sha2_256 as u32]),
        ));

        actual_records.extend([
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDENAME,
                IndexData::StringArray(provide_names),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEVERSION,
                IndexData::StringArray(provide_versions),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEFLAGS,
                IndexData::Int32(provide_flags),
            ),
        ]);

        if !depends_dict.is_empty() {
            actual_records.extend([
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDEPENDSX,
                    IndexData::Int32(file_depends_x),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDEPENDSN,
                    IndexData::Int32(file_depends_n),
                ),
                IndexEntry::new(IndexTag::RPMTAG_DEPENDSDICT, IndexData::Int32(depends_dict)),
            ]);
        }

        // digest of the uncompressed raw archive calculated on the inner writer
        let (hash_values, raw_archive_size) = archive.into_digests();
        let payload = compressor.finish_compression()?;

        // digest of the post-compression archive (payload)
        let payload_sha256 = {
            let mut hasher = sha2::Sha256::default();
            hasher.update(payload.as_slice());
            hex::encode(hasher.finalize())
        };

        let payload_sha512 = {
            let mut hasher = sha2::Sha512::default();
            hasher.update(payload.as_slice());
            hex::encode(hasher.finalize())
        };

        let payload_sha3_256 = {
            let mut hasher = sha3::Sha3_256::default();
            hasher.update(payload.as_slice());
            hex::encode(hasher.finalize())
        };

        if let Some(raw_archive_sha256) = hash_values.get(&HashKind::Sha256) {
            // RPM uses array types for RPMTAG_PAYLOADSHA256 and friends, but switched to string types when
            // adding new payload checksum types.
            actual_records.extend([
                IndexEntry::new(
                    IndexTag::RPMTAG_PAYLOADSHA256,
                    IndexData::StringArray(vec![payload_sha256]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PAYLOADSHA256ALT,
                    IndexData::StringArray(vec![raw_archive_sha256.to_string()]),
                ),
            ]);
            // PAYLOADSHA256ALGO is obsolete and not used in v6 packages
            if self.config.format == RpmFormat::V4 {
                actual_records.push(IndexEntry::new(
                    IndexTag::RPMTAG_PAYLOADSHA256ALGO,
                    IndexData::Int32(vec![DigestAlgorithm::Sha2_256 as u32]),
                ));
            }
        }

        if self.config.format == RpmFormat::V6 {
            if let Some(nevr) = source_nevr {
                actual_records.push(IndexEntry::new(
                    IndexTag::RPMTAG_SOURCENEVR,
                    IndexData::StringTag(nevr),
                ));
            }
            actual_records.extend([
                IndexEntry::new(IndexTag::RPMTAG_RPMFORMAT, IndexData::Int32(vec![6])),
                IndexEntry::new(
                    IndexTag::RPMTAG_PAYLOADSIZE,
                    IndexData::Int64(vec![payload.len() as u64]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_PAYLOADSIZEALT,
                    IndexData::Int64(vec![raw_archive_size as u64]),
                ),
            ]);
            if let Some(raw_archive_sha3_256) = hash_values.get(&HashKind::Sha3_256) {
                actual_records.extend([
                    IndexEntry::new(
                        IndexTag::RPMTAG_PAYLOAD_SHA3_256,
                        IndexData::StringTag(payload_sha3_256),
                    ),
                    IndexEntry::new(
                        IndexTag::RPMTAG_PAYLOAD_SHA3_256_ALT,
                        IndexData::StringTag(raw_archive_sha3_256.to_string()),
                    ),
                ]);
            }
            if let Some(raw_archive_sha512) = hash_values.get(&HashKind::Sha512) {
                actual_records.extend([
                    IndexEntry::new(
                        IndexTag::RPMTAG_PAYLOAD_SHA512,
                        IndexData::StringTag(payload_sha512),
                    ),
                    IndexEntry::new(
                        IndexTag::RPMTAG_PAYLOAD_SHA512_ALT,
                        IndexData::StringTag(raw_archive_sha512.to_string()),
                    ),
                ]);
            }
        }

        // RPM always writes payloadflags unconditionally. That is a little silly, but we will do the same
        let (compression_name, compression_flags) = match self.config.compression {
            CompressionWithLevel::None => (None, String::new()),
            CompressionWithLevel::Gzip(level) => (Some("gzip".to_owned()), level.to_string()),
            CompressionWithLevel::Zstd(level) => (Some("zstd".to_owned()), level.to_string()),
            CompressionWithLevel::Xz(level) => (Some("xz".to_owned()), level.to_string()),
            CompressionWithLevel::Bzip2(level) => (Some("bzip2".to_owned()), level.to_string()),
        };

        if let Some(compression_name) = compression_name {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
                IndexData::StringTag(compression_name),
            ));
        }
        actual_records.push(IndexEntry::new(
            IndexTag::RPMTAG_PAYLOADFLAGS,
            IndexData::StringTag(compression_flags),
        ));

        if !self.changelog_names.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGNAME,
                IndexData::StringArray(self.changelog_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTEXT,
                IndexData::StringArray(self.changelog_entries),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTIME,
                IndexData::Int32(self.changelog_times.into_iter().map(Into::into).collect()),
            ));
        }

        if !obsolete_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETENAME,
                IndexData::StringArray(obsolete_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEVERSION,
                IndexData::StringArray(obsolete_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEFLAGS,
                IndexData::Int32(obsolete_flags),
            ));
        }

        if !require_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIRENAME,
                IndexData::StringArray(require_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREVERSION,
                IndexData::StringArray(require_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREFLAGS,
                IndexData::Int32(require_flags),
            ));
        }

        if !conflicts_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTNAME,
                IndexData::StringArray(conflicts_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTVERSION,
                IndexData::StringArray(conflicts_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTFLAGS,
                IndexData::Int32(conflicts_flags),
            ));
        }

        if !recommends_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_RECOMMENDNAME,
                IndexData::StringArray(recommends_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_RECOMMENDVERSION,
                IndexData::StringArray(recommends_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_RECOMMENDFLAGS,
                IndexData::Int32(recommends_flags),
            ));
        }

        if !suggests_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUGGESTNAME,
                IndexData::StringArray(suggests_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUGGESTVERSION,
                IndexData::StringArray(suggests_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUGGESTFLAGS,
                IndexData::Int32(suggests_flags),
            ));
        }

        if !enhances_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ENHANCENAME,
                IndexData::StringArray(enhances_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ENHANCEVERSION,
                IndexData::StringArray(enhances_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ENHANCEFLAGS,
                IndexData::Int32(enhances_flags),
            ));
        }

        if !supplements_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUPPLEMENTNAME,
                IndexData::StringArray(supplements_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUPPLEMENTVERSION,
                IndexData::StringArray(supplements_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUPPLEMENTFLAGS,
                IndexData::Int32(supplements_flags),
            ));
        }

        if !order_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ORDERNAME,
                IndexData::StringArray(order_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ORDERVERSION,
                IndexData::StringArray(order_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ORDERFLAGS,
                IndexData::Int32(order_flags),
            ));
        }

        if let Some(script) = self.pre_inst_script {
            script.apply(&mut actual_records, PREIN_TAGS);
        }

        if let Some(script) = self.post_inst_script {
            script.apply(&mut actual_records, POSTIN_TAGS);
        }

        if let Some(script) = self.pre_uninst_script {
            script.apply(&mut actual_records, PREUN_TAGS);
        }

        if let Some(script) = self.post_uninst_script {
            script.apply(&mut actual_records, POSTUN_TAGS);
        }

        if let Some(script) = self.pre_trans_script {
            script.apply(&mut actual_records, PRETRANS_TAGS);
        }

        if let Some(script) = self.post_trans_script {
            script.apply(&mut actual_records, POSTTRANS_TAGS);
        }

        if let Some(script) = self.pre_untrans_script {
            script.apply(&mut actual_records, PREUNTRANS_TAGS);
        }

        if let Some(script) = self.post_untrans_script {
            script.apply(&mut actual_records, POSTUNTRANS_TAGS);
        }

        if let Some(script) = self.verify_script {
            script.apply(&mut actual_records, VERIFYSCRIPT_TAGS);
        }

        // Serialize package triggers
        serialize_triggers(&self.triggers, &mut actual_records, TRIGGER_TAGS, None);

        // Serialize file triggers
        serialize_triggers(
            &self.file_triggers,
            &mut actual_records,
            FILETRIGGER_TAGS,
            Some(IndexTag::RPMTAG_FILETRIGGERPRIORITIES),
        );

        // Serialize transaction file triggers
        serialize_triggers(
            &self.trans_file_triggers,
            &mut actual_records,
            TRANSFILETRIGGER_TAGS,
            Some(IndexTag::RPMTAG_TRANSFILETRIGGERPRIORITIES),
        );

        if let Some(vendor) = self.vendor {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_VENDOR,
                IndexData::StringTag(vendor),
            ));
        }

        if let Some(packager) = self.packager {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PACKAGER,
                IndexData::StringTag(packager),
            ));
        }

        if let Some(url) = self.url {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_URL,
                IndexData::StringTag(url),
            ));
        }

        if let Some(vcs) = self.vcs {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_VCS,
                IndexData::StringTag(vcs),
            ));
        }

        if let Some(cookie) = self.cookie {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_COOKIE,
                IndexData::StringTag(cookie),
            ));
        }

        let header = Header::from_entries(actual_records, IndexTag::RPMTAG_HEADERIMMUTABLE);

        Ok((lead, header, payload))
    }
}

/// Extract comparison flags and version string from an optional version condition.
/// Sort dependencies by (name, EVR, flags) to match what RPM does. Uses a lexicographic
/// sort, not a version-aware one.
fn sort_deps(deps: &mut [Dependency]) {
    deps.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then_with(|| a.version.cmp(&b.version))
            .then_with(|| a.flags.bits().cmp(&b.flags.bits()))
    });
}

fn unpack_version_condition(
    condition: Option<(DependencyFlags, &str)>,
) -> (DependencyFlags, String) {
    match condition {
        Some((cmp, ver)) => (cmp, ver.to_owned()),
        None => (DependencyFlags::empty(), String::new()),
    }
}

/// Add a list of trigger entries into RPM header index entries.
///
/// Each trigger family (package triggers, file triggers, trans file triggers) uses
/// the same parallel-array structure but with different tag sets.
/// If `priority_tag` is provided, a priorities array is also written (used by file triggers).
fn serialize_triggers(
    triggers: &[PackageTriggerEntry],
    records: &mut Vec<IndexEntry<IndexTag>>,
    tags: TriggerIndexTags,
    priority_tag: Option<IndexTag>,
) {
    if triggers.is_empty() {
        return;
    }

    let (scripts_tag, progs_tag, _flags_tag, names_tag, versions_tag, cond_flags_tag, index_tag) =
        tags;

    // Scripts and progs arrays preserve insertion order (one entry per trigger).
    let mut scripts = Vec::with_capacity(triggers.len());
    let mut progs = Vec::with_capacity(triggers.len());
    for entry in triggers {
        scripts.push(entry.script.script.clone());
        progs.push(
            entry
                .script
                .program
                .as_ref()
                .and_then(|p| p.first().cloned())
                .unwrap_or_else(|| "/bin/sh".to_owned()),
        );
    }

    // Condition arrays (names, versions, flags, indices) are sorted to match RPM's ordering:
    // by (name, version, flags, index)
    let mut condition_order: Vec<usize> = (0..triggers.len()).collect();
    condition_order.sort_by(|&a, &b| {
        let ea = &triggers[a];
        let eb = &triggers[b];
        ea.name
            .cmp(&eb.name)
            .then(ea.version.cmp(&eb.version))
            .then(ea.flags.bits().cmp(&eb.flags.bits()))
            .then(a.cmp(&b))
    });

    let mut names = Vec::with_capacity(triggers.len());
    let mut versions = Vec::with_capacity(triggers.len());
    let mut cond_flags = Vec::with_capacity(triggers.len());
    let mut indices = Vec::with_capacity(triggers.len());
    for &i in &condition_order {
        let entry = &triggers[i];
        names.push(entry.name.clone());
        versions.push(entry.version.clone());
        cond_flags.push(entry.flags.bits());
        indices.push(i as u32); // maps back to the script at the original position
    }

    records.push(IndexEntry::new(
        scripts_tag,
        IndexData::StringArray(scripts),
    ));
    records.push(IndexEntry::new(progs_tag, IndexData::StringArray(progs)));
    records.push(IndexEntry::new(names_tag, IndexData::StringArray(names)));
    records.push(IndexEntry::new(
        versions_tag,
        IndexData::StringArray(versions),
    ));
    records.push(IndexEntry::new(
        cond_flags_tag,
        IndexData::Int32(cond_flags),
    ));
    records.push(IndexEntry::new(index_tag, IndexData::Int32(indices)));

    if let Some(prio_tag) = priority_tag {
        records.push(IndexEntry::new(
            prio_tag,
            IndexData::Int32(vec![1000000u32; triggers.len()]),
        ));
    }
}

/// Convert a canonical RPM architecture name to its ISA (Instruction Set Architecture) string.
///
/// This is conceptually similar to RPM's `installplatform` dependency generator script.
///
/// RPM uses ISA strings in auto-generated provides like `NAME(ISA)`. The ISA is formed as
/// `ISANAME-ISABITS` (e.g. `x86-64` for `x86_64`). Returns `None` for `noarch` and
/// unrecognized architectures.
fn arch_to_isa(arch: &str) -> Option<&'static str> {
    match arch {
        // x86
        "x86_64" | "amd64" | "ia32e" => Some("x86-64"),
        "i386" | "i486" | "i586" | "i686" | "athlon" | "geode" => Some("x86-32"),
        // ARM
        "aarch64" => Some("aarch-64"),
        "armv7hl" | "armv7hnl" => Some("armv7hl-32"),
        // Power
        "ppc64" | "ppc64p7" => Some("ppc-64"),
        "ppc64le" => Some("ppc-64"),
        "ppc" => Some("ppc-32"),
        // s390
        "s390x" => Some("s390-64"),
        "s390" => Some("s390-32"),
        // RISC-V
        "riscv64" => Some("riscv-64"),
        // LoongArch
        "loongarch64" => Some("loongarch-64"),
        // MIPS
        "mips64" | "mips64el" => Some("mips-64"),
        "mips" | "mipsel" => Some("mips-32"),
        "mips64r6" | "mips64r6el" => Some("mipsr6-64"),
        "mipsr6" | "mipsr6el" => Some("mipsr6-32"),
        // SPARC
        "sparc64" | "sparc64v" => Some("sparc-64"),
        "sparc" | "sparcv8" | "sparcv9" | "sparcv9v" => Some("sparc-32"),
        // Other
        "ia64" => Some("ia-64"),
        "alpha" | "alphaev5" | "alphaev56" | "alphaev6" | "alphaev67" | "alphapca56" => {
            Some("alpha-64")
        }
        "m68k" => Some("m68k-32"),
        "e2k" | "e2kv4" | "e2kv5" | "e2kv6" | "e2kv7" => Some("e2k-64"),
        // noarch and unknown
        _ => None,
    }
}
