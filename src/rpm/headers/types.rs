//! A collection of types used in various header records.
#[cfg(feature = "payload")]
use crate::{IndexData, IndexEntry};
use crate::{constants::*, errors};
use itertools::Itertools;
/// Offsets into an RPM Package (from the start of the file) demarking locations of each section
///
/// See: `Package::get_package_segment_offsets`
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PackageSegmentOffsets {
    pub lead: u64,
    pub signature_header: u64,
    pub header: u64,
    pub payload: u64,
}

/// The type of a file entry in an RPM package.
#[non_exhaustive]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum FileType {
    Regular,
    Dir,
    SymbolicLink,
    /// A file type not directly handled by this library (e.g. block/char devices, FIFOs, sockets).
    Other,
}

/// A file mode combining file type and permission bits, as stored in RPM headers.
///
/// See <https://man7.org/linux/man-pages/man7/inode.7.html> section "The file type and mode"
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub struct FileMode(u16);

const FILE_TYPE_BIT_MASK: u16 = 0o170000; // bit representation = "1111000000000000"
const PERMISSIONS_BIT_MASK: u16 = 0o7777; // bit representation = "0000111111111111"
pub const REGULAR_FILE_TYPE: u16 = 0o100000; //  bit representation = "1000000000000000"
pub const DIR_FILE_TYPE: u16 = 0o040000; //      bit representation = "0100000000000000"
pub const SYMBOLIC_LINK_FILE_TYPE: u16 = 0o120000; // bit representation = "1010000000000000"

impl From<u16> for FileMode {
    fn from(raw_mode: u16) -> Self {
        FileMode(raw_mode)
    }
}

impl TryFrom<i32> for FileMode {
    type Error = errors::Error;

    fn try_from(raw_mode: i32) -> Result<Self, Self::Error> {
        if raw_mode > u16::MAX.into() || raw_mode < i16::MIN.into() {
            Err(errors::Error::InvalidFileMode {
                raw_mode,
                reason: "provided integer is out of 16bit bounds",
            })
        } else {
            Ok(FileMode(raw_mode as u16))
        }
    }
}

impl FileMode {
    /// Create a regular file mode. `permissions` will be masked to 0o7777.
    pub fn regular(permissions: u16) -> Self {
        FileMode(REGULAR_FILE_TYPE | (permissions & PERMISSIONS_BIT_MASK))
    }

    /// Create a directory mode. `permissions` will be masked to 0o7777.
    pub fn dir(permissions: u16) -> Self {
        FileMode(DIR_FILE_TYPE | (permissions & PERMISSIONS_BIT_MASK))
    }

    /// Create a symbolic link mode. `permissions` will be masked to 0o7777.
    pub fn symbolic_link(permissions: u16) -> Self {
        FileMode(SYMBOLIC_LINK_FILE_TYPE | (permissions & PERMISSIONS_BIT_MASK))
    }

    /// Set the permission bits, preserving the file type. Values greater than 0o7777 will be masked.
    pub fn set_permissions(&mut self, permissions: u16) {
        self.0 = self.raw_file_type() | (permissions & PERMISSIONS_BIT_MASK);
    }

    /// Returns the complete raw mode (type + permissions bits).
    pub fn raw_mode(&self) -> u16 {
        self.0
    }

    /// Returns the [`FileType`] of this mode.
    pub fn file_type(&self) -> FileType {
        match self.0 & FILE_TYPE_BIT_MASK {
            DIR_FILE_TYPE => FileType::Dir,
            REGULAR_FILE_TYPE => FileType::Regular,
            SYMBOLIC_LINK_FILE_TYPE => FileType::SymbolicLink,
            _ => FileType::Other,
        }
    }

    /// Returns the raw file type bits from the mode.
    pub fn raw_file_type(&self) -> u16 {
        self.0 & FILE_TYPE_BIT_MASK
    }

    /// Returns the permission bits (including setuid/setgid/sticky).
    pub fn permissions(&self) -> u16 {
        self.0 & PERMISSIONS_BIT_MASK
    }
}

impl From<FileMode> for u32 {
    fn from(mode: FileMode) -> Self {
        mode.raw_mode() as u32
    }
}

impl From<FileMode> for u16 {
    fn from(mode: FileMode) -> Self {
        mode.raw_mode()
    }
}

#[cfg(feature = "payload")]
mod build_types {
    use std::fs::{self, File};
    use std::io::{self, BufRead, BufReader, Cursor};
    use std::path::PathBuf;
    use std::str::FromStr;

    use super::*;
    use crate::{FileCaps, Timestamp, errors};

    /// Define rpm content type source, from file path or raw bytes data.
    pub enum ContentSource {
        Path(PathBuf),
        Raw(Vec<u8>),
        /// No content - used for directories, symlinks, and ghost files
        None,
    }

    impl ContentSource {
        /// get type which impl BufRead
        pub fn try_into_bufread(&self) -> io::Result<Box<dyn BufRead + '_>> {
            match self {
                Self::Path(p) => Ok(Box::new(BufReader::new(File::open(p)?))),
                Self::Raw(v) => Ok(Box::new(Cursor::new(v))),
                Self::None => Ok(Box::new(Cursor::new(&[] as &[u8]))),
            }
        }

        pub fn size(&self) -> io::Result<u64> {
            match self {
                Self::Path(p) => fs::metadata(p).map(|m| m.len()),
                Self::Raw(v) => Ok(v.len() as u64),
                Self::None => Ok(0),
            }
        }
    }

    /// Describes a file present in the rpm file.
    pub struct PackageFileEntry {
        pub mode: FileMode,
        pub modified_at: Timestamp,
        pub link: String,
        pub flags: FileFlags,
        pub user: String,
        pub group: String,
        pub base_name: String,
        pub dir: String,
        pub caps: Option<FileCaps>,
        pub verify_flags: FileVerifyFlags,
        pub source: ContentSource,
        /// Whether this entry was added by a bulk operation (e.g. `with_dir`).
        /// Bulk-added entries can be replaced by explicit methods like `with_file`.
        pub(crate) bulk_added: bool,
    }

    #[derive(Debug)]
    pub struct FileOptions {
        pub(crate) destination: String,
        /// `None` means use the builder's default user.
        pub(crate) user: Option<String>,
        /// `None` means use the builder's default group.
        pub(crate) group: Option<String>,
        pub(crate) symlink: String,
        pub(crate) mode: FileMode,
        pub(crate) flag: FileFlags,
        pub(crate) use_default_permissions: bool,
        pub(crate) caps: Option<FileCaps>,
        pub(crate) verify_flags: FileVerifyFlags,
    }

    impl FileOptions {
        /// Create a new FileOptions for a regular file which will be placed at the provided path.
        ///
        /// By default, files will be owned by the "root" user and group, and inherit their permissions
        /// from the on-disk file.
        #[allow(clippy::new_ret_no_self)]
        pub fn new(dest: impl Into<String>) -> FileOptionsBuilder {
            FileOptionsBuilder {
                inner: FileOptions {
                    destination: dest.into(),
                    user: None,
                    group: None,
                    symlink: "".to_string(),
                    mode: FileMode::regular(0o644),
                    flag: FileFlags::empty(),
                    use_default_permissions: true,
                    caps: None,
                    verify_flags: FileVerifyFlags::ALL_FLAGS,
                },
            }
        }

        /// Create a new FileOptions for a directory at the provided path.
        ///
        /// Directories do not require any content source. Use with
        /// [`PackageBuilder::with_dir_entry()`] to add a directory entry.
        ///
        /// Default permissions are 0o755.
        pub fn dir(dest: impl Into<String>) -> FileOptionsBuilder {
            FileOptionsBuilder {
                inner: FileOptions {
                    destination: dest.into(),
                    user: None,
                    group: None,
                    symlink: "".to_string(),
                    mode: FileMode::dir(0o755),
                    flag: FileFlags::empty(),
                    use_default_permissions: true,
                    caps: None,
                    verify_flags: FileVerifyFlags::ALL_FLAGS,
                },
            }
        }

        /// Create a new FileOptions for a symbolic link.
        ///
        /// `dest` is the path where the symlink will be created.
        /// `target` is the path the symlink points to.
        ///
        /// Symlinks do not require any content source. Use with
        /// [`PackageBuilder::with_file_contents()`] (passing empty content) or
        /// [`PackageBuilder::with_symlink()`].
        pub fn symlink(dest: impl Into<String>, target: impl Into<String>) -> FileOptionsBuilder {
            FileOptionsBuilder {
                inner: FileOptions {
                    destination: dest.into(),
                    user: None,
                    group: None,
                    symlink: target.into(),
                    mode: FileMode::symbolic_link(0o777),
                    flag: FileFlags::empty(),
                    use_default_permissions: false,
                    caps: None,
                    verify_flags: FileVerifyFlags::ALL_FLAGS,
                },
            }
        }

        /// Create a new FileOptions for a ghost file at the provided path.
        ///
        /// Ghost files are not included in the package payload, but their metadata
        /// (ownership, permissions, etc.) is tracked by RPM. This is commonly used
        /// for files that are created at runtime, such as log files or PID files.
        ///
        /// Use with [`PackageBuilder::with_ghost()`].
        ///
        /// Default permissions are 0 (no permission bits), matching RPM's behavior for
        /// ghost files that don't exist on disk.
        pub fn ghost(dest: impl Into<String>) -> FileOptionsBuilder {
            FileOptionsBuilder {
                inner: FileOptions {
                    destination: dest.into(),
                    user: None,
                    group: None,
                    symlink: "".to_string(),
                    mode: FileMode::regular(0),
                    flag: FileFlags::GHOST,
                    use_default_permissions: true,
                    caps: None,
                    // Ghost files can't verify content-related attributes since they don't exist in the payload
                    verify_flags: FileVerifyFlags::ALL_FLAGS
                        & !(FileVerifyFlags::FILEDIGEST
                            | FileVerifyFlags::FILESIZE
                            | FileVerifyFlags::LINKTO
                            | FileVerifyFlags::MTIME),
                },
            }
        }

        /// Create a new FileOptions for a ghost directory at the provided path.
        ///
        /// Like ghost files, ghost directories are not included in the package payload,
        /// but their metadata is tracked by RPM.
        ///
        /// Use with [`PackageBuilder::with_ghost()`].
        ///
        /// Default permissions are 0o755.
        pub fn ghost_dir(dest: impl Into<String>) -> FileOptionsBuilder {
            FileOptionsBuilder {
                inner: FileOptions {
                    destination: dest.into(),
                    user: None,
                    group: None,
                    symlink: "".to_string(),
                    mode: FileMode::dir(0o755),
                    flag: FileFlags::GHOST,
                    use_default_permissions: true,
                    caps: None,
                    verify_flags: FileVerifyFlags::ALL_FLAGS,
                },
            }
        }
    }

    #[derive(Debug)]
    pub struct FileOptionsBuilder {
        inner: FileOptions,
    }

    impl FileOptionsBuilder {
        /// Indicates that the file should be owned by the specified username.
        ///
        /// Specifying a non-root user here will direct RPM to create the user via sysusers.d at
        /// installation time.
        ///
        /// See: `%attr` from specfile syntax
        pub fn user(mut self, user: impl Into<String>) -> Self {
            self.inner.user = Some(user.into());
            self
        }

        /// Indicates that the file should be part of the specified group.
        ///
        /// Specifying a non-root group here will direct RPM to create the group via sysusers.d at
        /// installation time.
        ///
        /// See: `%attr` from specfile syntax
        pub fn group(mut self, group: impl Into<String>) -> Self {
            self.inner.group = Some(group.into());
            self
        }

        /// Indicates that a file is a symlink pointing to the location provided
        pub fn symlink(mut self, symlink: impl Into<String>) -> Self {
            self.inner.symlink = symlink.into();
            self
        }

        /// Set the FileMode - type of file (or directory, or symlink) and permissions.
        ///
        /// Note: prefer using [`permissions()`](Self::permissions) instead, which sets only the
        /// permission bits without requiring the file type prefix. This method requires the caller
        /// to include the file type in the mode value (e.g. `0o100755` for a regular file with
        /// `rwxr-xr-x` permissions).
        ///
        /// See: `%attr` from specfile syntax
        pub fn mode(mut self, mode: impl Into<FileMode>) -> Self {
            self.inner.mode = mode.into();
            self.inner.use_default_permissions = false;
            self
        }

        /// Set the permission bits for the file without changing the file type.
        ///
        /// This is the preferred way to set permissions. Unlike [`mode()`](Self::mode), you only
        /// need to provide the permission bits (e.g. `0o755`) without the file type prefix.
        ///
        /// Values greater than `0o7777` will be masked to fit.
        ///
        /// See: `%attr` from specfile syntax
        pub fn permissions(mut self, permissions: u16) -> Self {
            self.inner.mode.set_permissions(permissions);
            self.inner.use_default_permissions = false;
            self
        }

        /// Indicates that a file should have the provided POSIX file capabilities.
        ///
        /// See: `%caps` from specfile syntax
        pub fn caps(mut self, caps: impl Into<String>) -> Result<Self, errors::Error> {
            // verify capabilities
            self.inner.caps = match FileCaps::from_str(&caps.into()) {
                Ok(caps) => Some(caps),
                Err(e) => {
                    return Err(errors::Error::InvalidCapabilities {
                        caps: e.to_string(),
                    });
                }
            };
            Ok(self)
        }

        /// Direct which aspects of the file you would like RPM to verify.
        ///
        /// By default, every aspect of the file will be checked.
        ///
        /// See: `%verify` from specfile syntax
        pub fn verify(mut self, flags: FileVerifyFlags) -> Self {
            self.inner.verify_flags = flags;
            self
        }

        /// Indicates that a file is documentation.
        ///
        /// See: `%doc` from specfile syntax
        pub fn doc(mut self) -> Self {
            self.inner.flag.insert(FileFlags::DOC);
            self
        }

        /// Mark this file as a configuration file. When a package is updated, files marked as
        /// configuration files will be checked for modifications compared to their default state,
        /// and if any are present then the old configuration file will be saved with a `.rpmsave`
        /// extension.
        ///
        /// User intervention may be required to reconcile the changes between the new and old configs.
        ///
        /// Can be combined with [`noreplace()`](Self::noreplace) or [`missingok()`](Self::missingok).
        ///
        /// See: `%config` from specfile syntax
        pub fn config(mut self) -> Self {
            self.inner.flag.insert(FileFlags::CONFIG);
            self
        }

        /// Indicates that a configuration file should not be replaced if it has been modified.
        /// When a package is updated, the new configuration file will be installed with a `.rpmnew`
        /// extension instead.
        ///
        /// User intervention may be required to reconcile the changes between the new and old configs.
        ///
        /// Only meaningful in combination with [`config()`](Self::config).
        ///
        /// See: `%config(noreplace)` from specfile syntax
        pub fn noreplace(mut self) -> Self {
            self.inner.flag.insert(FileFlags::NOREPLACE);
            self
        }

        /// Indicates that the absence of this file is not an error. During verification (`rpm -V`),
        /// a missing file marked with `missingok` will not be reported as a failure. During package
        /// removal, the file will be silently skipped if it does not exist.
        ///
        /// This is an independent attribute — it can be set on any file, not just config files.
        /// However, it is commonly combined with [`config()`](Self::config).
        ///
        /// See: `%missingok` or `%config(missingok)` from specfile syntax
        pub fn missingok(mut self) -> Self {
            self.inner.flag.insert(FileFlags::MISSINGOK);
            self
        }

        /// Indicates that a file ought not to actually be included in the package, but that it should
        /// still be considered owned by a package (e.g. a log file). Its attributes are still tracked.
        ///
        /// Note: prefer using [`FileOptions::ghost()`] / [`PackageBuilder::with_ghost()`] instead of
        /// setting this flag manually, as those constructors handle the content source correctly.
        ///
        /// See: `%ghost` from specfile syntax
        pub fn ghost(mut self) -> Self {
            self.inner.flag.insert(FileFlags::GHOST);
            self
        }

        /// Mark this file as a software license. License files are always included — they are
        /// never filtered out during installation.
        ///
        /// See: `%license` from specfile syntax
        pub fn license(mut self) -> Self {
            self.inner.flag.insert(FileFlags::LICENSE);
            self
        }

        /// Mark this file as a build artifact.
        ///
        /// See: `%artifact` from specfile syntax
        pub fn artifact(mut self) -> Self {
            self.inner.flag.insert(FileFlags::ARTIFACT);
            self
        }

        /// Deprecated: use [`doc()`](Self::doc) instead. Marks a file as a README.
        ///
        /// See: `%readme` from specfile syntax
        #[deprecated(since = "0.20.0", note = "use doc() instead")]
        pub fn readme(mut self) -> Self {
            self.inner.flag.insert(FileFlags::README);
            self
        }
    }

    impl From<FileOptionsBuilder> for FileOptions {
        fn from(builder: FileOptionsBuilder) -> Self {
            builder.inner
        }
    }
}

#[cfg(feature = "payload")]
pub use build_types::*;

/// Description of a dependency as present in a RPM header record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub flags: DependencyFlags,
    pub version: String,
}

impl Dependency {
    /// Create a dependency on any version of some package or file (or string in general).
    pub fn any(dep_name: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::ANY, "".to_string())
    }

    /// Create a dependency on an exact version of some package.
    pub fn eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::EQUAL, version.into())
    }

    /// Create a dependency on a version of some package less than the provided one.
    pub fn less(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::LESS, version.into())
    }

    /// Create a dependency on a version of some package less than or equal to the provided one.
    pub fn less_eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::LESS | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Create a dependency on a version of some package greater than the provided one.
    pub fn greater(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::GREATER, version.into())
    }

    /// Create a dependency on a version of some package greater than or equal to the provided one.
    pub fn greater_eq(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::GREATER | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Create a dependency on an rpm feature, required to install this package
    pub fn rpmlib(dep_name: impl Into<String>, version: impl Into<String>) -> Self {
        // The reason why it counterintuitively uses <= is so that the range is closed, as >=
        // would be making promise that it will work forever. It should be read as "this package
        // won't work on versions less than $version"
        Self::new(
            format!("rpmlib({})", dep_name.into()),
            DependencyFlags::RPMLIB | DependencyFlags::LESS | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Add a config dependency
    pub fn config(dep_name: &str, version: impl Into<String>) -> Self {
        Self::new(
            format!("config({})", dep_name),
            DependencyFlags::CONFIG | DependencyFlags::EQUAL,
            version.into(),
        )
    }

    /// Create a new user dependency
    ///
    /// If such a dependency is required, versions of RPM 4.19 and newer will automatically create
    /// the required users and groups using systemd sys.users.d.
    pub fn user(username: &str) -> Self {
        Self::new(
            format!("user({})", username),
            DependencyFlags::SCRIPT_PRE | DependencyFlags::SCRIPT_POSTUN,
            "".to_owned(),
        )
    }

    /// Create a new group dependency
    ///
    /// If such a dependency is required, versions of RPM 4.19 and newer will automatically create
    /// the required users and groups using systemd sys.users.d.
    pub fn group(groupname: &str) -> Self {
        Self::new(
            format!("group({})", groupname),
            DependencyFlags::SCRIPT_PRE | DependencyFlags::SCRIPT_POSTUN,
            "".to_owned(),
        )
    }

    // @todo: Is it ever the case that version matters here? it's at least not the common case

    /// Create a dependency on a package or file required for a pre-install script.
    pub fn script_pre(dep_name: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::SCRIPT_PRE, "".to_string())
    }

    /// Create a dependency on a package or file required for a post-install script.
    pub fn script_post(dep_name: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::SCRIPT_POST,
            "".to_string(),
        )
    }

    /// Create a dependency on a package or file required for a pre-un-install script.
    pub fn script_preun(dep_name: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::SCRIPT_PREUN,
            "".to_string(),
        )
    }

    /// Create a dependency on a package or file required for a post-un-install script.
    pub fn script_postun(dep_name: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::SCRIPT_POSTUN,
            "".to_string(),
        )
    }

    /// Create an interpreter dependency (e.g. `/bin/sh`).
    ///
    /// This corresponds to a bare `Requires(interp)` without a phase-specific
    /// flag. RPM generates these for explicit `-p` interpreter declarations
    /// in spec files (e.g. `%post -p /bin/sh`).
    pub fn interp(dep_name: impl Into<String>) -> Self {
        Self::new(dep_name.into(), DependencyFlags::INTERP, "".to_string())
    }

    /// Create a dependency on a package or file required for a verify script.
    pub fn script_verify(dep_name: impl Into<String>) -> Self {
        Self::new(
            dep_name.into(),
            DependencyFlags::SCRIPT_VERIFY,
            "".to_string(),
        )
    }

    fn new(dep_name: String, flags: DependencyFlags, version: String) -> Self {
        Dependency {
            name: dep_name,
            flags,
            version,
        }
    }
}

impl std::fmt::Display for Dependency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cmp = self.flags.comparator_str();
        if cmp.is_empty() || self.version.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{} {} {}", self.name, cmp, self.version)
        }
    }
}

/// Type-alias for a tuple containing index tags for a scriptlet type,
pub(crate) type ScriptletIndexTags = (IndexTag, IndexTag, IndexTag);

/// Type-alias for the set of index tags used by a trigger family
/// (scripts, progs, flags, names, versions, condition-flags, index).
pub(crate) type TriggerIndexTags = (
    IndexTag, // scripts
    IndexTag, // script progs
    IndexTag, // script flags (optional)
    IndexTag, // condition names
    IndexTag, // condition versions
    IndexTag, // condition flags
    IndexTag, // condition-to-script index
);

/// A single trigger entry parsed from an RPM header.
///
/// Each trigger has a script body, interpreter, and one or more conditions
/// (target packages or paths) that activate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trigger {
    /// The script to execute when the trigger fires
    pub script: String,
    /// The interpreter for the script (e.g. `["/bin/sh"]`)
    pub program: Vec<String>,
    /// The conditions that activate this trigger
    pub conditions: Vec<TriggerCondition>,
}

/// A single condition within a trigger entry.
///
/// For package triggers, `name` is the target package name (e.g. `"bash"`).
/// For file triggers, `name` is the monitored path (e.g. `"/usr/lib"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TriggerCondition {
    /// Target package name or file path
    pub name: String,
    /// Dependency flags encoding the trigger type and version comparison
    pub flags: DependencyFlags,
    /// Version constraint (empty string if unconstrained)
    pub version: String,
}

/// Description of a scriptlet as present in a RPM header record
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scriptlet {
    /// Content of the scriptlet
    pub script: String,
    /// Optional scriptlet flags
    pub flags: Option<ScriptletFlags>,
    /// Optional scriptlet interpreter/arguments
    pub program: Option<Vec<String>>,
}

impl Scriptlet {
    /// Returns a new scriplet
    #[inline]
    pub fn new(script: impl Into<String>) -> Scriptlet {
        Scriptlet {
            script: script.into(),
            flags: None,
            program: None,
        }
    }

    /// Sets the scriptlet flags
    ///
    /// **Note** These flags can be used to configure macro expansions etc.
    #[inline]
    pub fn flags(mut self, flags: ScriptletFlags) -> Self {
        self.flags = Some(flags);
        self
    }

    /// Sets the scriptlet interpreter/arguments
    #[inline]
    pub fn prog(mut self, mut prog: Vec<impl Into<String>>) -> Self {
        self.program = Some(prog.drain(..).map(|p| p.into()).collect_vec());
        self
    }

    /// Consumes the receiver and applies all index entries for the scriptlet based on builder state
    #[cfg(feature = "payload")]
    pub(crate) fn apply(self, records: &mut Vec<IndexEntry<IndexTag>>, tags: ScriptletIndexTags) {
        let (script_tag, flags_tag, prog_tag) = tags;

        records.push(IndexEntry::new(
            script_tag,
            IndexData::StringTag(self.script),
        ));

        if let Some(flags) = self.flags {
            records.push(IndexEntry::new(
                flags_tag,
                IndexData::Int32(vec![flags.bits()]),
            ));
        }

        if let Some(prog) = self.program {
            // RPM writes single-value prog tags as String for backward compatibility, and
            // StringArray only when there are multiple interpreter arguments.
            let data = if prog.len() == 1 {
                IndexData::StringTag(prog.into_iter().next().unwrap())
            } else {
                IndexData::StringArray(prog)
            };
            records.push(IndexEntry::new(prog_tag, data));
        }
    }
}

impl<T> From<T> for Scriptlet
where
    T: Into<String>,
{
    fn from(value: T) -> Self {
        Scriptlet::new(value)
    }
}

mod test {
    #[test]
    fn test_file_mode() -> Result<(), Box<dyn std::error::Error>> {
        use super::*;

        // test constructor functions
        let test_table = vec![(0, 0), (0o7777, 0o7777), (0o17777, 0o7777)];
        for (permissions, expected) in test_table {
            let result = FileMode::dir(permissions);
            assert_eq!(expected, result.permissions());
            let result = FileMode::regular(permissions);
            assert_eq!(expected, result.permissions());
            let result = FileMode::symbolic_link(permissions);
            assert_eq!(expected, result.permissions());
        }

        // test set_permissions
        let mut mode = FileMode::regular(0o644);
        assert_eq!(mode.permissions(), 0o644);
        assert_eq!(mode.file_type(), FileType::Regular);

        mode.set_permissions(0o755);
        assert_eq!(mode.permissions(), 0o755);
        assert_eq!(mode.file_type(), FileType::Regular);

        // set_permissions on a directory preserves the directory type
        let mut dir_mode = FileMode::dir(0o755);
        dir_mode.set_permissions(0o700);
        assert_eq!(dir_mode.permissions(), 0o700);
        assert_eq!(dir_mode.file_type(), FileType::Dir);

        // set_permissions masks values > 0o7777
        let mut mode2 = FileMode::regular(0o644);
        mode2.set_permissions(0o17777);
        assert_eq!(mode2.permissions(), 0o7777);
        assert_eq!(mode2.file_type(), FileType::Regular);

        // test TryFrom<i32>
        let try_from_table: Vec<(i32, Result<FileMode, &str>)> = vec![
            (0o10_0664, Ok(FileMode::regular(0o664))),
            (0o04_0665, Ok(FileMode::dir(0o665))),
            // test sticky bit
            (0o10_1664, Ok(FileMode::regular(0o1664))),
            (0o12_0664, Ok(FileMode::symbolic_link(0o0664))),
            (0o12_1664, Ok(FileMode::symbolic_link(0o1664))),
            // unknown file type maps to Other
            (0o664, Ok(FileMode(0o664))),
            // out of 16bit bounds is an error
            (0o27_1664, Err("provided integer is out of 16bit bounds")),
        ];
        for (raw_mode, expected) in try_from_table {
            let result = FileMode::try_from(raw_mode);
            match (&expected, &result) {
                (Ok(expected), Ok(actual)) => assert_eq!(expected, actual),
                (Err(expected_reason), Err(errors::Error::InvalidFileMode { reason, .. })) => {
                    assert_eq!(expected_reason, reason);
                }
                _ => panic!(
                    "mismatched result for {:#o}: expected {:?}, got {:?}",
                    raw_mode, expected, result
                ),
            }
        }

        // test From<u16> and file_type()
        let from_table: Vec<(i32, FileMode, FileType)> = vec![
            (0o10_0755, FileMode::regular(0o0755), FileType::Regular),
            (0o10_1755, FileMode::regular(0o1755), FileType::Regular),
            (0o04_0755, FileMode::dir(0o0755), FileType::Dir),
            (
                0o12_0755,
                FileMode::symbolic_link(0o0755),
                FileType::SymbolicLink,
            ),
            (
                0o12_1755,
                FileMode::symbolic_link(0o1755),
                FileType::SymbolicLink,
            ),
            // unknown file type via From<u16>
            (0o0755, FileMode(0o0755), FileType::Other),
        ];
        for (raw_mode, expected_mode, expected_type) in from_table {
            let mode = FileMode::from(raw_mode as u16);
            assert_eq!(expected_mode, mode);
            assert_eq!(raw_mode as u16, mode.raw_mode());
            assert_eq!(expected_type, mode.file_type());
        }
        Ok(())
    }

    #[cfg(feature = "payload")]
    #[test]
    fn test_verify_capabilities_valid() {
        let blank_file = crate::FileOptions::new("/usr/bin/awesome");
        blank_file.caps("cap_net_admin,cap_net_raw+p").unwrap();
    }

    #[cfg(feature = "payload")]
    #[test]
    fn test_verify_capabilities_invalid() -> Result<(), crate::errors::Error> {
        let blank_file = crate::FileOptions::new("/usr/bin/awesome");
        blank_file.caps("cap_net_an,cap_net_raw+p").unwrap_err();
        Ok(())
    }

    #[cfg(feature = "payload")]
    #[test]
    fn test_scriptlet_builder() {
        // Test full state
        let scriptlet = crate::Scriptlet::new(
            r#"
echo `hello world`
        "#
            .trim(),
        )
        .flags(crate::ScriptletFlags::EXPAND)
        .prog(vec!["/usr/bin/blah", "-c"]);

        let mut records = vec![];

        scriptlet.apply(&mut records, crate::PREIN_TAGS);

        assert!(records.len() == 3);
        assert_eq!(records[0].tag, crate::IndexTag::RPMTAG_PREIN as u32);
        assert_eq!(
            records[0].data,
            crate::IndexData::StringTag("echo `hello world`".to_string())
        );
        assert_eq!(records[1].tag, crate::IndexTag::RPMTAG_PREINFLAGS as u32);
        assert_eq!(records[1].data, crate::IndexData::Int32(vec![1]));
        assert_eq!(records[2].tag, crate::IndexTag::RPMTAG_PREINPROG as u32);
        assert_eq!(
            records[2].data,
            crate::IndexData::StringArray(vec!["/usr/bin/blah".to_string(), "-c".to_string()])
        );

        // Test partial state
        let scriptlet = crate::Scriptlet::new(
            r#"
        echo `hello world`
                "#
            .trim(),
        );

        let mut records = vec![];

        scriptlet.apply(&mut records, crate::POSTUN_TAGS);
        assert!(records.len() == 1);
        assert_eq!(records[0].tag, crate::IndexTag::RPMTAG_POSTUN as u32);
        assert_eq!(
            records[0].data,
            crate::IndexData::StringTag("echo `hello world`".to_string())
        );
    }
}
