//! A collection of types used in various header records.
use crate::{constants::*, errors, FileCaps, IndexData, IndexEntry, Timestamp};
use digest::Digest;
use itertools::Itertools;
use std::str::FromStr;

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

/// Describes a file present in the rpm file.
pub struct PackageFileEntry {
    pub size: u64,
    pub mode: FileMode,
    pub modified_at: Timestamp,
    pub sha_checksum: String,
    pub link: String,
    pub flags: FileFlags,
    pub user: String,
    pub group: String,
    pub base_name: String,
    pub dir: String,
    pub caps: Option<FileCaps>,
    pub verify_flags: FileVerifyFlags,
    pub(crate) content: Vec<u8>,
}

#[non_exhaustive]
#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum FileMode {
    // It does not really matter if we use u16 or i16 since all we care about
    // is the bit representation which is the same for both.
    Dir { permissions: u16 },
    Regular { permissions: u16 },
    SymbolicLink { permissions: u16 },
    // For "Invalid" we use a larger integer since it is possible to create an invalid
    // FileMode by providing an overflowing integer.
    Invalid { raw_mode: i32, reason: &'static str },
}

// there are more file types but in the context of RPM, only regular and directory and symbolic file should be relevant.
// See <https://man7.org/linux/man-pages/man7/inode.7.html> section "The file type and mode"
const FILE_TYPE_BIT_MASK: u16 = 0o170000; // bit representation = "1111000000000000"
const PERMISSIONS_BIT_MASK: u16 = 0o7777; // bit representation = "0000111111111111"
pub const REGULAR_FILE_TYPE: u16 = 0o100000; //  bit representation = "1000000000000000"
pub const DIR_FILE_TYPE: u16 = 0o040000; //      bit representation = "0100000000000000"
pub const SYMBOLIC_LINK_FILE_TYPE: u16 = 0o120000; // bit representation = "1010000000000000"

use bitflags::bitflags;

// typedef enum rpmFileTypes_e {
//     	=  1,	/*!< pipe/fifo */
//     CDEV	=  2,	/*!< character device */
//     XDIR	=  4,	/*!< directory */
//     BDEV	=  6,	/*!< block device */
//     REG		=  8,	/*!< regular file */
//     LINK	= 10,	/*!< hard link */
//     SOCK	= 12	/*!< socket */
// } rpmFileTypes;

bitflags! {
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    pub struct FileModeFlags: u16 {
        const PERMISSIONS_BIT_MASK =    0b0000111111111111; // 0o007777

        const SUID_BIT_MASK =           0b0000100000000000; // 0o007777
        const SGID_BIT_MASK =           0b0000010000000000; // 0o007777
        const STICKY_BIT_MASK =         0b0000001000000000; // 0o007777

        const USER_PERM_BIT_MASK =      0b0000000111000000; // 0o007777
        const GROUP_PERM_BIT_MASK =     0b0000000000111000; // 0o007777
        const OTHER_PERM_BIT_MASK =     0b0000000000000111;

// The set-user-ID bit (setuid bit).

//     On execution, set the process’s effective user ID to that of the file. For directories on a few systems, give files created in the directory the same owner as the directory, no matter who creates them, and set the set-user-ID bit of newly-created subdirectories.
// The set-group-ID bit (setgid bit).

//     On execution, set the process’s effective group ID to that of the file. For directories on most systems, give files created in the directory the same group as the directory, no matter what group the user who creates them is in, and set the set-group-ID bit of newly-created subdirectories.
// The restricted deletion flag or sticky bit.

//     Prevent unprivileged users from removing or renaming a file in a directory unless they own the file or the directory; this is commonly found on world-writable directories like /tmp. For regular files on some older systems, save the program’s text image on the swap device so it will load more quickly when run, so that the image is “sticky”.

        const FILE_TYPE_BIT_MASK =      0b1111000000000000; // 0o170000
        const REGULAR_FILE_TYPE =       0b1000000000000000; // 0o100000
        const DIR_FILE_TYPE =           0b0100000000000000; // 0o040000
        const SYMBOLIC_LINK_FILE_TYPE = 0b1010000000000000; // 0o120000
    }
}



impl From<u16> for FileMode {
    fn from(raw_mode: u16) -> Self {
        // example
        //  1111000000000000  (0o170000)  <- file type bit mask
        // &1000000111101101  (0o100755)  <- regular executable file
        // -----------------------------
        //  1000000000000000  (0o100000)  <- type for regular files
        //
        // we effectively extract the file type bits with an AND operation.
        // Here are two links for a quick refresh:
        // <https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Bitwise_AND>
        // <https://en.wikipedia.org/wiki/Bitwise_operation#AND>
        let file_type = raw_mode & FILE_TYPE_BIT_MASK;
        let permissions = raw_mode & PERMISSIONS_BIT_MASK;
        match file_type {
            DIR_FILE_TYPE => FileMode::Dir { permissions },
            REGULAR_FILE_TYPE => FileMode::Regular { permissions },
            SYMBOLIC_LINK_FILE_TYPE => FileMode::SymbolicLink { permissions },
            _ => FileMode::Invalid {
                raw_mode: raw_mode as i32,
                reason: "unknown file type",
            },
        }
    }
}

impl From<i32> for FileMode {
    fn from(raw_mode: i32) -> Self {
        // since we ultimately only deal with 16bit integers
        // we need to check if a safe conversion to 16bit is doable.
        if raw_mode > u16::MAX.into() || raw_mode < i16::MIN.into() {
            FileMode::Invalid {
                raw_mode,
                reason: "provided integer is out of 16bit bounds",
            }
        } else {
            FileMode::from(raw_mode as u16)
        }
    }
}

impl FileMode {
    /// Create a new Regular instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn regular(permissions: u16) -> Self {
        FileMode::Regular {
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Create a new Dir instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn dir(permissions: u16) -> Self {
        FileMode::Dir {
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Create a new Symbolic link instance. `permissions` can be between 0 and 0o7777. Values greater will be set to 0o7777.
    pub fn symbolic_link(permissions: u16) -> Self {
        FileMode::SymbolicLink {
            permissions: permissions & PERMISSIONS_BIT_MASK,
        }
    }

    /// Usually this should be done with TryFrom, but since we already have a `From` implementation,
    /// we run into this issue: <https://github.com/rust-lang/rust/issues/50133>
    pub fn try_from_raw(raw: i32) -> Result<Self, errors::Error> {
        let mode: FileMode = raw.into();
        mode.to_result()
    }

    /// Turns this FileMode into a result. If the mode is Invalid, it will be converted into
    /// Error::InvalidFileMode. Otherwise it is Ok(self).
    pub fn to_result(self) -> Result<Self, errors::Error> {
        match self {
            Self::Invalid { raw_mode, reason } => {
                Err(errors::Error::InvalidFileMode { raw_mode, reason })
            }
            _ => Ok(self),
        }
    }

    /// Returns the complete file mode (type and permissions)
    pub fn raw_mode(&self) -> u16 {
        match self {
            Self::Dir { permissions }
            | Self::Regular { permissions }
            | Self::SymbolicLink { permissions } => *permissions | self.file_type(),
            Self::Invalid {
                raw_mode,
                reason: _,
            } => *raw_mode as u16,
        }
    }

    pub fn file_type(&self) -> u16 {
        match self {
            Self::Dir { permissions: _ } => DIR_FILE_TYPE,
            Self::Regular { permissions: _ } => REGULAR_FILE_TYPE,
            Self::SymbolicLink { permissions: _ } => SYMBOLIC_LINK_FILE_TYPE,
            Self::Invalid {
                raw_mode,
                reason: _,
            } => *raw_mode as u16 & FILE_TYPE_BIT_MASK,
        }
    }

    pub fn permissions(&self) -> u16 {
        match self {
            Self::Dir { permissions }
            | Self::Regular { permissions }
            | Self::SymbolicLink { permissions } => *permissions,
            Self::Invalid {
                raw_mode,
                reason: _,
            } => *raw_mode as u16 & PERMISSIONS_BIT_MASK,
        }
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

#[derive(Debug)]
pub struct FileOptions {
    pub(crate) destination: String,
    pub(crate) user: String,
    pub(crate) group: String,
    pub(crate) symlink: String,
    pub(crate) mode: FileMode,
    pub(crate) flag: FileFlags,
    pub(crate) inherit_permissions: bool,
    pub(crate) caps: Option<FileCaps>,
    pub(crate) verify_flags: FileVerifyFlags,
}

impl FileOptions {
    /// Create a new FileOptions for a file which will be placed at the provided path.
    ///
    /// By default, files will be owned by the "root" user and group, and inherit their permissions
    /// from the on-disk file.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(dest: impl Into<String>) -> FileOptionsBuilder {
        FileOptionsBuilder {
            inner: FileOptions {
                destination: dest.into(),
                user: "root".to_string(),
                group: "root".to_string(),
                symlink: "".to_string(),
                mode: FileMode::regular(0o664),
                flag: FileFlags::empty(),
                inherit_permissions: true,
                caps: None,
                verify_flags: FileVerifyFlags::all(),
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
        self.inner.user = user.into();
        self
    }

    /// Indicates that the file should be part of the specified group.
    ///
    /// Specifying a non-root group here will direct RPM to create the group via sysusers.d at
    /// installation time.
    ///
    /// See: `%attr` from specfile syntax
    pub fn group(mut self, group: impl Into<String>) -> Self {
        self.inner.group = group.into();
        self
    }

    /// Indicates that a file is a symlink pointing to the location provided
    pub fn symlink(mut self, symlink: impl Into<String>) -> Self {
        self.inner.symlink = symlink.into();
        self
    }

    /// Set the FileMode - type of file (or directory, or symlink) and permissions.
    ///
    /// See: `%attr` from specfile syntax
    pub fn mode(mut self, mode: impl Into<FileMode>) -> Self {
        self.inner.mode = mode.into();
        self.inner.inherit_permissions = false;
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
                })
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
    pub fn is_doc(mut self) -> Self {
        self.inner.flag.insert(FileFlags::DOC);
        self
    }

    /// Indicates that a file is a configuration file. When a package is updated, files marked as
    /// configuration files will be checked for modifications compared to their default state,
    /// and if any are present then the old configuration file will be saved with a `.rpmsave`
    /// extension.
    ///
    /// User intervention may be required to reconcile the changes between the new and old configs.
    ///
    /// See: `%config` from specfile syntax
    pub fn is_config(mut self) -> Self {
        self.inner.flag.insert(FileFlags::CONFIG);
        self
    }

    /// Indicates that a file is a configuration file and that it should not be replaced if it has been
    /// modified. When a package is updated, configuration files will be checked for modifications
    /// compared to their default state, and if any are present then the new configuration file will
    /// be installed with a `.rpmnew` extension.
    ///
    /// User intervention may be required to reconcile the changes between the new and old configs.
    ///
    /// See: `%config(noreplace)` from specfile syntax
    pub fn is_config_noreplace(mut self) -> Self {
        self.inner
            .flag
            .insert(FileFlags::CONFIG | FileFlags::NOREPLACE);
        self
    }

    /// Indicates that a file ought not to actually be included in the package, but that it should
    /// still be considered owned by a package (e.g. a log file).  Its attributes are still tracked.
    ///
    /// See: `%ghost` from specfile syntax
    pub fn is_ghost(mut self) -> Self {
        self.inner.flag.insert(FileFlags::GHOST);
        self
    }

    /// Indicates that a file is a software license. License files are always included - they are
    /// never filtered out during installation.
    ///
    /// See: `%license` from specfile syntax
    pub fn is_license(mut self) -> Self {
        self.inner.flag.insert(FileFlags::LICENSE);
        self
    }

    /// Deprecated (use `is_doc()` instead). Marks a file as a README.
    ///
    /// See: `%readme` from specfile syntax
    pub fn is_readme(mut self) -> Self {
        self.inner.flag.insert(FileFlags::README);
        self
    }
}

impl From<FileOptionsBuilder> for FileOptions {
    fn from(builder: FileOptionsBuilder) -> Self {
        builder.inner
    }
}

/// Description of a dependency as present in a RPM header record.
#[derive(Debug, PartialEq, Eq)]
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
        Self::new(
            format!("rpmlib({})", dep_name.into()),
            DependencyFlags::RPMLIB | DependencyFlags::EQUAL,
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

    fn new(dep_name: String, flags: DependencyFlags, version: String) -> Self {
        Dependency {
            name: dep_name,
            flags,
            version,
        }
    }
}

/// A wrapper for calculating the sha256 checksum of the contents written to it
pub struct Sha256Writer<W> {
    writer: W,
    hasher: sha2::Sha256,
}

impl<W> Sha256Writer<W> {
    pub fn new(writer: W) -> Self {
        Sha256Writer {
            writer,
            hasher: sha2::Sha256::new(),
        }
    }

    pub fn into_digest(self) -> impl AsRef<[u8]> {
        self.hasher.finalize()
    }
}

impl<W: std::io::Write> std::io::Write for Sha256Writer<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

/// Type-alias for a tuple containing index tags for a scriptlet type,
pub(crate) type ScriptletIndexTags = (IndexTag, IndexTag, IndexTag);

/// Description of a scriptlet as present in a RPM header record
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
    pub(crate) fn apply(
        self,
        records: &mut Vec<IndexEntry<IndexTag>>,
        offset: i32,
        tags: ScriptletIndexTags,
    ) {
        let (script_tag, flags_tag, prog_tag) = tags;

        records.push(IndexEntry::new(
            script_tag,
            offset,
            IndexData::StringTag(self.script),
        ));

        if let Some(flags) = self.flags {
            records.push(IndexEntry::new(
                flags_tag,
                offset,
                IndexData::Int32(vec![flags.bits()]),
            ));
        }

        if let Some(prog) = self.program {
            records.push(IndexEntry::new(
                prog_tag,
                offset,
                IndexData::StringArray(prog),
            ));
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

        let test_table = vec![
            (0o10_0664, Ok(FileMode::regular(0o664))),
            (0o04_0665, Ok(FileMode::dir(0o665))),
            // test sticky bit
            (0o10_1664, Ok(FileMode::regular(0o1664))),
            (0o12_0664, Ok(FileMode::symbolic_link(0o0664))),
            (0o12_1664, Ok(FileMode::symbolic_link(0o1664))),
            (
                0o664,
                Err(errors::Error::InvalidFileMode {
                    raw_mode: 0o664,
                    reason: "unknown file type",
                }),
            ),
            (
                0o27_1664,
                Err(errors::Error::InvalidFileMode {
                    raw_mode: 0o27_1664,
                    reason: "provided integer is out of 16bit bounds",
                }),
            ),
        ];

        // test try_from_raw
        for (testant, expected) in test_table {
            let result = FileMode::try_from_raw(testant);
            match (&expected, &result) {
                (Ok(expected), Ok(actual)) => {
                    assert_eq!(expected, actual);
                }
                (Err(expected), Err(actual)) => {
                    if let errors::Error::InvalidFileMode {
                        raw_mode: actual_raw_mode,
                        reason: actual_reason,
                    } = actual
                    {
                        if let errors::Error::InvalidFileMode {
                            raw_mode: expected_raw_mode,
                            reason: expected_reason,
                        } = expected
                        {
                            assert_eq!(expected_raw_mode, actual_raw_mode);
                            assert_eq!(expected_reason, actual_reason);
                        } else {
                            unreachable!();
                        }
                    } else {
                        panic!("invalid error type");
                    }
                }
                _ => panic!("a and b not equal,{:?} vs {:?}", expected, result),
            }
        }

        // test into methods
        let test_table = vec![
            (0o10_0755, FileMode::regular(0o0755), REGULAR_FILE_TYPE),
            (0o10_1755, FileMode::regular(0o1755), REGULAR_FILE_TYPE),
            (0o04_0755, FileMode::dir(0o0755), DIR_FILE_TYPE),
            (
                0o12_0755,
                FileMode::symbolic_link(0o0755),
                SYMBOLIC_LINK_FILE_TYPE,
            ),
            (
                0o12_1755,
                FileMode::symbolic_link(0o1755),
                SYMBOLIC_LINK_FILE_TYPE,
            ),
            (
                0o20_0755,
                FileMode::Invalid {
                    raw_mode: 0o20_0755,
                    reason: "provided integer is out of 16bit bounds",
                },
                0,
            ),
            (
                0o0755,
                FileMode::Invalid {
                    raw_mode: 0o0755,
                    reason: "unknown file type",
                },
                0,
            ),
        ];
        for (raw_mode, expected_mode, expected_type) in test_table {
            let mode = FileMode::from(raw_mode);
            assert_eq!(expected_mode, mode);
            assert_eq!(raw_mode as u16, mode.raw_mode());
            assert_eq!(expected_type, mode.file_type());
        }
        Ok(())
    }

    #[test]
    fn test_verify_capabilities_valid() {
        let blank_file = crate::FileOptions::new("/usr/bin/awesome");
        blank_file.caps("cap_net_admin,cap_net_raw+p").unwrap();
    }

    #[test]
    fn test_verify_capabilities_invalid() -> Result<(), crate::errors::Error> {
        let blank_file = crate::FileOptions::new("/usr/bin/awesome");
        blank_file.caps("cap_net_an,cap_net_raw+p").unwrap_err();
        Ok(())
    }

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
        let offset = 0i32;

        scriptlet.apply(&mut records, offset, crate::PREIN_TAGS);

        assert!(records.len() == 3);
        assert_eq!(records[0].tag, crate::IndexTag::RPMTAG_PREIN as u32);
        assert_eq!(records[0].data.as_str(), Some("echo `hello world`"));
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
        let offset = 0i32;

        scriptlet.apply(&mut records, offset, crate::POSTUN_TAGS);
        assert!(records.len() == 1);
        assert_eq!(records[0].tag, crate::IndexTag::RPMTAG_POSTUN as u32);
        assert_eq!(records[0].data.as_str(), Some("echo `hello world`"));
    }
}
