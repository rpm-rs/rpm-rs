use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::convert::TryInto;

use std::fs;
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use std::fmt::Debug;
use std::path::{Path, PathBuf};

use digest::Digest;

use super::compressor::Compressor;
use super::headers::*;
use super::Lead;
use crate::errors::*;
use crate::{constants::*, Timestamp};

#[cfg(feature = "signature-meta")]
use crate::signature;

use crate::Package;
use crate::PackageMetadata;

use crate::{CompressionType, CompressionWithLevel};

#[cfg(unix)]
fn file_mode(file: &fs::File) -> Result<u32, Error> {
    Ok(file.metadata()?.permissions().mode())
}

#[cfg(windows)]
fn file_mode(_file: &fs::File) -> Result<u32, Error> {
    Ok(0)
}

/// Create an RPM file by specifying metadata and files using the builder pattern.
#[derive(Default)]
pub struct PackageBuilder {
    name: String,
    epoch: u32,
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

    pre_inst_script: Option<Scriptlet>,
    post_inst_script: Option<Scriptlet>,
    pre_uninst_script: Option<Scriptlet>,
    post_uninst_script: Option<Scriptlet>,
    pre_trans_script: Option<Scriptlet>,
    post_trans_script: Option<Scriptlet>,
    pre_untrans_script: Option<Scriptlet>,
    post_untrans_script: Option<Scriptlet>,
    verify_script: Option<Scriptlet>,

    /// The author name with email followed by a dash with the version
    /// `Max Mustermann <max@example.com> - 0.1-1`
    changelog_names: Vec<String>,
    changelog_entries: Vec<String>,
    changelog_times: Vec<Timestamp>,
    compression: CompressionWithLevel,

    vendor: Option<String>,
    packager: Option<String>,
    group: Option<String>,
    url: Option<String>,
    vcs: Option<String>,
    cookie: Option<String>,

    source_date: Option<Timestamp>,
    build_host: Option<String>,
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
            epoch: 0,
            version: version.to_string(),
            license: license.to_string(),
            arch: arch.to_string(),
            summary: summary.to_string(),
            release: "1".to_string(),
            ..Default::default()
        }
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
    pub fn epoch(mut self, epoch: u32) -> Self {
        self.epoch = epoch;
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
    pub fn release(mut self, release: impl Into<String>) -> Self {
        self.release = release.into();
        self
    }

    /// Set the URL for the package. Most often this is the website of the upstream project being
    /// packaged
    pub fn url(mut self, content: impl Into<String>) -> Self {
        self.url = Some(content.into());
        self
    }

    /// Set the version control URL of the upstream project
    pub fn vcs(mut self, content: impl Into<String>) -> Self {
        self.vcs = Some(content.into());
        self
    }

    /// Define a detailed, multiline, description of what the packaged software does
    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.desc = Some(desc.into());
        self
    }

    /// Set the package vendor - the name of the organization that is producing the package.
    pub fn vendor(mut self, content: impl Into<String>) -> Self {
        self.vendor = Some(content.into());
        self
    }

    /// Set the packager, the name of the person producing the package. This is often not present,
    /// or set to the same value as the vendor
    pub fn packager(mut self, content: impl Into<String>) -> Self {
        self.packager = Some(content.into());
        self
    }

    /// Set the package group (this is deprecated in most packaging guidelines)
    pub fn group(mut self, content: impl Into<String>) -> Self {
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
    pub fn build_host(mut self, build_host: impl AsRef<str>) -> Self {
        self.build_host = Some(build_host.as_ref().to_owned());
        self
    }

    /// Set source date (usually the date of the latest commit in VCS) used
    /// to clamp modification time of included files and build time of the package.
    ///
    /// `dt` is number of seconds since the UNIX Epoch.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    /// // It's recommended to use timestamp of last commit in your VCS
    /// let source_date = 1_600_000_000;
    /// // Do not forget
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MPL-2.0", "x86_64", "some bar package")
    ///     .source_date(source_date)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn source_date(mut self, t: impl TryInto<Timestamp, Error = impl Debug>) -> Self {
        self.source_date = Some(t.try_into().unwrap());
        self
    }

    /// Define a value that can be used for associating several package builds as being part of
    /// one operation
    ///
    /// You can use any value, but the standard format is "${build_host} ${build_time}"
    pub fn cookie(mut self, cookie: impl AsRef<str>) -> Self {
        self.cookie = Some(cookie.as_ref().to_owned());
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
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "some baz package")
    ///     .compression(rpm::CompressionType::Gzip)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    /// If you would like to specify a custom compression level (for faster package builds, at the
    /// expense of package size), pass a `CompressionWithLevel` value instead.
    ///
    /// ```
    /// # fn foo() -> Result<(), Box<dyn std::error::Error>> {
    ///
    /// let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "some baz package")
    ///     .compression(rpm::CompressionWithLevel::Zstd(3))
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
    pub fn compression(mut self, comp: impl Into<CompressionWithLevel>) -> Self {
        self.compression = comp.into();
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
        mut self,
        name: impl AsRef<str>,
        entry: impl AsRef<str>,
        timestamp: impl TryInto<Timestamp, Error = impl Debug>,
    ) -> Self {
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
    ///         rpm::FileOptions::new("/etc/awesome/config.toml").is_config(),
    ///     )?
    ///     // file mode is inherited from source file
    ///     .with_file(
    ///         "./awesome-bin",
    ///         rpm::FileOptions::new("/usr/bin/awesome"),
    ///     )?
    ///      .with_file(
    ///         "./awesome-config.toml",
    ///         // you can set a custom mode, capabilities and custom user too
    ///         rpm::FileOptions::new("/etc/awesome/second.toml").mode(0o100744).caps("cap_sys_admin=pe")?.user("hugo"),
    ///     )?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_file(
        mut self,
        source: impl AsRef<Path>,
        options: impl Into<FileOptions>,
    ) -> Result<Self, Error> {
        let mut input = fs::File::open(source)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        let mut options = options.into();
        if options.inherit_permissions {
            options.mode = (file_mode(&input)? as i32).into();
        }

        let modified_at = input.metadata()?.modified()?.try_into()?;

        self.add_data(content, modified_at, options)?;
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
    ///         rpm::FileOptions::new("/etc/awesome/config.toml").is_config(),
    ///     )?
    ///      .with_file_contents(
    ///         "./awesome-config.toml",
    ///         // you can set a custom mode, capabilities and custom user too
    ///         rpm::FileOptions::new("/etc/awesome/second.toml").mode(0o100744).caps("cap_sys_admin=pe")?.user("hugo"),
    ///     )?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_file_contents(
        mut self,
        content: impl Into<Vec<u8>>,
        options: impl Into<FileOptions>,
    ) -> Result<Self, Error> {
        self.add_data(content.into(), Timestamp::now(), options.into())?;
        Ok(self)
    }

    fn add_data(
        &mut self,
        content: Vec<u8>,
        modified_at: Timestamp,
        options: FileOptions,
    ) -> Result<(), Error> {
        let dest = options.destination;
        if !dest.starts_with("./") && !dest.starts_with('/') {
            return Err(Error::InvalidDestinationPath {
                path: dest,
                desc: "invalid start, expected / or ./",
            });
        }

        let pb = PathBuf::from(dest.clone());

        let parent = pb.parent().ok_or_else(|| Error::InvalidDestinationPath {
            path: dest.clone(),
            desc: "no parent directory found",
        })?;

        let (cpio_path, dir) = if dest.starts_with('.') {
            (
                dest.to_string(),
                // strip_prefix() should never fail because we've checked the special cases already
                format!("/{}/", parent.strip_prefix(".").unwrap().to_string_lossy()),
            )
        } else {
            (
                format!(".{}", dest),
                format!("{}/", parent.to_string_lossy()),
            )
        };

        let mut hasher = sha2::Sha256::default();
        hasher.update(&content);
        let hash_result = hasher.finalize();
        let sha_checksum = hex::encode(hash_result); // encode as string
        let entry = PackageFileEntry {
            // file_name() should never fail because we've checked the special cases already
            base_name: pb.file_name().unwrap().to_string_lossy().to_string(),
            size: content.len() as u64,
            content,
            flags: options.flag,
            user: options.user,
            group: options.group,
            mode: options.mode,
            link: options.symlink,
            modified_at,
            dir: dir.clone(),
            // Convert the caps to a string, so that we can store it in the header.
            // We do this so that it's possible to verify that caps are correct when provided
            // and then later check if any were set
            caps: options.caps,
            sha_checksum,
            verify_flags: options.verify_flags,
        };

        self.directories.insert(dir);
        self.files.entry(cpio_path).or_insert(entry);
        Ok(())
    }

    /// Set a script to be executed just before the package is installed or upgraded.
    ///
    /// See: %pre from specfile syntax
    #[inline]
    pub fn pre_install_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.pre_inst_script = Some(content.into());
        self
    }

    /// Set a script to be executed just after the package is installed or upgraded.
    ///
    /// See: %post from specfile syntax
    #[inline]
    pub fn post_install_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.post_inst_script = Some(content.into());
        self
    }

    /// Set a script to be executed just before package removal during uninstallation or upgrade.
    ///
    /// See: %preun from specfile syntax
    #[inline]
    pub fn pre_uninstall_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.pre_uninst_script = Some(content.into());
        self
    }

    /// Set a script to be executed just after package removal during uninstallation or upgrade.
    ///
    /// See: %postun from specfile syntax
    #[inline]
    pub fn post_uninstall_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.post_uninst_script = Some(content.into());
        self
    }

    /// Set a script to be executed before a transaction in which the package is installed or
    /// upgraded. This happens before any packages have been installed / upgraded / removed.
    ///
    /// See: %pretrans from specfile syntax
    #[inline]
    pub fn pre_trans_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.pre_trans_script = Some(content.into());
        self
    }

    /// Set a script to be executed after a transaction in which the package has been installed
    /// or upgraded. This happens after all packages in the transaction have been installed /
    /// upgraded / removed.
    ///
    /// See: %posttrans from specfile syntax
    #[inline]
    pub fn post_trans_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.post_trans_script = Some(content.into());
        self
    }

    /// Set a script to be executed before a transaction in which the package is being removed or
    /// upgraded. This happens before any packages have been installed / upgraded / removed.
    ///
    /// See: %preuntrans from specfile syntax
    #[inline]
    pub fn pre_untrans_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.pre_untrans_script = Some(content.into());
        self
    }

    /// Set a script to be executed after a transaction in which the package is being removed or
    /// upgraded. This happens after all packages in the transaction have been installed /
    /// upgraded / removed.
    ///
    /// See: %posttrans from specfile syntax
    #[inline]
    pub fn post_untrans_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.post_untrans_script = Some(content.into());
        self
    }

    /// Set a script to be executed during package verification, post-installation or using
    /// `rpm --verify`
    ///
    /// See: `%verifyscript` from specfile syntax
    #[inline]
    pub fn verify_script(mut self, content: impl Into<Scriptlet>) -> Self {
        self.verify_script = Some(content.into());
        self
    }

    /// Add a "provides" dependency
    ///
    /// These are aliases or capabilities provided by this package which other packages can reference.
    pub fn provides(mut self, dep: Dependency) -> Self {
        self.provides.push(dep);
        self
    }

    /// Add a "requires" dependency
    ///
    /// These are packages or capabilities which must be present in order for the package to be
    /// installed.
    pub fn requires(mut self, dep: Dependency) -> Self {
        self.requires.push(dep);
        self
    }

    /// Add a "conflicts" dependency
    ///
    /// These are packages which must not be present in order for the package to be installed.
    pub fn conflicts(mut self, dep: Dependency) -> Self {
        self.conflicts.push(dep);
        self
    }

    /// Add an "obsoletes" dependency
    ///
    /// These are packages this package supercedes - if this package is installed, packages
    /// listed as "obsoletes" will be be automatically removed (if they are present).
    pub fn obsoletes(mut self, dep: Dependency) -> Self {
        self.obsoletes.push(dep);
        self
    }

    /// Get a list of dependencies which this package "recommends"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat them
    /// as though they were "requires".  Unlike "requires" however, if installing a package listed
    /// as a "recommends" would cause errors, it may be ignored without error.
    pub fn recommends(mut self, dep: Dependency) -> Self {
        self.recommends.push(dep);
        self
    }

    /// Get a list of dependencies which this package "suggests"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// them to the user to be optionally installed.
    pub fn suggests(mut self, dep: Dependency) -> Self {
        self.suggests.push(dep);
        self
    }

    /// Get a list of reverse-dependencies which this package "enhances"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// this package to the user to be optionally installed when a package matching the "enhances"
    /// dependency is installed.
    pub fn enhances(mut self, dep: Dependency) -> Self {
        self.enhances.push(dep);
        self
    }

    /// Get a list of reverse-dependencies which this package "supplements"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat this
    /// package as if it were a "requires" when the matching package is installed. Unlike a
    /// "requires" however, if installing it would cause errors, it can be ignored ignored
    /// without error.
    pub fn supplements(mut self, dep: Dependency) -> Self {
        self.supplements.push(dep);
        self
    }

    /// Build the package
    pub fn build(self) -> Result<Package, Error> {
        let (lead, header_idx_tag, content) = self.prepare_data()?;

        let mut header = Vec::with_capacity(128);
        header_idx_tag.write(&mut header)?;

        let digest_header = {
            let header_digest_sha256 = hex::encode(sha2::Sha256::digest(&header));

            Header::<IndexSignatureTag>::builder()
                .add_digest(header_digest_sha256.as_str())
                .build()
        };

        let metadata = PackageMetadata {
            lead,
            signature: digest_header,
            header: header_idx_tag,
        };
        let pkg = Package { metadata, content };
        Ok(pkg)
    }

    /// Build the package and sign it with the provided signer
    ///
    /// If `source_date` was configured, that timestamp will be used during generation of the signature
    /// rather than the current one - which makes "reproducible builds" easier.
    ///
    /// See `signature::Signing` for more details.
    #[cfg(feature = "signature-meta")]
    pub fn build_and_sign<S>(self, signer: S) -> Result<Package, Error>
    where
        S: signature::Signing<Signature = Vec<u8>>,
    {
        let source_date = self.source_date;
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
    /// @todo split this into multiple `fn`s, one per `IndexTag`-group.
    fn prepare_data(mut self) -> Result<(Lead, Header<IndexTag>, Vec<u8>), Error> {
        // signature depends on header and payload. So we build these two first.
        // then the signature. Then we stitch all together.
        // Lead is not important. just build it here

        let lead = Lead::new(&self.name);

        // Calculate the sha256 of the archive as we write it into the compressor, so that we don't
        // need to keep two copies in memory simultaneously.
        let mut compressor: Compressor = self.compression.try_into()?;
        let mut archive = Sha256Writer::new(&mut compressor);

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

        // @todo: sort entries by path?
        // @todo: normalize path?
        // @todo: remove duplicates?
        // if we remove duplicates, remember anything already pre-computed
        for (cpio_path, entry) in self.files.iter() {
            combined_file_sizes += entry.size;
            if entry.caps.is_some() {
                uses_file_capabilities = true;
            }
            if &entry.user != "root" {
                users_to_create.insert(entry.user.clone());
            }
            if &entry.group != "root" {
                groups_to_create.insert(entry.group.clone());
            }
            file_sizes.push(entry.size);
            file_modes.push(entry.mode.into());
            file_caps.push(entry.caps.to_owned());
            // I really do not know the difference. It seems like file_rdevice is always 0 and file_device number always 1.
            // Who knows, who cares.
            file_rdevs.push(0);
            file_devices.push(1);
            let mtime = match self.source_date {
                Some(d) if d < entry.modified_at => d,
                _ => entry.modified_at,
            };
            file_mtimes.push(mtime.into());
            file_hashes.push(entry.sha_checksum.to_owned());
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
            // @todo: is there a use case for not performing all verifications? and are we performing those verifications currently anyway?
            file_verify_flags.push(entry.verify_flags.bits());
            let content = entry.content.to_owned();
            let mut writer = cpio::newc::Builder::new(cpio_path)
                .mode(entry.mode.into())
                .ino(ino_index)
                .uid(self.uid.unwrap_or(0))
                .gid(self.gid.unwrap_or(0))
                .write(&mut archive, content.len() as u32);

            writer.write_all(&content)?;
            writer.finish()?;

            ino_index += 1;
        }
        cpio::newc::trailer(&mut archive)?;

        self.provides
            .push(Dependency::eq(self.name.clone(), self.version.clone()));
        self.provides.push(Dependency::eq(
            format!("{}({})", self.name.clone(), self.arch.clone()),
            self.version.clone(),
        ));

        self.requires
            .push(Dependency::rpmlib("CompressedFileNames", "3.0.4-1"));

        self.requires
            .push(Dependency::rpmlib("FileDigests", "4.6.0-1"));

        self.requires
            .push(Dependency::rpmlib("PayloadFilesHavePrefix", "4.0-1"));

        if self.compression.compression_type() == CompressionType::Zstd {
            self.requires
                .push(Dependency::rpmlib("PayloadIsZstd", "5.4.18-1"));
        }

        if uses_file_capabilities {
            self.requires
                .push(Dependency::rpmlib("FileCaps", "4.6.1-1".to_owned()));
        }
        // TODO: as per https://rpm-software-management.github.io/rpm/manual/users_and_groups.html,
        // at some point in the future this might make sense as hard requirements, but since it's a new feature,
        // they have to be weak requirements to avoid breaking things.
        for user in &users_to_create {
            self.recommends.push(Dependency::user(user));
        }

        for group in &groups_to_create {
            self.recommends.push(Dependency::group(group));
        }

        let mut provide_names = Vec::new();
        let mut provide_flags = Vec::new();
        let mut provide_versions = Vec::new();

        for d in self.provides.into_iter() {
            provide_names.push(d.name);
            provide_flags.push(d.flags.bits());
            provide_versions.push(d.version);
        }

        let mut obsolete_names = Vec::new();
        let mut obsolete_flags = Vec::new();
        let mut obsolete_versions = Vec::new();

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

        for d in self.conflicts.into_iter() {
            conflicts_names.push(d.name);
            conflicts_flags.push(d.flags.bits());
            conflicts_versions.push(d.version);
        }

        let mut recommends_names = Vec::new();
        let mut recommends_flags = Vec::new();
        let mut recommends_versions = Vec::new();

        for d in self.recommends.into_iter() {
            recommends_names.push(d.name);
            recommends_flags.push(d.flags.bits());
            recommends_versions.push(d.version);
        }

        let mut suggests_names = Vec::new();
        let mut suggests_flags = Vec::new();
        let mut suggests_versions = Vec::new();

        for d in self.suggests.into_iter() {
            suggests_names.push(d.name);
            suggests_flags.push(d.flags.bits());
            suggests_versions.push(d.version);
        }

        let mut enhances_names = Vec::new();
        let mut enhances_flags = Vec::new();
        let mut enhances_versions = Vec::new();

        for d in self.enhances.into_iter() {
            enhances_names.push(d.name);
            enhances_flags.push(d.flags.bits());
            enhances_versions.push(d.version);
        }

        let mut supplements_names = Vec::new();
        let mut supplements_flags = Vec::new();
        let mut supplements_versions = Vec::new();

        for d in self.supplements.into_iter() {
            supplements_names.push(d.name);
            supplements_flags.push(d.flags.bits());
            supplements_versions.push(d.version);
        }

        let offset = 0;
        let small_package = combined_file_sizes <= u32::MAX.into();

        let mut actual_records = vec![
            // Existence of this tag is how rpm decides whether or not a package is a source rpm or binary rpm
            // If the SOURCERPM tag is set, then the package is seen as a binary rpm.
            IndexEntry::new(
                IndexTag::RPMTAG_SOURCERPM,
                offset,
                IndexData::StringTag("(none)".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_HEADERI18NTABLE,
                offset,
                IndexData::StringArray(vec!["C".to_string()]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_NAME,
                offset,
                IndexData::StringTag(self.name),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_EPOCH,
                offset,
                IndexData::Int32(vec![self.epoch]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_RPMVERSION,
                offset,
                IndexData::StringTag(format!("rpm-rs {}", env!("CARGO_PKG_VERSION"))),
            ),
            // @todo: write RPMTAG_PLATFORM?
            IndexEntry::new(
                IndexTag::RPMTAG_VERSION,
                offset,
                IndexData::StringTag(self.version),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_RELEASE,
                offset,
                IndexData::StringTag(self.release),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_DESCRIPTION,
                offset,
                IndexData::I18NString(vec![self.desc.unwrap_or_else(|| self.summary.clone())]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_SUMMARY,
                offset,
                IndexData::I18NString(vec![self.summary]),
            ),
            if small_package {
                let combined_file_sizes = combined_file_sizes
                    .try_into()
                    .expect("combined_file_sizes should be smaller than 4 GiB");
                IndexEntry::new(
                    IndexTag::RPMTAG_SIZE,
                    offset,
                    IndexData::Int32(vec![combined_file_sizes]),
                )
            } else {
                IndexEntry::new(
                    IndexTag::RPMTAG_LONGSIZE,
                    offset,
                    IndexData::Int64(vec![combined_file_sizes]),
                )
            },
            IndexEntry::new(
                IndexTag::RPMTAG_LICENSE,
                offset,
                IndexData::StringTag(self.license),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_OS,
                offset,
                IndexData::StringTag("linux".to_string()),
            ),
            // @todo: Fedora packaging guidelines recommend against using %group <https://fedoraproject.org/wiki/RPMGroups>
            // If it's legacy and safe to drop entirely let's do so. rpmbuild still writes it in the header though.
            IndexEntry::new(
                IndexTag::RPMTAG_GROUP,
                offset,
                IndexData::I18NString(vec!["Unspecified".to_string()]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_ARCH,
                offset,
                IndexData::StringTag(self.arch),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_ENCODING,
                offset,
                IndexData::StringTag("utf-8".to_string()),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFORMAT,
                offset,
                IndexData::StringTag("cpio".to_string()),
            ),
        ];

        let now = Timestamp::now();
        let build_time = match self.source_date {
            Some(t) if t < now => t,
            _ => now,
        };
        actual_records.push(IndexEntry::new(
            IndexTag::RPMTAG_BUILDTIME,
            offset,
            IndexData::Int32(vec![build_time.into()]),
        ));

        if let Some(build_host) = self.build_host {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_BUILDHOST,
                offset,
                IndexData::StringTag(build_host),
            ));
        }

        // if we have an empty RPM, we have to leave out all file related index entries.
        if !self.files.is_empty() {
            let size_entry = if small_package {
                let file_sizes = file_sizes
                    .into_iter()
                    .map(u32::try_from)
                    .collect::<Result<_, _>>()
                    .expect(
                        "combined_file_sizes and thus all file sizes \
                         should be smaller than 4 GiB",
                    );
                IndexEntry::new(
                    IndexTag::RPMTAG_FILESIZES,
                    offset,
                    IndexData::Int32(file_sizes),
                )
            } else {
                IndexEntry::new(
                    IndexTag::RPMTAG_LONGFILESIZES,
                    offset,
                    IndexData::Int64(file_sizes),
                )
            };
            actual_records.extend([
                size_entry,
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEMODES,
                    offset,
                    IndexData::Int16(file_modes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILERDEVS,
                    offset,
                    IndexData::Int16(file_rdevs),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEMTIMES,
                    offset,
                    IndexData::Int32(file_mtimes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDIGESTS,
                    offset,
                    IndexData::StringArray(file_hashes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILELINKTOS,
                    offset,
                    IndexData::StringArray(file_linktos),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEFLAGS,
                    offset,
                    IndexData::Int32(file_flags),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEUSERNAME,
                    offset,
                    IndexData::StringArray(file_usernames),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEGROUPNAME,
                    offset,
                    IndexData::StringArray(file_groupnames),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDEVICES,
                    offset,
                    IndexData::Int32(file_devices),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEINODES,
                    offset,
                    IndexData::Int32(file_inodes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_DIRINDEXES,
                    offset,
                    IndexData::Int32(dir_indixes),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILELANGS,
                    offset,
                    IndexData::StringArray(file_langs),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEDIGESTALGO,
                    offset,
                    IndexData::Int32(vec![DigestAlgorithm::Sha2_256 as u32]),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_FILEVERIFYFLAGS,
                    offset,
                    IndexData::Int32(file_verify_flags),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_BASENAMES,
                    offset,
                    IndexData::StringArray(base_names),
                ),
                IndexEntry::new(
                    IndexTag::RPMTAG_DIRNAMES,
                    offset,
                    IndexData::StringArray(self.directories.into_iter().collect()),
                ),
            ]);
            if file_caps.iter().any(|caps| caps.is_some()) {
                actual_records.extend([IndexEntry::new(
                    IndexTag::RPMTAG_FILECAPS,
                    offset,
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

        actual_records.extend([
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDENAME,
                offset,
                IndexData::StringArray(provide_names),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEVERSION,
                offset,
                IndexData::StringArray(provide_versions),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PROVIDEFLAGS,
                offset,
                IndexData::Int32(provide_flags),
            ),
        ]);

        // digest of the uncompressed raw archive calculated on the inner writer
        let raw_archive_digest_sha256 = hex::encode(archive.into_digest());
        let payload = compressor.finish_compression()?;

        // digest of the post-compression archive (payload)
        let payload_digest_sha256 = {
            let mut hasher = sha2::Sha256::default();
            hasher.update(payload.as_slice());
            hex::encode(hasher.finalize())
        };

        actual_records.extend([
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADDIGEST,
                offset,
                IndexData::StringArray(vec![payload_digest_sha256]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADDIGESTALGO,
                offset,
                IndexData::Int32(vec![DigestAlgorithm::Sha2_256 as u32]),
            ),
            IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADDIGESTALT,
                offset,
                IndexData::StringArray(vec![raw_archive_digest_sha256]),
            ),
        ]);

        let compression_details = match self.compression {
            CompressionWithLevel::None => None,
            CompressionWithLevel::Gzip(level) => Some(("gzip".to_owned(), level.to_string())),
            CompressionWithLevel::Zstd(level) => Some(("zstd".to_owned(), level.to_string())),
            CompressionWithLevel::Xz(level) => Some(("xz".to_owned(), level.to_string())),
            CompressionWithLevel::Bzip2(level) => Some(("bzip2".to_owned(), level.to_string())),
        };

        if let Some((compression_name, compression_level)) = compression_details {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADCOMPRESSOR,
                offset,
                IndexData::StringTag(compression_name),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_PAYLOADFLAGS,
                offset,
                IndexData::StringTag(compression_level),
            ));
        }

        if !self.changelog_names.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGNAME,
                offset,
                IndexData::StringArray(self.changelog_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTEXT,
                offset,
                IndexData::StringArray(self.changelog_entries),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CHANGELOGTIME,
                offset,
                IndexData::Int32(self.changelog_times.into_iter().map(Into::into).collect()),
            ));
        }

        if !obsolete_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETENAME,
                offset,
                IndexData::StringArray(obsolete_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEVERSION,
                offset,
                IndexData::StringArray(obsolete_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_OBSOLETEFLAGS,
                offset,
                IndexData::Int32(obsolete_flags),
            ));
        }

        if !require_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIRENAME,
                offset,
                IndexData::StringArray(require_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREVERSION,
                offset,
                IndexData::StringArray(require_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_REQUIREFLAGS,
                offset,
                IndexData::Int32(require_flags),
            ));
        }

        if !conflicts_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTNAME,
                offset,
                IndexData::StringArray(conflicts_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTVERSION,
                offset,
                IndexData::StringArray(conflicts_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_CONFLICTFLAGS,
                offset,
                IndexData::Int32(conflicts_flags),
            ));
        }

        if !recommends_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_RECOMMENDNAME,
                offset,
                IndexData::StringArray(recommends_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_RECOMMENDVERSION,
                offset,
                IndexData::StringArray(recommends_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_RECOMMENDFLAGS,
                offset,
                IndexData::Int32(recommends_flags),
            ));
        }

        if !suggests_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUGGESTNAME,
                offset,
                IndexData::StringArray(suggests_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUGGESTVERSION,
                offset,
                IndexData::StringArray(suggests_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUGGESTFLAGS,
                offset,
                IndexData::Int32(suggests_flags),
            ));
        }

        if !enhances_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ENHANCENAME,
                offset,
                IndexData::StringArray(enhances_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ENHANCEVERSION,
                offset,
                IndexData::StringArray(enhances_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_ENHANCEFLAGS,
                offset,
                IndexData::Int32(enhances_flags),
            ));
        }

        if !supplements_flags.is_empty() {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUPPLEMENTNAME,
                offset,
                IndexData::StringArray(supplements_names),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUPPLEMENTVERSION,
                offset,
                IndexData::StringArray(supplements_versions),
            ));
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_SUPPLEMENTFLAGS,
                offset,
                IndexData::Int32(supplements_flags),
            ));
        }

        if let Some(script) = self.pre_inst_script {
            script.apply(&mut actual_records, offset, PREIN_TAGS);
        }

        if let Some(script) = self.post_inst_script {
            script.apply(&mut actual_records, offset, POSTIN_TAGS);
        }

        if let Some(script) = self.pre_uninst_script {
            script.apply(&mut actual_records, offset, PREUN_TAGS);
        }

        if let Some(script) = self.post_uninst_script {
            script.apply(&mut actual_records, offset, POSTUN_TAGS);
        }

        if let Some(script) = self.pre_trans_script {
            script.apply(&mut actual_records, offset, PRETRANS_TAGS);
        }

        if let Some(script) = self.post_trans_script {
            script.apply(&mut actual_records, offset, POSTTRANS_TAGS);
        }

        if let Some(script) = self.pre_untrans_script {
            script.apply(&mut actual_records, offset, PREUNTRANS_TAGS);
        }

        if let Some(script) = self.post_untrans_script {
            script.apply(&mut actual_records, offset, POSTUNTRANS_TAGS);
        }

        if let Some(vendor) = self.vendor {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_VENDOR,
                offset,
                IndexData::StringTag(vendor),
            ));
        }

        if let Some(url) = self.url {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_URL,
                offset,
                IndexData::StringTag(url),
            ));
        }

        if let Some(vcs) = self.vcs {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_VCS,
                offset,
                IndexData::StringTag(vcs),
            ));
        }

        if let Some(cookie) = self.cookie {
            actual_records.push(IndexEntry::new(
                IndexTag::RPMTAG_COOKIE,
                offset,
                IndexData::StringTag(cookie),
            ));
        }

        let header = Header::from_entries(actual_records, IndexTag::RPMTAG_HEADERIMMUTABLE);

        Ok((lead, header, payload))
    }
}
