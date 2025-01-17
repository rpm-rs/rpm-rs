use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

use digest::Digest;
use num_traits::FromPrimitive;

use crate::{constants::*, decompress_stream, errors::*, CompressionType};

#[cfg(feature = "signature-pgp")]
use crate::signature::pgp::Verifier;
#[cfg(feature = "signature-meta")]
use crate::{signature, Timestamp};
#[cfg(feature = "signature-meta")]
use std::fmt::Debug;

use super::headers::*;
use super::Lead;

/// A complete rpm file.
///
/// Can either be created using the [`PackageBuilder`](crate::PackageBuilder)
/// or used with [`parse`](`self::Package::parse`) to obtain from a file.
#[derive(Debug)]
pub struct Package {
    /// Header and metadata structures.
    ///
    /// Contains the constant lead as well as the metadata store.
    pub metadata: PackageMetadata,
    /// The compressed or uncompressed files.
    pub content: Vec<u8>,
}

impl Package {
    /// Open and parse a file at the provided path as an RPM package
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let rpm_file = fs::File::open(path.as_ref())?;
        let mut buf_reader = io::BufReader::new(rpm_file);
        Self::parse(&mut buf_reader)
    }

    /// Parse an RPM package from an existing buffer
    pub fn parse(input: &mut impl io::BufRead) -> Result<Self, Error> {
        let metadata = PackageMetadata::parse(input)?;
        let mut content = Vec::new();
        input.read_to_end(&mut content)?;
        Ok(Package { metadata, content })
    }

    /// Write the RPM package to a buffer
    pub fn write(&self, out: &mut impl io::Write) -> Result<(), Error> {
        self.metadata.write(out)?;
        out.write_all(&self.content)?;
        Ok(())
    }

    /// Write the RPM package to a file
    pub fn write_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        self.write(&mut io::BufWriter::new(fs::File::create(path)?))
    }

    /// Iterate over the file contents of the package payload
    ///
    /// # Examples
    /// ```ignore
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("test_assets/freesrp-udev-0.3.0-1.25.x86_64.rpm")?;
    /// for entry in package.files()? {
    ///     let file = entry?;
    ///     // do something with file.content
    ///     println!("{} is {} bytes", file.metadata.path.display(), file.content.len());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn files(&self) -> Result<FileIterator, Error> {
        let file_entries = self.metadata.get_file_entries()?;
        let archive = decompress_stream(
            self.metadata.get_payload_compressor()?,
            io::Cursor::new(self.content.clone()),
        )?;

        Ok(FileIterator {
            file_entries,
            archive,
            count: 0,
        })
    }

    /// Extract all contents of the package payload to a given directory
    ///
    /// # Examples
    /// ```ignore
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("test_assets/ima_signed.rpm")?;
    /// package.extract(&package.metadata.get_name()?)?;
    /// # Ok(()) }
    /// ```
    pub fn extract(&self, dest: impl AsRef<Path>) -> Result<(), Error> {
        fs::create_dir_all(&dest)?;

        let dirs = self
            .metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_DIRNAMES)?;

        // pull every base directory name in the package and create the directory in advance
        for dir in dirs {
            let dir_path = dest
                .as_ref()
                .join(Path::new(dir).strip_prefix("/").unwrap_or(dest.as_ref()));
            fs::create_dir_all(&dir_path)?;
        }

        // TODO: reduce memory by replacing this with an impl that writes the files immediately after reading them from the archive
        // instead of reading each file entirely into memory (while the archive is also entirely in memory) before writing them
        for file in self.files()? {
            let file = file?;
            let file_path = dest.as_ref().join(
                file.metadata
                    .path
                    .strip_prefix("/")
                    .unwrap_or(dest.as_ref()),
            );

            let perms = fs::Permissions::from_mode(file.metadata.mode.permissions().into());
            match file.metadata.mode {
                FileMode::Dir { .. } => {
                    fs::create_dir_all(&file_path)?;
                    fs::set_permissions(&file_path, perms)?;
                }
                FileMode::Regular { .. } => {
                    let mut f = fs::File::create(&file_path)?;
                    f.write_all(&file.content)?;
                    fs::set_permissions(&file_path, perms)?;
                }
                FileMode::SymbolicLink { .. } => {
                    // broken symlinks (common for debuginfo handling) are perceived as not existing by "exists()"
                    if file_path.exists() || file_path.symlink_metadata().is_ok() {
                        fs::remove_file(&file_path)?;
                    }
                    std::os::unix::fs::symlink(&file.metadata.linkto, &file_path)?;
                }
                _ => unreachable!("Encountered an unknown or invalid FileMode"),
            }
        }

        Ok(())
    }

    /// Create package signatures using an external key and add them to the signature header
    #[cfg(feature = "signature-meta")]
    pub fn sign<S>(&mut self, signer: S) -> Result<(), Error>
    where
        S: signature::Signing<Signature = Vec<u8>>,
    {
        self.sign_with_timestamp(signer, Timestamp::now())
    }

    /// Create package signatures using an external key and provided timestamp.
    /// Adds generated signatures to the signature header.
    ///
    /// This method is usually used for reproducible builds, otherwise you should
    /// prefer using the [`sign`][Package::sign] method instead.
    ///
    /// # Examples
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut package = rpm::Package::open("test_assets/ima_signed.rpm")?;
    /// let raw_secret_key = std::fs::read("./test_assets/secret_key.asc")?;
    /// let signer = rpm::signature::pgp::Signer::load_from_asc_bytes(&raw_secret_key)?;
    /// // It's recommended to use timestamp of last commit in your VCS
    /// let source_date = 1_600_000_000;
    /// package.sign_with_timestamp(signer, source_date)?;
    /// # Ok(()) }
    /// ```
    #[cfg(feature = "signature-meta")]
    pub fn sign_with_timestamp<S>(
        &mut self,
        signer: S,
        t: impl TryInto<Timestamp, Error = impl Debug>,
    ) -> Result<(), Error>
    where
        S: signature::Signing<Signature = Vec<u8>>,
    {
        let t = t.try_into().unwrap();
        // create a temporary byte repr of the header and re-create all hashes
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        // make sure to not hash any previous signatures in the header
        self.metadata.header.write(&mut header_bytes)?;

        let header_digest_sha256 = hex::encode(sha2::Sha256::digest(header_bytes.as_slice()));
        let header_signature = signer.sign(header_bytes.as_slice(), t)?;

        let sig_header_builder =
            Header::<IndexSignatureTag>::builder().add_digest(&header_digest_sha256);

        let sig_header_builder = match signer.algorithm() {
            crate::signature::AlgorithmType::RSA => {
                sig_header_builder.add_rsa_signature(&header_signature)
            }
            crate::signature::AlgorithmType::EdDSA => {
                sig_header_builder.add_eddsa_signature(&header_signature)
            }
            crate::signature::AlgorithmType::ECDSA => {
                sig_header_builder.add_ecdsa_signature(&header_signature)
            }
        };

        self.metadata.signature = sig_header_builder.build();
        Ok(())
    }

    /// Return the key ids (issuers) of the signature as a hexadecimal string
    #[cfg(feature = "signature-pgp")]
    pub fn signature_key_ids(&self) -> Result<Vec<String>, Error> {
        let mut signature = Err(Error::NoSignatureFound);
        let rsa_sig = &self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RSA);
        if let Ok(rsa_sig) = rsa_sig {
            signature = Verifier::parse_signature(rsa_sig);
        }

        let eddsa_sig = &self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_DSA);
        if let Ok(eddsa_sig) = eddsa_sig {
            signature = Verifier::parse_signature(eddsa_sig);
        }

        let rpm_v3_sig = &self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_PGP);
        if let Ok(rpm_v3_sig) = rpm_v3_sig {
            signature = Verifier::parse_signature(rpm_v3_sig);
        }

        let key_ids = signature?
            .issuer()
            .iter()
            .map(|x| format!("{:x}", x))
            .collect();
        Ok(key_ids)
    }

    // @todo: verify_signature() and verify_digests() don't provide any feedback on whether a signature/digest
    //        was present and verified or whether it was not present at all.

    /// Verify the signature as present within the RPM package.
    #[cfg(feature = "signature-meta")]
    pub fn verify_signature<V>(&self, verifier: V) -> Result<(), Error>
    where
        V: signature::Verifying<Signature = Vec<u8>>,
    {
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;
        self.verify_digests()?;

        let rsa_sig = &self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RSA);
        let eddsa_sig = &self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_DSA);
        let rpm_v3_sig = &self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_PGP);

        if !rsa_sig.is_ok() && !eddsa_sig.is_ok() && !rpm_v3_sig.is_ok() {
            return Err(Error::NoSignatureFound);
        }

        if let Ok(signature_header_only) = eddsa_sig {
            signature::echo_signature("signature_header(header only)", signature_header_only);
            verifier.verify(header_bytes.as_slice(), signature_header_only)?;
        }

        if let Ok(signature_header_and_content) = rpm_v3_sig {
            signature::echo_signature(
                "signature_header(header and content)",
                signature_header_and_content,
            );
            let header_and_content_cursor =
                io::Cursor::new(&header_bytes).chain(io::Cursor::new(&self.content));
            verifier.verify(header_and_content_cursor, signature_header_and_content)?;
        }

        if let Ok(signature_header_only) = rsa_sig {
            signature::echo_signature("signature_header(header only)", signature_header_only);
            verifier.verify(header_bytes.as_slice(), signature_header_only)?;
        }

        Ok(())
    }

    /// Verify any digests which may be present in the RPM headers
    pub fn verify_digests(&self) -> Result<(), Error> {
        let mut header = Vec::<u8>::with_capacity(1024);
        // make sure to not hash any previous signatures in the header
        self.metadata.header.write(&mut header)?;

        let md5_declared = self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_MD5);
        let sha1_declared = self
            .metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA1);
        let sha256_declared = self
            .metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256);

        if let Ok(md5_declared) = md5_declared {
            let header_and_content_digest_md5 = {
                let mut hasher = md5::Md5::default();
                hasher.update(&header);
                hasher.update(&self.content);
                let hash_result = hasher.finalize();
                hash_result.to_vec()
            };
            if md5_declared != header_and_content_digest_md5 {
                return Err(Error::DigestMismatchError);
            }
        }

        if let Ok(sha1_declared) = sha1_declared {
            let header_digest_sha1 = hex::encode(sha1::Sha1::digest(header.as_slice()));
            if sha1_declared != header_digest_sha1 {
                return Err(Error::DigestMismatchError);
            }
        }

        if let Ok(sha256) = sha256_declared {
            let header_digest_sha256 = hex::encode(sha2::Sha256::digest(header.as_slice()));
            if sha256 != header_digest_sha256 {
                return Err(Error::DigestMismatchError);
            }
        }

        let payload_digest_val = self
            .metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADDIGEST);
        let payload_digest_algo = self
            .metadata
            .header
            .get_entry_data_as_u32(IndexTag::RPMTAG_PAYLOADDIGESTALGO);

        if let (Ok(payload_digest_val), Ok(payload_digest_algo)) =
            (payload_digest_val, payload_digest_algo)
        {
            let payload_digest_algo = DigestAlgorithm::from_u32(payload_digest_algo)
                .expect("Completely unknown payload digest algorithm");

            // @todo: UnsupportedDigestAlgorithm is awkward, if a number is outside the range of the expected
            // variants to begin with, we can't even return it, as it carries a DigestAlgorithm. But also, in
            // this case even when it is "supported" by the library in general it is not supported here in particular
            // Not that that should happen here for a while to come.

            let mut hasher = match payload_digest_algo {
                DigestAlgorithm::Sha2_256 => sha2::Sha256::default(),
                a => return Err(Error::UnsupportedDigestAlgorithm(a)),
                // At the present moment even rpmbuild only supports sha256
            };
            let payload_digest = {
                hasher.update(self.content.as_slice());
                hex::encode(hasher.finalize())
            };
            if payload_digest != payload_digest_val[0] {
                return Err(Error::DigestMismatchError);
            }
        }

        Ok(())
    }
}

#[derive(PartialEq, Debug)]
pub struct PackageMetadata {
    pub lead: Lead,
    pub signature: Header<IndexSignatureTag>,
    pub header: Header<IndexTag>,
}

impl PackageMetadata {
    /// Open and parse PackageMetadata from the file at the provided path
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let rpm_file = fs::File::open(path.as_ref())?;
        let mut buf_reader = io::BufReader::new(rpm_file);
        Self::parse(&mut buf_reader)
    }

    /// Parse PackageMetadata from the provided reader
    pub fn parse(input: &mut impl io::BufRead) -> Result<Self, Error> {
        let mut lead_buffer = [0; LEAD_SIZE as usize];
        input.read_exact(&mut lead_buffer)?;
        let lead = Lead::parse(&lead_buffer)?;
        let signature_header = Header::parse_signature(input)?;
        let header = Header::parse(input)?;

        Ok(PackageMetadata {
            lead,
            signature: signature_header,
            header,
        })
    }

    /// Write the RPM header to a buffer
    pub fn write(&self, out: &mut impl io::Write) -> Result<(), Error> {
        self.lead.write(out)?;
        self.signature.write_signature(out)?;
        self.header.write(out)?;
        Ok(())
    }

    /// Whether this package is a source package, or not
    #[inline]
    pub fn is_source_package(&self) -> bool {
        self.header.entry_is_present(IndexTag::RPMTAG_SOURCEPACKAGE)
    }

    /// Get the package name
    #[inline]
    pub fn get_name(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_NAME)
    }

    /// Get the package epoch
    #[inline]
    pub fn get_epoch(&self) -> Result<u32, Error> {
        self.header.get_entry_data_as_u32(IndexTag::RPMTAG_EPOCH)
    }

    /// Get the package version (the upstream version string)
    #[inline]
    pub fn get_version(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VERSION)
    }

    /// Get the package release
    #[inline]
    pub fn get_release(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_RELEASE)
    }

    /// Get the package architecture
    #[inline]
    pub fn get_arch(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_ARCH)
    }

    /// Get the package vendor - the organization that produced the package
    #[inline]
    pub fn get_vendor(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VENDOR)
    }

    /// Get the package URL. Most often this is the upstream project website for the software
    /// being packaged.
    #[inline]
    pub fn get_url(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_URL)
    }

    /// Get the package version control URL (of the upstream project)
    #[inline]
    pub fn get_vcs(&self) -> Result<&str, Error> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_VCS)
    }

    /// Get the package license
    #[inline]
    pub fn get_license(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_LICENSE)
    }

    /// Get the package summary (very brief description of the packaged software)
    #[inline]
    pub fn get_summary(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_SUMMARY)
    }

    /// Get the package description (a full description of the packaged software)
    #[inline]
    pub fn get_description(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_DESCRIPTION)
    }

    /// Get the package group (this is deprecated in most packaging guidelines)
    #[inline]
    pub fn get_group(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_GROUP)
    }

    /// Get the packager, the name of the person that produced this package
    #[inline]
    pub fn get_packager(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PACKAGER)
    }

    /// Get the timestamp when this package was built. This is commonly not present.
    #[inline]
    pub fn get_build_time(&self) -> Result<u64, Error> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_BUILDTIME)
            .map(|x| x as u64)
    }

    /// Get the build host on which this package was built. This is commonly not present.
    #[inline]
    pub fn get_build_host(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_BUILDHOST)
    }

    /// The cookie is a value that can be used for tracking packages built together, e.g.
    /// packages built in one build operation (from a single source RPM, for example).
    #[inline]
    pub fn get_cookie(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_COOKIE)
    }

    /// Get the filename of the source RPM package used to build this package
    #[inline]
    pub fn get_source_rpm(&self) -> Result<&str, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_SOURCERPM)
    }

    /// Get the %pre scriptlet for this package
    #[inline]
    pub fn get_pre_install_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PREIN_TAGS)
    }

    /// Get the %post scriptlet for this package
    #[inline]
    pub fn get_post_install_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTIN_TAGS)
    }

    /// Get the %preun scriptlet for this package
    #[inline]
    pub fn get_pre_uninstall_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PREUN_TAGS)
    }

    /// Get the %postun scriptlet for this package
    #[inline]
    pub fn get_post_uninstall_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTUN_TAGS)
    }

    /// Get the %pretrans scriptlet for this package
    #[inline]
    pub fn get_pre_trans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PRETRANS_TAGS)
    }

    /// Get the %posttrans scriptlet for this package
    #[inline]
    pub fn get_post_trans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTTRANS_TAGS)
    }

    /// Get the %preuntrans scriptlet for this package
    #[inline]
    pub fn get_pre_untrans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(PREUNTRANS_TAGS)
    }

    /// Get the %postuntrans scriptlet for this package
    #[inline]
    pub fn get_post_untrans_script(&self) -> Result<Scriptlet, Error> {
        self.get_scriptlet(POSTUNTRANS_TAGS)
    }

    fn get_dependencies(
        &self,
        names_tag: IndexTag,
        flags_tag: IndexTag,
        versions_tag: IndexTag,
    ) -> Result<Vec<Dependency>, Error> {
        let names = self.header.get_entry_data_as_string_array(names_tag);
        let flags = self.header.get_entry_data_as_u32_array(flags_tag);
        let versions = self.header.get_entry_data_as_string_array(versions_tag);

        match (names, flags, versions) {
            // Return an empty list if the tags are not present
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(names), Ok(flags), Ok(versions)) => {
                let v = Vec::from_iter(itertools::multizip((names, flags, versions)).map(
                    |(name, flags, version)| Dependency {
                        name: name.to_owned(),
                        flags: DependencyFlags::from_bits_retain(flags),
                        version: version.to_owned(),
                    },
                ));
                Ok(v)
            }
            (names, flags, versions) => {
                names?;
                flags?;
                versions?;
                unreachable!()
            }
        }
    }

    fn get_scriptlet(&self, tags: ScriptletIndexTags) -> Result<Scriptlet, Error> {
        let (scriptlet_tag, flags_tag, program_tag) = tags;

        let script = self
            .header
            .get_entry_data_as_string(scriptlet_tag)
            .map(|s| s.to_string())?;
        let flags = self
            .header
            .get_entry_data_as_u32(flags_tag)
            .ok()
            .map(ScriptletFlags::from_bits_retain);
        let program = self
            .header
            .get_entry_data_as_string_array(program_tag)
            .ok()
            .map(|p| p.to_owned());

        Ok(Scriptlet {
            script,
            flags,
            program,
        })
    }

    /// Get a list of dependencies which this package "provides"
    ///
    /// These are aliases or capabilities provided by this package which other packages can reference.
    pub fn get_provides(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_PROVIDENAME,
            IndexTag::RPMTAG_PROVIDEFLAGS,
            IndexTag::RPMTAG_PROVIDEVERSION,
        )
    }

    /// Get a list of dependencies which this package "requires"
    ///
    /// These are packages or capabilities which must be present in order for the package to be
    /// installed.
    pub fn get_requires(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_REQUIRENAME,
            IndexTag::RPMTAG_REQUIREFLAGS,
            IndexTag::RPMTAG_REQUIREVERSION,
        )
    }

    /// Get a list of dependencies which this package "conflicts" with
    ///
    /// These are packages which must not be present in order for the package to be installed.
    pub fn get_conflicts(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_CONFLICTNAME,
            IndexTag::RPMTAG_CONFLICTFLAGS,
            IndexTag::RPMTAG_CONFLICTVERSION,
        )
    }

    /// Get a list of dependencies which this package "obsoletes"
    ///
    /// These are packages which are superceded by this package - if this package is installed,
    /// they will be automatically removed if they are present.
    pub fn get_obsoletes(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_OBSOLETENAME,
            IndexTag::RPMTAG_OBSOLETEFLAGS,
            IndexTag::RPMTAG_OBSOLETEVERSION,
        )
    }

    /// Get a list of dependencies which this package "recommends"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat them
    /// as though they were "requires".  Unlike "requires" however, if installing a package listed
    /// as a "recommends" would cause errors, it may be ignored without error.
    pub fn get_recommends(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_RECOMMENDNAME,
            IndexTag::RPMTAG_RECOMMENDFLAGS,
            IndexTag::RPMTAG_RECOMMENDVERSION,
        )
    }

    /// Get a list of dependencies which this package "suggests"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// them to the user to be optionally installed.
    pub fn get_suggests(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_SUGGESTNAME,
            IndexTag::RPMTAG_SUGGESTFLAGS,
            IndexTag::RPMTAG_SUGGESTVERSION,
        )
    }

    /// Get a list of reverse-dependencies which this package "enhances"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to display
    /// this package to the user to be optionally installed when a package matching the "enhances"
    /// dependency is installed.
    pub fn get_enhances(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_ENHANCENAME,
            IndexTag::RPMTAG_ENHANCEFLAGS,
            IndexTag::RPMTAG_ENHANCEVERSION,
        )
    }

    /// Get a list of reverse-dependencies which this package "supplements"
    ///
    /// "rpm" itself will ignore such dependencies, but a dependency solver may elect to treat this
    /// package as a "requires" when the matching package is installed. Unlike a "requires" however,
    /// if installing it would cause errors, it can be ignored ignored without error.
    pub fn get_supplements(&self) -> Result<Vec<Dependency>, Error> {
        self.get_dependencies(
            IndexTag::RPMTAG_SUPPLEMENTNAME,
            IndexTag::RPMTAG_SUPPLEMENTFLAGS,
            IndexTag::RPMTAG_SUPPLEMENTVERSION,
        )
    }

    /// An RPM package is comprised of several segments - the Lead, Signature Header, Header, and Payload.
    /// This function returns the computed (byte) boundaries between those segments in the package file
    /// as if it were written out on-disk.
    ///
    /// ```
    /// # use rpm::Package;
    /// # let package = Package::open("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm").unwrap();
    /// let offsets = package.metadata.get_package_segment_offsets();
    /// let lead = offsets.lead..offsets.signature_header;
    /// let sig_header = offsets.signature_header..offsets.header;
    /// let header = offsets.header..offsets.payload;
    /// let payload = offsets.payload..;
    /// ```
    pub fn get_package_segment_offsets(&self) -> PackageSegmentOffsets {
        // Lead is 96 bytes.

        // Each Header starts like this (16 bytes)
        // 3 bytes for the magic
        // 1 byte RPM version number - always 1
        // 4 reserved bytes (no meaning, just padding)
        // 4 bytes for the number of entries in the index (u32)
        // 4 bytes for the length of the data section (u32)

        // Next comes a series of index entries
        // Each index entry is 16 bytes
        // 4 bytes for the tag (u32)
        // 4 bytes for the tag data type (u32)
        // 4 bytes for the offset relative to the beginning of the data store
        // 4 bytes for the count that contains the number of data items pointed to by the index entry

        // After the header entries comes the data section. This stores the data pointed to by
        // the offsets within each index entry.

        let sig_header_start = LEAD_SIZE;
        let sig_header_size = self.signature.size();
        let padding = self.signature.padding_required();

        let header_start = sig_header_start + sig_header_size + padding;
        let header_size = self.header.size();

        let payload_start = header_start + header_size;

        PackageSegmentOffsets {
            lead: 0,
            signature_header: sig_header_start as u64,
            header: header_start as u64,
            payload: payload_start as u64,
        }
    }

    /// Get the sum of the sizes of all files present in the package payload
    pub fn get_installed_size(&self) -> Result<u64, Error> {
        self.header
            .get_entry_data_as_u64(IndexTag::RPMTAG_LONGSIZE)
            .or_else(|_e| {
                self.header
                    .get_entry_data_as_u32(IndexTag::RPMTAG_SIZE)
                    .map(|v| v as u64)
            })
    }

    #[inline]
    pub fn get_payload_compressor(&self) -> Result<CompressionType, Error> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
            .map_or_else(
                |e| {
                    if matches!(e, Error::TagNotFound(_)) {
                        Ok(CompressionType::None)
                    } else {
                        Err(e)
                    }
                },
                CompressionType::from_str,
            )
    }

    /// Extract a the set of contained file names.
    ///
    /// # Examples
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("test_assets/ima_signed.rpm")?;
    /// for path in package.metadata.get_file_paths()? {
    ///     println!("{}", path.display());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn get_file_paths(&self) -> Result<Vec<PathBuf>, Error> {
        // reconstruct the messy de-constructed paths
        let basenames = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_BASENAMES);
        let biject = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_DIRINDEXES);
        let dirs = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_DIRNAMES);

        // Return an empty list if the tags are not present
        match (basenames, biject, dirs) {
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(basenames), Ok(biject), Ok(dirs)) => {
                let n = dirs.len();

                let v = basenames
                    .iter()
                    .zip(biject.into_iter())
                    .try_fold::<Vec<PathBuf>, _, _>(
                        Vec::<PathBuf>::with_capacity(basenames.len()),
                        |mut acc, item| {
                            let (basename, dir_index) = item;
                            if let Some(dir) = dirs.get(dir_index as usize) {
                                acc.push(Path::new(dir).join(basename));
                                Ok(acc)
                            } else {
                                Err(Error::InvalidTagIndex {
                                    tag: IndexTag::RPMTAG_DIRINDEXES.to_string(),
                                    index: dir_index,
                                    bound: n as u32,
                                })
                            }
                        },
                    )?;
                Ok(v)
            }
            (basenames, biject, dirs) => {
                basenames?;
                biject?;
                dirs?;
                unreachable!()
            }
        }
    }

    /// The digest algorithm used per file.
    ///
    /// Note that this is not necessarily the same as the digest
    /// used for headers.
    pub fn get_file_digest_algorithm(&self) -> Result<DigestAlgorithm, Error> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_FILEDIGESTALGO)
            .and_then(|x| {
                DigestAlgorithm::from_u32(x).ok_or_else(|| Error::InvalidTagValueEnumVariant {
                    tag: IndexTag::RPMTAG_FILEDIGESTALGO.to_string(),
                    variant: x,
                })
            })
    }

    /// Get a list of metadata about the files in the RPM, without the file contents.
    ///
    /// # Examples
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("test_assets/ima_signed.rpm")?;
    /// for entry in package.metadata.get_file_entries()? {
    ///     println!("{} is {} bytes", entry.path.display(), entry.size);
    /// }
    /// # Ok(()) }
    /// ```
    pub fn get_file_entries(&self) -> Result<Vec<FileEntry>, Error> {
        // rpm does not encode it, if it is the default md5
        let algorithm = self
            .get_file_digest_algorithm()
            .unwrap_or(DigestAlgorithm::Md5);
        //
        let modes = self
            .header
            .get_entry_data_as_u16_array(IndexTag::RPMTAG_FILEMODES);
        if let Err(Error::TagNotFound(_)) = modes {
            return Ok(Vec::new());
        }

        let users = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEUSERNAME);
        let groups = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEGROUPNAME);
        let digests = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEDIGESTS);
        let mtimes = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILEMTIMES);
        let sizes = self
            .header
            .get_entry_data_as_u64_array(IndexTag::RPMTAG_LONGFILESIZES)
            .or_else(|_e| {
                self.header
                    .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILESIZES)
                    .map(|file_sizes| {
                        file_sizes
                            .into_iter()
                            .map(|file_size| file_size as _)
                            .collect::<Vec<u64>>()
                    })
            });
        let flags = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILEFLAGS);

        // Look for the file capabilities tag
        // but it's not required so don't error out if it's not
        let caps = match self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILECAPS)
        {
            Ok(caps) => Ok(Some(caps)),
            Err(Error::TagNotFound(_)) => Ok(None),
            Err(e) => return Err(e),
        };
        let links = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILELINKTOS);
        let ima_signatures = match self
            .signature
            .get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_FILESIGNATURES)
        {
            Ok(ima_signatures) => Ok(Some(ima_signatures)),
            Err(Error::TagNotFound(_)) => Ok(None),
            Err(e) => {
                println!("{e:?}");
                return Err(e);
            }
        };

        match (
            modes,
            users,
            groups,
            digests,
            mtimes,
            sizes,
            flags,
            caps,
            links,
            ima_signatures,
        ) {
            (
                Ok(modes),
                Ok(users),
                Ok(groups),
                Ok(digests),
                Ok(mtimes),
                Ok(sizes),
                Ok(flags),
                Ok(caps),
                Ok(links),
                Ok(ima_signatures),
            ) => {
                let paths = self.get_file_paths()?;
                let n = paths.len();

                let v = itertools::multizip((
                    paths.into_iter(),
                    users,
                    groups,
                    modes,
                    digests,
                    mtimes,
                    sizes,
                    flags,
                    links,
                ))
                .enumerate()
                .try_fold::<Vec<FileEntry>, _, Result<_, Error>>(
                    Vec::with_capacity(n),
                    |mut acc, (idx, (path, user, group, mode, digest, mtime, size, flags, linkto))| {
                        let digest = if digest.is_empty() {
                            None
                        } else {
                            Some(FileDigest::new(algorithm, digest)?)
                        };
                        let cap = match caps {
                            Some(caps) => caps.get(idx).map(|x| x.to_owned()),
                            None => None,
                        };
                        let ima_signature: Option<String> = match ima_signatures {
                            Some(ima_signatures) => ima_signatures.get(idx).map(|x| x.to_owned()),
                            None => None,
                        };
                        acc.push(FileEntry {
                            path,
                            ownership: FileOwnership {
                                user: user.to_owned(),
                                group: group.to_owned(),
                            },
                            mode: mode.into(),
                            modified_at: crate::Timestamp(mtime),
                            digest,
                            flags: FileFlags::from_bits_retain(flags),
                            size: size as usize,
                            caps: cap,
                            linkto: linkto.to_owned(),
                            ima_signature,
                        });
                        Ok(acc)
                    },
                )?;
                Ok(v)
            }
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (modes, users, groups, digests, mtimes, sizes, flags, caps, links, ima_signatures) => {
                modes?;
                users?;
                groups?;
                digests?;
                mtimes?;
                sizes?;
                flags?;
                caps?;
                links?;
                ima_signatures?;
                unreachable!()
            }
        }
    }

    /// Return a list of changelog entries
    pub fn get_changelog_entries(&self) -> Result<Vec<ChangelogEntry>, Error> {
        let names = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_CHANGELOGNAME);
        let timestamps = self
            .header
            .get_entry_data_as_u32_array(IndexTag::RPMTAG_CHANGELOGTIME);
        let descriptions = self
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_CHANGELOGTEXT);

        // Return an empty list if the tags are not present
        match (names, timestamps, descriptions) {
            (
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
                Err(Error::TagNotFound(_)),
            ) => Ok(vec![]),
            (Ok(names), Ok(timestamps), Ok(descriptions)) => {
                let v = Vec::from_iter(itertools::multizip((names, timestamps, descriptions)).map(
                    |(name, timestamp, description)| ChangelogEntry {
                        name: name.to_owned(),
                        timestamp: timestamp as u64,
                        description: description.to_owned(),
                    },
                ));
                Ok(v)
            }
            (name, timestamp, description) => {
                name?;
                timestamp?;
                description?;
                unreachable!()
            }
        }
    }
}

pub struct FileIterator<'a> {
    file_entries: Vec<FileEntry>,
    archive: Box<dyn io::Read + 'a>,
    count: usize,
}

#[derive(Debug)]
pub struct RpmFile {
    pub metadata: FileEntry,
    pub content: Vec<u8>,
}

impl Iterator for FileIterator<'_> {
    type Item = Result<RpmFile, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count >= self.file_entries.len() {
            return None;
        }

        let file_entry = self.file_entries[self.count].clone();
        self.count += 1;

        let reader = cpio::NewcReader::new(&mut self.archive);

        match reader {
            Ok(mut entry_reader) => {
                if entry_reader.entry().is_trailer() {
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
