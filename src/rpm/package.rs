#[cfg(feature = "signature-meta")]
use std::io::Read;
use std::{
    fmt, fs,
    io::{self, Seek},
    path::{Path, PathBuf},
    str::FromStr,
};

use digest::Digest;
use num_traits::FromPrimitive;

use crate::rpm::skip_reader::SkipReader;
use crate::{constants::*, errors::*, CompressionType};
#[cfg(feature = "signature-meta")]
use crate::{signature, Timestamp};

use super::headers::*;
use super::Lead;

/// Combined digest of signature header tags `RPMSIGTAG_MD5` and `RPMSIGTAG_SHA1`
///
/// Succinct to cover to "verify" the content of the rpm file. Quotes because
/// the fact `md5` is used doesn't really give any guarantee anything anymore
/// in the 2020s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    /// The sha256 digest of the header.
    pub(crate) header_digest_sha256: String,
    /// The sha1 digest of the header.
    pub(crate) header_digest_sha1: String,
    /// The sha1 digest of the entire header + payload
    pub(crate) header_and_content_digest: Vec<u8>,
}

/// A complete rpm file.
///
/// Can either be created using the [`RPMBuilder`](super::builder::RPMBuilder)
/// or used with [`parse`](`self::RPMPackage::parse`) to obtain from a file.
pub struct RPMPackage<R> {
    /// Header and metadata structures.
    ///
    /// Contains the constant lead as well as the metadata store.
    pub metadata: RPMPackageMetadata,
    /// The compressed or uncompressed files.
    pub content: R,
}

#[cfg(feature = "signature-meta")]
fn stream_len(mut stream: impl Seek) -> io::Result<u64> {
    let old_pos = stream.stream_position()?;
    let len = stream.seek(io::SeekFrom::End(0))?;

    // Avoid seeking a third time when we were already at the end of the
    // stream. The branch is usually way cheaper than a seek operation.
    if old_pos != len {
        stream.seek(io::SeekFrom::Start(old_pos))?;
    }

    Ok(len)
}

impl RPMPackage<()> {
    /// Open and parse a file at the provided path as an RPM package
    pub fn open(
        path: impl AsRef<Path>,
    ) -> Result<RPMPackage<SkipReader<io::BufReader<fs::File>>>, RPMError> {
        let rpm_file = fs::File::open(path.as_ref())?;
        let buf_reader = io::BufReader::new(rpm_file);
        RPMPackage::parse(buf_reader)
    }
}

impl<R: io::BufRead + Seek> RPMPackage<R> {
    /// Parse an RPM package from an existing buffer
    pub fn parse(mut input: R) -> Result<RPMPackage<SkipReader<R>>, RPMError> {
        let metadata = RPMPackageMetadata::parse(&mut input)?;
        let content = SkipReader::new(input)?;
        Ok(RPMPackage { metadata, content })
    }

    /// Write the RPM package to a buffer
    pub fn write(&mut self, out: &mut impl io::Write) -> Result<(), RPMError> {
        self.metadata.write(out)?;
        io::copy(&mut self.content, out)?;
        self.content.rewind()?;
        Ok(())
    }

    /// Write the RPM package to a file
    pub fn write_file(&mut self, path: impl AsRef<Path>) -> Result<(), RPMError> {
        self.write(&mut io::BufWriter::new(fs::File::create(path)?))
    }

    /// Prepare both header and content digests as used by the `SignatureIndex`.
    pub(crate) fn create_sig_header_digests(
        header: &[u8],
        payload: &mut R,
    ) -> Result<Digests, RPMError> {
        let digest_md5 = {
            let mut hasher = md5::Md5::default();
            hasher.update(header);
            io::copy(payload, &mut hasher)?;
            payload.rewind()?;
            let hash_result = hasher.finalize();
            hash_result.to_vec()
        };

        let digest_sha1 = hex::encode(sha1::Sha1::digest(header));
        let digest_sha256 = hex::encode(sha2::Sha256::digest(header));

        Ok(Digests {
            header_digest_sha256: digest_sha256,
            header_digest_sha1: digest_sha1,
            header_and_content_digest: digest_md5,
        })
    }

    /// Create package signatures using an external key and add them to the signature header
    #[cfg(feature = "signature-meta")]
    pub fn sign<S>(&mut self, signer: S) -> Result<(), RPMError>
    where
        S: signature::Signing<signature::algorithm::RSA, Signature = Vec<u8>>,
    {
        self.sign_with_timestamp(signer, Timestamp::now())
    }

    /// Create package signatures using an external key and provided timestamp.
    /// Adds generated signatures to the signature header.
    ///
    /// This method is usually used for reproducible builds, otherwise you should
    /// prefer using the [`sign`][RPMPackage::sign] method instead.
    ///
    /// # Examples
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut package = rpm::RPMPackage::open("test_assets/ima_signed.rpm")?;
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
        t: impl TryInto<Timestamp, Error = impl fmt::Debug>,
    ) -> Result<(), RPMError>
    where
        S: signature::Signing<signature::algorithm::RSA, Signature = Vec<u8>>,
    {
        let t = t.try_into().unwrap();
        // create a temporary byte repr of the header
        // and re-create all hashes
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        // make sure to not hash any previous signatures in the header
        self.metadata.header.write(&mut header_bytes)?;

        let content_len = stream_len(&mut self.content)?;
        let header_and_content_len = header_bytes.len() as u64 + content_len;

        let Digests {
            header_digest_sha256,
            header_digest_sha1,
            header_and_content_digest,
        } = Self::create_sig_header_digests(header_bytes.as_slice(), &mut self.content)?;

        let rsa_signature_spanning_header_only = signer.sign(header_bytes.as_slice(), t)?;
        let mut header_and_content_cursor = io::Cursor::new(header_bytes).chain(&mut self.content);

        let rsa_signature_spanning_header_and_archive =
            signer.sign(&mut header_and_content_cursor, t)?;

        // NOTE: size stands for the combined size of header and payload.
        self.metadata.signature = Header::<IndexSignatureTag>::new_signature_header(
            header_and_content_len,
            &header_and_content_digest,
            &header_digest_sha1,
            &header_digest_sha256,
            rsa_signature_spanning_header_only.as_slice(),
            rsa_signature_spanning_header_and_archive.as_slice(),
        );

        Ok(())
    }

    // @todo: a function that returns the key ID of the key used to sign this package would be useful
    // @todo: verify_signature() and verify_digests() don't provide any feedback on whether a signature/digest
    //        was present and verified or whether it was not present at all.

    /// Verify the signature as present within the RPM package.
    #[cfg(feature = "signature-meta")]
    pub fn verify_signature<V>(&mut self, verifier: V) -> Result<(), RPMError>
    where
        V: signature::Verifying<signature::algorithm::RSA, Signature = Vec<u8>>,
    {
        let mut header_bytes = Vec::<u8>::with_capacity(1024);
        self.metadata.header.write(&mut header_bytes)?;

        let signature_header_only = self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RSA)?;

        signature::echo_signature("signature_header(header only)", signature_header_only);
        verifier.verify(header_bytes.as_slice(), signature_header_only)?;

        self.verify_digests()?;

        let signature_header_and_content = self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_PGP)?;

        signature::echo_signature(
            "signature_header(header and content)",
            signature_header_and_content,
        );
        let header_and_content_cursor = io::Cursor::new(header_bytes).chain(&mut self.content);
        verifier.verify(header_and_content_cursor, signature_header_and_content)?;
        self.content.rewind()?;

        Ok(())
    }

    /// Verify any digests which may be present in the RPM headers
    pub fn verify_digests(&mut self) -> Result<(), RPMError> {
        let mut header = Vec::<u8>::with_capacity(1024);
        // make sure to not hash any previous signatures in the header
        self.metadata.header.write(&mut header)?;

        let pkg_actual_digests =
            Self::create_sig_header_digests(header.as_slice(), &mut self.content)?;

        let md5 = self
            .metadata
            .signature
            .get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_MD5);
        let sha1 = self
            .metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA1);
        let sha256 = self
            .metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256);

        if let Ok(md5) = md5 {
            if md5 != pkg_actual_digests.header_and_content_digest {
                return Err(RPMError::DigestMismatchError);
            }
        }

        if let Ok(sha1) = sha1 {
            if sha1 != pkg_actual_digests.header_digest_sha1 {
                return Err(RPMError::DigestMismatchError);
            }
        }

        if let Ok(sha256) = sha256 {
            if sha256 != pkg_actual_digests.header_digest_sha256 {
                return Err(RPMError::DigestMismatchError);
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
                a => return Err(RPMError::UnsupportedDigestAlgorithm(a)),
                // At the present moment even rpmbuild only supports sha256
            };
            let payload_digest = {
                io::copy(&mut self.content, &mut hasher)?;
                self.content.rewind()?;
                hex::encode(hasher.finalize())
            };
            if payload_digest != payload_digest_val[0] {
                return Err(RPMError::DigestMismatchError);
            }
        }

        Ok(())
    }
}

impl<R> fmt::Debug for RPMPackage<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RPMPackage")
            .field("metadata", &self.metadata)
            .finish()
    }
}

#[derive(PartialEq, Debug)]
pub struct RPMPackageMetadata {
    pub lead: Lead,
    pub signature: Header<IndexSignatureTag>,
    pub header: Header<IndexTag>,
}

impl RPMPackageMetadata {
    /// Open and parse RPMPackageMetadata from the file at the provided path
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RPMError> {
        let rpm_file = fs::File::open(path.as_ref())?;
        let mut buf_reader = io::BufReader::new(rpm_file);
        Self::parse(&mut buf_reader)
    }

    /// Parse RPMPackageMetadata from the provided reader
    pub fn parse(mut input: impl io::BufRead) -> Result<Self, RPMError> {
        let mut lead_buffer = [0; LEAD_SIZE as usize];
        input.read_exact(&mut lead_buffer)?;
        let lead = Lead::parse(&lead_buffer)?;
        let signature_header = Header::parse_signature(&mut input)?;
        let header = Header::parse(&mut input)?;

        Ok(RPMPackageMetadata {
            lead,
            signature: signature_header,
            header,
        })
    }

    pub(crate) fn write(&self, out: &mut impl io::Write) -> Result<(), RPMError> {
        self.lead.write(out)?;
        self.signature.write_signature(out)?;
        self.header.write(out)?;
        Ok(())
    }

    /// Whether this package is a source package, or not
    #[inline]
    pub fn is_source_package(&self) -> bool {
        self.header
            .find_entry_or_err(IndexTag::RPMTAG_SOURCEPACKAGE)
            .is_ok()
    }

    /// Get the package name
    #[inline]
    pub fn get_name(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_NAME)
    }

    /// Get the package epoch
    #[inline]
    pub fn get_epoch(&self) -> Result<u32, RPMError> {
        self.header.get_entry_data_as_u32(IndexTag::RPMTAG_EPOCH)
    }

    /// Get the package version (the upstream version string)
    #[inline]
    pub fn get_version(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VERSION)
    }

    /// Get the package release
    #[inline]
    pub fn get_release(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_RELEASE)
    }

    /// Get the package architecture
    #[inline]
    pub fn get_arch(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_ARCH)
    }

    /// Get the package vendor - the organization that produced the package
    #[inline]
    pub fn get_vendor(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_VENDOR)
    }

    /// Get the package URL. Most often this is the upstream project website for the software
    /// being packaged.
    #[inline]
    pub fn get_url(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_URL)
    }

    /// Get the package version control URL (of the upstream project)
    #[inline]
    pub fn get_vcs(&self) -> Result<&str, RPMError> {
        self.header.get_entry_data_as_string(IndexTag::RPMTAG_VCS)
    }

    /// Get the package license
    #[inline]
    pub fn get_license(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_LICENSE)
    }

    /// Get the package summary (very brief description of the packaged software)
    #[inline]
    pub fn get_summary(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_SUMMARY)
    }

    /// Get the package description (a full description of the packaged software)
    #[inline]
    pub fn get_description(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_DESCRIPTION)
    }

    /// Get the package group (this is deprecated in most packaging guidelines)
    #[inline]
    pub fn get_group(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_i18n_string(IndexTag::RPMTAG_GROUP)
    }

    #[inline]
    pub fn get_packager(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PACKAGER)
    }

    /// Get the timestamp when this package was built. This is commonly not present.
    #[inline]
    pub fn get_build_time(&self) -> Result<u64, RPMError> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_BUILDTIME)
            .map(|x| x as u64)
    }

    /// Get the build host on which this package was built. This is commonly not present.
    #[inline]
    pub fn get_build_host(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_BUILDHOST)
    }

    /// The cookie is a value that can be used for tracking packages built together, e.g.
    /// packages built in one build operation (from a single source RPM, for example).
    #[inline]
    pub fn get_cookie(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_COOKIE)
    }

    /// Get the filename of the source RPM package used to build this package
    #[inline]
    pub fn get_source_rpm(&self) -> Result<&str, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_SOURCERPM)
    }

    fn get_dependencies(
        &self,
        names_tag: IndexTag,
        flags_tag: IndexTag,
        versions_tag: IndexTag,
    ) -> Result<Vec<Dependency>, RPMError> {
        let names = self.header.get_entry_data_as_string_array(names_tag);
        let flags = self.header.get_entry_data_as_u32_array(flags_tag);
        let versions = self.header.get_entry_data_as_string_array(versions_tag);

        match (names, flags, versions) {
            // Return an empty list if the tags are not present
            (
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
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

    /// Get a list of dependencies which this package "provides"
    ///
    /// These are aliases or capabilities provided by this package which other packages can reference.
    pub fn get_provides(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_requires(&self) -> Result<Vec<Dependency>, RPMError> {
        self.get_dependencies(
            IndexTag::RPMTAG_REQUIRENAME,
            IndexTag::RPMTAG_REQUIREFLAGS,
            IndexTag::RPMTAG_REQUIREVERSION,
        )
    }

    /// Get a list of dependencies which this package "conflicts" with
    ///
    /// These are packages which must not be present in order for the package to be installed.
    pub fn get_conflicts(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_obsoletes(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_recommends(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_suggests(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_enhances(&self) -> Result<Vec<Dependency>, RPMError> {
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
    pub fn get_supplements(&self) -> Result<Vec<Dependency>, RPMError> {
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
    /// # use rpm::RPMPackage;
    /// # let package = RPMPackage::open("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm").unwrap();
    /// let offsets = package.metadata.get_package_segment_offsets();
    /// let lead = offsets.lead..offsets.signature_header;
    /// let sig_header = offsets.signature_header..offsets.header;
    /// let header = offsets.header..offsets.payload;
    /// let payload = offsets.payload..;
    /// ```
    pub fn get_package_segment_offsets(&self) -> RPMPackageSegmentOffsets {
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
        let padding = (8 - (sig_header_size % 8)) % 8; // todo: share padding code

        let header_start = sig_header_start + sig_header_size + padding;
        let header_size = self.header.size();

        let payload_start = header_start + header_size;

        RPMPackageSegmentOffsets {
            lead: 0,
            signature_header: sig_header_start as u64,
            header: header_start as u64,
            payload: payload_start as u64,
        }
    }

    /// Get the sum of the sizes of all files present in the package payload
    pub fn get_installed_size(&self) -> Result<u64, RPMError> {
        self.header
            .get_entry_data_as_u64(IndexTag::RPMTAG_LONGSIZE)
            .or_else(|_e| {
                self.header
                    .get_entry_data_as_u32(IndexTag::RPMTAG_SIZE)
                    .map(|v| v as u64)
            })
    }

    #[inline]
    pub fn get_payload_compressor(&self) -> Result<CompressionType, RPMError> {
        self.header
            .get_entry_data_as_string(IndexTag::RPMTAG_PAYLOADCOMPRESSOR)
            .map_or_else(
                |e| {
                    if matches!(e, RPMError::TagNotFound(_)) {
                        Ok(CompressionType::None)
                    } else {
                        Err(e)
                    }
                },
                CompressionType::from_str,
            )
    }

    #[inline]
    pub fn get_file_checksums(&self) -> Result<&[String], RPMError> {
        self.header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_FILEDIGESTS)
    }

    #[inline]
    pub fn get_file_ima_signatures(&self) -> Result<&[String], RPMError> {
        self.signature
            .get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_FILESIGNATURES)
    }

    /// Extract a the set of contained file names.
    pub fn get_file_paths(&self) -> Result<Vec<PathBuf>, RPMError> {
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
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
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
                                acc.push(PathBuf::from(dir).join(basename));
                                Ok(acc)
                            } else {
                                Err(RPMError::InvalidTagIndex {
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
    pub fn get_file_digest_algorithm(&self) -> Result<DigestAlgorithm, RPMError> {
        self.header
            .get_entry_data_as_u32(IndexTag::RPMTAG_FILEDIGESTALGO)
            .and_then(|x| {
                DigestAlgorithm::from_u32(x).ok_or_else(|| RPMError::InvalidTagValueEnumVariant {
                    tag: IndexTag::RPMTAG_FILEDIGESTALGO.to_string(),
                    variant: x,
                })
            })
    }

    /// Extract a the set of contained file names including the additional metadata.
    pub fn get_file_entries(&self) -> Result<Vec<FileEntry>, RPMError> {
        // rpm does not encode it, if it is the default md5
        let algorithm = self
            .get_file_digest_algorithm()
            .unwrap_or(DigestAlgorithm::Md5);
        //
        let modes = self
            .header
            .get_entry_data_as_u16_array(IndexTag::RPMTAG_FILEMODES);
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
        // @todo
        // let caps = self.get_entry_i32_array_data(IndexTag::RPMTAG_FILECAPS)?;

        match (modes, users, groups, digests, mtimes, sizes, flags) {
            (Ok(modes), Ok(users), Ok(groups), Ok(digests), Ok(mtimes), Ok(sizes), Ok(flags)) => {
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
                ))
                .try_fold::<Vec<FileEntry>, _, Result<_, RPMError>>(
                    Vec::with_capacity(n),
                    |mut acc, (path, user, group, mode, digest, mtime, size, flags)| {
                        let digest = if digest.is_empty() {
                            None
                        } else {
                            Some(FileDigest::load_from_str(algorithm, digest)?)
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
                        });
                        Ok(acc)
                    },
                )?;
                Ok(v)
            }
            (
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
            ) => Ok(vec![]),
            (modes, users, groups, digests, mtimes, sizes, flags) => {
                modes?;
                users?;
                groups?;
                digests?;
                mtimes?;
                sizes?;
                flags?;
                unreachable!()
            }
        }
    }

    /// Return a list of changelog entries
    pub fn get_changelog_entries(&self) -> Result<Vec<ChangelogEntry>, RPMError> {
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
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
                Err(RPMError::TagNotFound(_)),
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
