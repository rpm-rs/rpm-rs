//! signature index construction as builder pattern

use super::*;

#[cfg(feature = "signature-meta")]
use std::collections::HashSet;
use std::default::Default;

use crate::RpmFormat;
use crate::constants::*;
#[cfg(feature = "signature-meta")]
use crate::signature::{SignatureAlgorithm, parse_signature_info};

use base64::prelude::*;
use digest::Digest;

/// base signature header builder
pub struct SignatureHeaderBuilder {
    format: Option<RpmFormat>,
    openpgp_signatures: Vec<Vec<u8>>,
    header_sha1: Option<String>,
    header_sha256: Option<String>,
    header_sha3_256: Option<String>,
    content_length: Option<u64>,
    file_signatures: Option<Vec<String>>,
    file_signature_length: Option<u32>,
    verity_signatures: Option<Vec<String>>,
    verity_signature_algo: Option<u32>,
    reserved_space: Option<u32>,
}

impl Default for SignatureHeaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn decode_sig(signature: &str) -> Result<Vec<u8>, crate::Error> {
    BASE64_STANDARD
        .decode(signature)
        .map_err(|e| crate::Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

#[cfg(feature = "signature-meta")]
pub(crate) fn encode_sig(signature: &[u8]) -> String {
    BASE64_STANDARD.encode(signature)
}

impl SignatureHeaderBuilder {
    /// The default amount of reserved space (in bytes) for later adding signatures.
    /// Requires the format to be set; otherwise the reserved space is not written.
    ///
    /// RPM uses a default of %__gpg_reserved_space (4096) + 32 bytes
    pub const DEFAULT_RESERVED_SPACE: u32 = 4128;

    pub fn new() -> Self {
        Self {
            format: None,
            openpgp_signatures: Vec::new(),
            header_sha1: None,
            header_sha256: None,
            header_sha3_256: None,
            content_length: None,
            file_signatures: None,
            file_signature_length: None,
            verity_signatures: None,
            verity_signature_algo: None,
            reserved_space: Some(Self::DEFAULT_RESERVED_SPACE),
        }
    }

    /// Set the RPM format version, which determines the reserved space tag used.
    pub fn format(mut self, format: RpmFormat) -> Self {
        self.format = Some(format);
        self
    }

    /// Create a builder that preserves existing data from a signature header.
    ///
    /// This includes OpenPGP signatures, header digests, content length,
    /// file signatures (IMA), and verity signatures. It does NOT include legacy
    /// header + payload signatures (v3 signatures).
    pub fn from_existing(header: &Header<IndexSignatureTag>) -> Result<Self, crate::Error> {
        let mut builder = Self::new();
        if let Ok(existing_sigs) =
            header.get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_OPENPGP)
        {
            for base64_sig in existing_sigs {
                builder.openpgp_signatures.push(decode_sig(base64_sig)?);
            }
        } else {
            // Fall back to legacy binary signature tags
            if let Ok(sig) = header.get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RSA) {
                builder.openpgp_signatures.push(sig.to_vec());
            } else if let Ok(sig) =
                header.get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_DSA)
            {
                builder.openpgp_signatures.push(sig.to_vec());
            }
        }
        if let Ok(digest) = header.get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA1) {
            builder.header_sha1 = Some(digest.to_owned());
        }
        if let Ok(digest) = header.get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256) {
            builder.header_sha256 = Some(digest.to_owned());
        }
        if let Ok(digest) = header.get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256) {
            builder.header_sha3_256 = Some(digest.to_owned());
        }
        if let Ok(size) = header.get_entry_data_as_u32(IndexSignatureTag::RPMSIGTAG_SIZE) {
            builder.content_length = Some(size as u64);
        } else if let Ok(size) = header.get_entry_data_as_u64(IndexSignatureTag::RPMSIGTAG_LONGSIZE)
        {
            builder.content_length = Some(size);
        }
        if let Ok(sigs) =
            header.get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_FILESIGNATURES)
        {
            builder.file_signatures = Some(sigs.into_iter().map(String::from).collect());
        }
        if let Ok(len) =
            header.get_entry_data_as_u32(IndexSignatureTag::RPMSIGTAG_FILESIGNATURE_LENGTH)
        {
            builder.file_signature_length = Some(len);
        }
        if let Ok(sigs) =
            header.get_entry_data_as_string_array(IndexSignatureTag::RPMSIGTAG_VERITYSIGNATURES)
        {
            builder.verity_signatures = Some(sigs.into_iter().map(String::from).collect());
        }
        if let Ok(algo) =
            header.get_entry_data_as_u32(IndexSignatureTag::RPMSIGTAG_VERITYSIGNATUREALGO)
        {
            builder.verity_signature_algo = Some(algo);
        }
        // Detect format and preserve reserved space from existing header.
        // v6 uses RPMSIGTAG_RESERVED (999), v4 uses RPMSIGTAG_RESERVEDSPACE (1008).
        // If neither tag is present, reserved_space must be None — not the
        // default from new() — so we don't fabricate space that wasn't there.
        if let Ok(data) = header.get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RESERVED) {
            builder.format = Some(RpmFormat::V6);
            builder.reserved_space = Some(data.len() as u32);
        } else if let Ok(data) =
            header.get_entry_data_as_binary(IndexSignatureTag::RPMSIGTAG_RESERVEDSPACE)
        {
            builder.format = Some(RpmFormat::V4);
            builder.reserved_space = Some(data.len() as u32);
        } else {
            builder.reserved_space = None;
        }
        Ok(builder)
    }

    /// Construct the complete signature header.
    pub fn build(self) -> Result<Header<IndexSignatureTag>, crate::Error> {
        let mut entries = Vec::new();

        #[cfg(feature = "signature-meta")]
        if !self.openpgp_signatures.is_empty() {
            let mut openpgp_signatures = Vec::new();
            let mut legacy_sig = None;
            let mut seen_fingerprints = HashSet::new();

            // Iterate in reverse so that newer signatures (appended last) take
            // precedence when deduplicating by issuer fingerprint, and the
            // legacy signature tag is set from the newest matching signature.
            for sig_bytes in self.openpgp_signatures.iter().rev() {
                let info = parse_signature_info(sig_bytes)?;

                // Deduplicate: keep only the newest signature per key
                if let Some(fp) = info.fingerprint()
                    && !seen_fingerprints.insert(fp.to_owned())
                {
                    continue;
                }

                if legacy_sig.is_none() {
                    let legacy_sig_tag = match info.algorithm() {
                        Some(SignatureAlgorithm::RSA) => Some(IndexSignatureTag::RPMSIGTAG_RSA),
                        Some(
                            SignatureAlgorithm::ECDSA
                            | SignatureAlgorithm::EdDSALegacy
                            | SignatureAlgorithm::Ed25519
                            | SignatureAlgorithm::Ed448,
                        ) => Some(IndexSignatureTag::RPMSIGTAG_DSA),
                        _ => None,
                    };
                    if let Some(legacy_sig_tag) = legacy_sig_tag {
                        legacy_sig = Some((legacy_sig_tag, sig_bytes));
                    }
                }

                openpgp_signatures.push(encode_sig(sig_bytes));
            }
            // Restore original order (oldest first)
            openpgp_signatures.reverse();

            // OpenPGP signature tag is added unconditionally because it makes the code simpler
            // and causes no harm.
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_OPENPGP,
                IndexData::StringArray(openpgp_signatures),
            ));

            // the legacy signature tags are produced from the last valid signature in the list
            if self.format != Some(RpmFormat::V6)
                && let Some((tag, sig_bytes)) = legacy_sig
            {
                entries.push(IndexEntry::new(tag, IndexData::Bin(sig_bytes.clone())));
            }
        }

        // SHA-1 is only expected for v4 packages
        if self.format != Some(RpmFormat::V6)
            && let Some(digest) = self.header_sha1
        {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SHA1,
                IndexData::StringTag(digest),
            ));
        }

        if let Some(digest) = self.header_sha256 {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SHA256,
                IndexData::StringTag(digest),
            ));
        }

        // SHA3-256 is only expected for v6 packages
        if self.format != Some(RpmFormat::V4)
            && let Some(digest) = self.header_sha3_256
        {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SHA3_256,
                IndexData::StringTag(digest),
            ));
        }

        if let Some(sigs) = self.verity_signatures {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_VERITYSIGNATURES,
                IndexData::StringArray(sigs),
            ));
        }

        if let Some(algo) = self.verity_signature_algo {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_VERITYSIGNATUREALGO,
                IndexData::Int32(vec![algo]),
            ));
        }

        if let Some(sigs) = self.file_signatures {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_FILESIGNATURES,
                IndexData::StringArray(sigs),
            ));
        }

        if let Some(len) = self.file_signature_length {
            entries.push(IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_FILESIGNATURE_LENGTH,
                IndexData::Int32(vec![len]),
            ));
        }

        // Size tags are only expected for v4 packages
        if self.format != Some(RpmFormat::V6)
            && let Some(len) = self.content_length
        {
            if let Ok(len) = u32::try_from(len) {
                entries.push(IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_SIZE,
                    IndexData::Int32(vec![len]),
                ));
            } else {
                entries.push(IndexEntry::new(
                    IndexSignatureTag::RPMSIGTAG_LONGSIZE,
                    IndexData::Int64(vec![len]),
                ));
            }
        }

        // Write reserved space for later adding signatures without rewriting the package.
        // v4 uses RPMSIGTAG_RESERVEDSPACE (1008), v6 uses RPMSIGTAG_RESERVED (999).
        if let (Some(size), Some(fmt)) = (self.reserved_space, self.format) {
            let tag = match fmt {
                RpmFormat::V4 => IndexSignatureTag::RPMSIGTAG_RESERVEDSPACE,
                RpmFormat::V6 => IndexSignatureTag::RPMSIGTAG_RESERVED,
            };
            entries.push(IndexEntry::new(
                tag,
                IndexData::Bin(vec![0u8; size as usize]),
            ));
        }

        let header = Header::<IndexSignatureTag>::from_entries(
            entries,
            IndexSignatureTag::HEADER_SIGNATURES,
        );

        Ok(header)
    }

    /// Calculate header digests from the given header bytes.
    ///
    /// Always calculates SHA-256. SHA3-256 is only calculated for v6 packages.
    /// SHA-1 is only recalculated for v4 packages if it was already present
    /// (e.g. preserved via `from_existing`).
    pub fn calculate_digests(mut self, header_bytes: &[u8]) -> Self {
        self.header_sha256 = Some(hex::encode(sha2::Sha256::digest(header_bytes)));
        // SHA3-256 is only expected for v6 packages
        if self.format != Some(RpmFormat::V4) {
            self.header_sha3_256 = Some(hex::encode(sha3::Sha3_256::digest(header_bytes)));
        }
        // SHA-1 is only expected for v4 packages
        if self.format != Some(RpmFormat::V6) {
            self.header_sha1 = Some(hex::encode(sha1::Sha1::digest(header_bytes)));
        }
        self
    }

    /// Set the content length (compressed payload + header size).
    pub fn set_content_length(mut self, length: u64) -> Self {
        self.content_length = Some(length);
        self
    }

    // Add an openpgp signature of the header bytes
    pub fn add_openpgp_signature(mut self, signature: Vec<u8>) -> Self {
        self.openpgp_signatures.push(signature);
        self
    }

    // Clear all header signatures
    pub fn clear_signatures(mut self) -> Self {
        self.openpgp_signatures.clear();
        self
    }

    /// Whether this builder includes a reserved space tag.
    pub fn has_reserved_space(&self) -> bool {
        self.reserved_space.is_some()
    }

    /// Set the amount of reserved space (in bytes) for later adding signatures
    /// without rewriting the entire package.
    pub fn reserved_space(mut self, size: Option<u32>) -> Self {
        self.reserved_space = size;
        self
    }
}
