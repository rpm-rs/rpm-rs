//! signature index construction as builder pattern

use super::*;

use super::IndexEntry;
use crate::constants::*;
use std::default::Default;

/// A marker trait for builder stages
pub trait ConstructionStage {}

/// Initial empty builder.
pub struct Empty;
/// Builder beyond the empty stage, already containing a digest.
///
/// Implies that headers and content are complete.
pub struct WithDigest;

/// Builder already has a hash and is ready for completion.
pub struct WithSignature;

impl ConstructionStage for Empty {}

impl ConstructionStage for WithDigest {}

impl ConstructionStage for WithSignature {}

/// base signature header builder
///
/// T describes the stage and can be one of `Empty`, `WithDigest`, `WithSignature`
pub struct SignatureHeaderBuilder<T>
where
    T: ConstructionStage,
{
    entries: Vec<IndexEntry<IndexSignatureTag>>,
    phantom: std::marker::PhantomData<T>,
}

impl SignatureHeaderBuilder<Empty> {
    pub fn new() -> Self {
        Self {
            entries: Vec::with_capacity(10),
            phantom: Default::default(),
        }
    }
}

impl Default for SignatureHeaderBuilder<Empty> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> SignatureHeaderBuilder<T>
where
    T: ConstructionStage,
{
    /// Construct the complete signature header.
    pub fn build(mut self, headers_plus_payload_size: u64) -> Header<IndexSignatureTag> {
        let entry = match headers_plus_payload_size.try_into() {
            Ok(size) => IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_SIZE,
                0i32,
                IndexData::Int32(vec![size]),
            ),
            Err(_) => IndexEntry::new(
                IndexSignatureTag::RPMSIGTAG_LONGSIZE,
                0i32,
                IndexData::Int64(vec![headers_plus_payload_size]),
            ),
        };
        self.entries.insert(0, entry);

        Header::<IndexSignatureTag>::from_entries(
            self.entries,
            IndexSignatureTag::HEADER_SIGNATURES,
        )
    }
}

impl SignatureHeaderBuilder<Empty> {
    /// add a digest over the header and a signature across header and source excluding the static lead
    pub fn add_digest(
        mut self,
        digest_header_sha1: &str,
        digest_header_sha256: &str,
        digest_header_and_archive: &[u8],
    ) -> SignatureHeaderBuilder<WithDigest> {
        let offset = 0i32; // filled externally later on
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_MD5,
            offset,
            IndexData::Bin(digest_header_and_archive.to_vec()),
        ));
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_SHA1,
            offset,
            IndexData::StringTag(digest_header_sha1.to_string()),
        ));
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_SHA256,
            offset,
            IndexData::StringTag(digest_header_sha256.to_string()),
        ));
        SignatureHeaderBuilder::<WithDigest> {
            entries: self.entries,
            phantom: Default::default(),
        }
    }
}

impl SignatureHeaderBuilder<WithDigest> {
    /// add a signature over the header and a signature across header and source excluding the static lead
    pub fn add_signature(
        mut self,
        rsa_sig_header_only: &[u8],
        rsa_sig_header_and_archive: &[u8],
    ) -> SignatureHeaderBuilder<WithSignature> {
        let offset = 0i32; // filled externally later on
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_RSA,
            offset,
            IndexData::Bin(rsa_sig_header_only.to_vec()),
        ));
        self.entries.push(IndexEntry::new(
            IndexSignatureTag::RPMSIGTAG_PGP,
            offset,
            IndexData::Bin(rsa_sig_header_and_archive.to_vec()),
        ));
        SignatureHeaderBuilder::<WithSignature> {
            entries: self.entries,
            phantom: Default::default(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn signature_builder_w_digest_and_signature() {
        let builder = SignatureHeaderBuilder::<Empty>::new();

        let rsa_sig_header_only = [0u8; 32];
        let rsa_sig_header_and_archive = [0u8; 32];

        let digest_header_sha1 = hex::encode([0u8; 64]);
        let digest_header_sha256: String = hex::encode([0u8; 64]);

        let digest_header_and_archive = [0u8; 64];

        let header = builder
            .add_digest(
                digest_header_sha1.as_str(),
                digest_header_sha256.as_str(),
                &digest_header_and_archive[..],
            )
            .add_signature(&rsa_sig_header_only[..], &rsa_sig_header_and_archive[..])
            .build(32);

        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_RSA)
            .is_ok());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_PGP)
            .is_ok());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_MD5)
            .is_ok());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_SHA1)
            .is_ok());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_SHA256)
            .is_ok());
    }

    #[test]
    fn signature_builder_digest_only() {
        let builder = SignatureHeaderBuilder::<Empty>::new();

        let digest_header_sha1 = hex::encode([0u8; 64]);
        let digest_header_sha256: String = hex::encode([0u8; 64]);

        let digest_header_and_archive = [0u8; 64];

        let header = builder
            .add_digest(
                digest_header_sha1.as_str(),
                digest_header_sha256.as_str(),
                &digest_header_and_archive[..],
            )
            .build(32);

        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_RSA)
            .is_err());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_PGP)
            .is_err());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_MD5)
            .is_ok());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_SHA1)
            .is_ok());
        assert!(header
            .find_entry_or_err(IndexSignatureTag::RPMSIGTAG_SHA256)
            .is_ok());
    }
}
