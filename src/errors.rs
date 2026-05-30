use std::{io, str::Utf8Error};

use thiserror::Error;

use crate::{DigestAlgorithm, TimestampError, constants::format_tag_id};

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error("{0}")]
    Nom(String),
    #[error(
        "invalid magic expected: {expected} but got: {actual} - whole input was {complete_input:?}"
    )]
    InvalidMagic {
        expected: u8,
        actual: u8,
        complete_input: Vec<u8>,
    },
    #[error("unsupported Version {0} - only header version 1 is supported")]
    UnsupportedHeaderVersion(u8),
    #[error("invalid tag data type in store {store_type}: expected 0 - 9 but got {raw_data_type}")]
    InvalidTagDataType {
        raw_data_type: u32,
        store_type: &'static str,
    },
    #[error("unterminated string in header data store")]
    UnterminatedHeaderString,
    #[error("invalid UTF-8 in tag {tag} (encoding is guaranteed as utf-8)")]
    InvalidUtf8 { tag: String },
    #[error("unable to find tag {}", format_tag_id(*.0))]
    TagNotFound(u32),
    #[error("unable to find scriptlet")]
    ScriptletNotFound,
    #[error("tag {tag} has data type {actual_data_type}, not {expected_data_type}")]
    UnexpectedTagDataType {
        expected_data_type: &'static str,
        actual_data_type: String,
        tag: String,
    },
    #[error("invalid tag array index {tag} with {index} while bounded at {bound}")]
    InvalidTagIndex { tag: String, index: u32, bound: u32 },

    #[error("related tag arrays have inconsistent lengths")]
    InconsistentTagArrayLengths,

    #[error("invalid tag value enum variant for {tag} with {variant}")]
    InvalidTagValueEnumVariant { tag: String, variant: u32 },

    #[error("invalid size of reserved area - expected length of {expected} but got {actual}")]
    InvalidReservedSpaceSize { expected: u16, actual: usize },

    #[error("invalid destination path {path} - {desc}")]
    InvalidDestinationPath { path: String, desc: &'static str },

    #[error("invalid capabilities specified {caps}")]
    InvalidCapabilities { caps: String },

    #[error("signature packet not found in what is supposed to be a signature")]
    NoSignatureFound,

    #[error("signature packet found, but no version was specified")]
    UnknownVersionSignature,

    #[cfg(feature = "signature-pgp")]
    #[error("error creating signature: {0}")]
    SignError(#[source] pgp::errors::Error),

    #[error("error parsing keys, failed to parse bytes as utf8 for ascii armored parsing")]
    KeyLoadUtf8Error(
        #[from]
        #[source]
        Utf8Error,
    ),

    #[cfg(feature = "signature-pgp")]
    #[error("errors parsing keys, failed to parse bytes as ascii armored key")]
    KeyLoadSecretKeyError(
        #[from]
        #[source]
        pgp::errors::Error,
    ),

    #[cfg(feature = "signature-pgp")]
    #[error("key binding signature verification failed: {0}")]
    KeyBindingVerificationError(pgp::errors::Error),

    #[cfg(feature = "signature-pgp")]
    #[error("error verifying signature with key {key_ref}: {source}")]
    VerificationError {
        #[source]
        source: pgp::errors::Error,
        key_ref: String,
    },

    #[error("{digest} digest mismatch: expected {expected}, got {actual}")]
    DigestMismatchError {
        digest: &'static str,
        expected: String,
        actual: String,
    },

    #[error("no header digests found in package")]
    NoHeaderDigestError,

    #[error("no payload digests found in package")]
    NoPayloadDigestError,

    #[error("unable to find key with key-ref: {key_ref}")]
    KeyNotFoundError { key_ref: String },

    #[error("key {key_ref} lacks signing capability")]
    KeyLacksSigningCapability { key_ref: String },

    #[error("unknown compressor type {0} - supported types: gzip, zstd, xz, bzip2 and none")]
    UnknownCompressorType(String),

    #[error("unsupported compressor type {0} - try enabling the feature flag for it")]
    UnsupportedCompressorType(String),

    #[error("unsupported digest algorithm {0:?}")]
    UnsupportedDigestAlgorithm(DigestAlgorithm),

    #[error("invalid digest length for {algo:?}: expected {expected}, got {actual}")]
    InvalidDigestLength {
        algo: DigestAlgorithm,
        expected: usize,
        actual: usize,
    },

    #[cfg(feature = "signature-pgp")]
    #[error("unsupported PGP key type {0:?}")]
    UnsupportedPGPKeyType(pgp::crypto::public_key::PublicKeyAlgorithm),

    #[cfg(feature = "signature-pgp")]
    #[error("signature contains {0} issuer packets - should have exactly one")]
    UnexpectedIssuerCount(u32),

    #[error("invalid file mode {raw_mode} - {reason}")]
    InvalidFileMode { raw_mode: i32, reason: &'static str },

    #[error("invalid file options for {method}: {reason}")]
    InvalidFileOptions {
        method: &'static str,
        reason: &'static str,
    },

    #[error("timestamp conversion error: {0:?}")]
    TimestampConv(TimestampError),

    #[error("symbolic links are not supported on this platform")]
    UnsupportedSymlink,

    #[error("invalid {field}: control characters are not allowed, got {value:?}")]
    InvalidControlChar { field: &'static str, value: String },

    #[error("invalid {field} {value:?}: {reason}")]
    InvalidCharacters {
        field: &'static str,
        value: String,
        reason: &'static str,
    },

    #[error(
        "insufficient reserved space for in-place resigning: need {needed} bytes but only {available} available"
    )]
    InsufficientReservedSpace { needed: u32, available: u32 },

    #[error("{0}")]
    InvalidFileCaps(String),

    #[error(
        "PackageBuilder has already been consumed by a previous call to build() or build_and_sign()"
    )]
    BuilderReuse,
}

impl From<nom::Err<(&[u8], nom::error::ErrorKind)>> for Error {
    fn from(error: nom::Err<(&[u8], nom::error::ErrorKind)>) -> Self {
        match error {
            nom::Err::Error((_, kind)) | nom::Err::Failure((_, kind)) => {
                Error::Nom(kind.description().to_string())
            }
            nom::Err::Incomplete(_) => Error::Nom("unhandled incomplete".to_string()),
        }
    }
}

impl From<TimestampError> for Error {
    fn from(error: TimestampError) -> Self {
        Error::TimestampConv(error)
    }
}

// Assert at compile-time that Error implements Send and Sync.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
};
