/// The public key algorithm used in an OpenPGP signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    RSA,
    DSA,
    ECDSA,
    EdDSALegacy,
    Ed25519,
    Ed448,
    MlDsa65Ed25519,
    MlDsa87Ed448,
    /// An algorithm not recognized for use signing RPMs.
    Unsupported(u8),
}

/// The hash algorithm used in an OpenPGP signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureHashAlgorithm {
    SHA1,
    SHA256,
    SHA384,
    SHA512,
    SHA224,
    SHA3_256,
    SHA3_512,
    /// A hash algorithm not recognized by this library.
    Unsupported(u8),
}

/// The version of an OpenPGP signature packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureVersion {
    V4,
    V6,
    /// A version not recognized by this library.
    Unsupported(u8),
}

impl From<u8> for SignatureVersion {
    fn from(v: u8) -> Self {
        match v {
            4 => Self::V4,
            6 => Self::V6,
            other => Self::Unsupported(other),
        }
    }
}

/// Parsed information about a single OpenPGP signature embedded in an RPM package.
///
/// This provides access to the issuer fingerprint, key ID, algorithm, and creation time
/// without exposing the underlying OpenPGP backend's types.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    fingerprint: Option<String>,
    key_id: Option<String>,
    version: SignatureVersion,
    algorithm: Option<SignatureAlgorithm>,
    hash_algorithm: Option<SignatureHashAlgorithm>,
    created: Option<u32>,
}

impl SignatureInfo {
    pub(crate) fn new(
        fingerprint: Option<String>,
        key_id: Option<String>,
        version: SignatureVersion,
        algorithm: Option<SignatureAlgorithm>,
        hash_algorithm: Option<SignatureHashAlgorithm>,
        created: Option<u32>,
    ) -> Self {
        Self {
            fingerprint,
            key_id,
            version,
            algorithm,
            hash_algorithm,
            created,
        }
    }

    /// The issuer fingerprint as a lowercase hex string, if present.
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    /// The issuer key ID as a lowercase hex string, if present.
    pub fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    /// The OpenPGP signature packet version (e.g. 4 or 6).
    pub fn version(&self) -> SignatureVersion {
        self.version
    }

    /// The public key algorithm used to create the signature, if known.
    pub fn algorithm(&self) -> Option<SignatureAlgorithm> {
        self.algorithm
    }

    /// The hash algorithm used in the signature, if known.
    pub fn hash_algorithm(&self) -> Option<SignatureHashAlgorithm> {
        self.hash_algorithm
    }

    /// The signature creation time as seconds since the Unix epoch, if present.
    pub fn created(&self) -> Option<u32> {
        self.created
    }
}
