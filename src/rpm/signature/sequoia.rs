//! OpenPGP signing and verification backed by Sequoia.
//!
//! This backend uses Sequoia's pure-Rust crypto implementation. It is selected
//! instead of, rather than alongside, the `signature-pgp` backend.

use std::fmt;
use std::io;
use std::time::{Duration, UNIX_EPOCH};

use openpgp::cert::CertParser;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::packet::{Packet, Signature};
use openpgp::parse::{Parse, stream::*};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Message, Signer as StreamSigner};
use openpgp::types::{HashAlgorithm, PublicKeyAlgorithm, SignatureType};
use openpgp::{Cert, Fingerprint, KeyHandle};
use sequoia_openpgp as openpgp;

use super::traits;
pub use super::{SignatureAlgorithm, SignatureHashAlgorithm, SignatureInfo, SignatureVersion};
use crate::errors::Error;

type BoxedError = Box<dyn std::error::Error + Send + Sync>;

fn key_load_error(error: impl Into<BoxedError>) -> Error {
    Error::KeyLoadSecretKeyError(error.into())
}

fn sign_error(error: impl Into<BoxedError>) -> Error {
    Error::SignError(error.into())
}

fn verification_error(error: impl Into<BoxedError>, key_ref: impl Into<String>) -> Error {
    Error::VerificationError {
        source: error.into(),
        key_ref: key_ref.into(),
    }
}

fn parse_certs(input: &[u8]) -> Result<Vec<Cert>, Error> {
    let certs = CertParser::from_bytes(input)
        .map_err(key_load_error)?
        .collect::<openpgp::Result<Vec<_>>>()
        .map_err(key_load_error)?;

    if certs.is_empty() {
        Err(key_load_error(io::Error::other(
            "no OpenPGP certificates found",
        )))
    } else {
        Ok(certs)
    }
}

fn parse_public_certs(input: &[u8]) -> Result<Vec<Cert>, Error> {
    Ok(parse_certs(input)?
        .into_iter()
        .map(Cert::strip_secret_key_material)
        .collect())
}

fn find_default_signing_key(certs: &[Cert]) -> Result<Fingerprint, Error> {
    let policy = StandardPolicy::new();
    certs
        .iter()
        .find_map(|cert| {
            cert.keys()
                .secret()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_signing()
                .next()
                .map(|key| key.key().fingerprint())
        })
        .ok_or_else(|| key_load_error(io::Error::other("no suitable signing key found")))
}

/// Signer implementation using Sequoia's pure-Rust crypto backend.
///
/// The input may be a single transferable secret key or an armored keyring.
/// By default, the first policy-valid signing key is selected.
#[derive(Clone)]
pub struct Signer {
    certs: Vec<Cert>,
    signing_key: Fingerprint,
    key_passphrase: Option<String>,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("certificates", &self.certs.len())
            .field("signing_key", &self.signing_key)
            .field("has_key_passphrase", &self.key_passphrase.is_some())
            .finish()
    }
}

impl Signer {
    /// Construct a signer from an ASCII-armored file.
    pub fn from_asc_file(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        Self::from_asc_bytes(&std::fs::read(path).map_err(Error::Io)?)
    }

    /// Construct a signer from ASCII-armored bytes.
    pub fn from_asc_bytes(input: &[u8]) -> Result<Self, Error> {
        let certs = parse_certs(input)?;
        let signing_key = find_default_signing_key(&certs)?;
        Ok(Self {
            certs,
            signing_key,
            key_passphrase: None,
        })
    }

    /// Construct a signer from an ASCII-armored string.
    pub fn from_asc(input: &str) -> Result<Self, Error> {
        Self::from_asc_bytes(input.as_bytes())
    }

    /// Select a signing key by its full fingerprint bytes.
    pub fn with_signing_key(mut self, fingerprint: &[u8]) -> Result<Self, Error> {
        let policy = StandardPolicy::new();
        let found = self.certs.iter().find_map(|cert| {
            cert.keys()
                .secret()
                .with_policy(&policy, None)
                .supported()
                .alive()
                .revoked(false)
                .for_signing()
                .find(|key| key.key().fingerprint().as_bytes() == fingerprint)
                .map(|key| key.key().fingerprint())
        });

        self.signing_key = found.ok_or_else(|| Error::KeyNotFoundError {
            key_ref: hex::encode(fingerprint),
        })?;
        Ok(self)
    }

    /// Configure the passphrase used to unlock the selected secret key.
    pub fn with_key_passphrase(mut self, key_passphrase: impl Into<String>) -> Self {
        self.key_passphrase = Some(key_passphrase.into());
        self
    }
}

impl traits::Signing for Signer {
    type Signature = Vec<u8>;

    fn sign(&self, mut data: impl io::Read, t: crate::Timestamp) -> Result<Self::Signature, Error> {
        let policy = StandardPolicy::new();
        let (cert, signing_key) = self
            .certs
            .iter()
            .find_map(|cert| {
                cert.keys()
                    .secret()
                    .with_policy(&policy, None)
                    .supported()
                    .alive()
                    .revoked(false)
                    .for_signing()
                    .find(|key| key.key().fingerprint() == self.signing_key)
                    .map(|key| (cert, key))
            })
            .ok_or_else(|| Error::KeyNotFoundError {
                key_ref: hex::encode(self.signing_key.as_bytes()),
            })?;

        let mut key = signing_key.key().clone();
        if key.secret().is_encrypted() {
            let passphrase = self
                .key_passphrase
                .as_ref()
                .ok_or_else(|| sign_error(io::Error::other("selected signing key is encrypted")))?;
            let passphrase: openpgp::crypto::Password = passphrase.clone().into();
            key.secret_mut()
                .decrypt_in_place(signing_key.key(), &passphrase)
                .map_err(sign_error)?;
        }
        let keypair = key.into_keypair().map_err(sign_error)?;

        let mut template = SignatureBuilder::new(SignatureType::Binary);
        if let Ok(userid) = cert
            .with_policy(&policy, None)
            .and_then(|cert| cert.primary_userid())
        {
            template = template
                .set_signers_user_id(userid.userid().value())
                .map_err(sign_error)?;
        }

        let mut signature = Vec::new();
        let message = Message::new(&mut signature);
        let creation_time = UNIX_EPOCH + Duration::from_secs(t.0.into());
        let mut writer = StreamSigner::with_template(message, keypair, template)
            .map_err(sign_error)?
            .detached()
            .hash_algo(HashAlgorithm::SHA256)
            .map_err(sign_error)?
            .creation_time(creation_time)
            .build()
            .map_err(sign_error)?;
        io::copy(&mut data, &mut writer).map_err(Error::Io)?;
        writer.finalize().map_err(sign_error)?;
        Ok(signature)
    }
}

/// Verifier implementation using Sequoia.
#[derive(Clone, Default)]
pub struct Verifier {
    certs: Vec<Cert>,
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verifier")
            .field("certificates", &self.certs.len())
            .finish()
    }
}

impl Verifier {
    /// Construct an empty verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a verifier from an ASCII-armored file.
    pub fn from_asc_file(path: impl AsRef<std::path::Path>) -> Result<Self, Error> {
        Self::from_asc_bytes(&std::fs::read(path).map_err(Error::Io)?)
    }

    /// Construct a verifier from ASCII-armored bytes.
    pub fn from_asc_bytes(input: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            certs: parse_public_certs(input)?,
        })
    }

    /// Construct a verifier from an ASCII-armored string.
    pub fn from_asc(input: &str) -> Result<Self, Error> {
        Self::from_asc_bytes(input.as_bytes())
    }

    /// Append certificates from an ASCII-armored file.
    pub fn load_from_asc_file(&mut self, path: impl AsRef<std::path::Path>) -> Result<(), Error> {
        self.load_from_asc_bytes(&std::fs::read(path).map_err(Error::Io)?)
    }

    /// Append certificates from ASCII-armored bytes.
    pub fn load_from_asc_bytes(&mut self, input: &[u8]) -> Result<(), Error> {
        self.certs.extend(parse_public_certs(input)?);
        Ok(())
    }

    /// Append certificates from an ASCII-armored string.
    pub fn load_from_asc(&mut self, input: &str) -> Result<(), Error> {
        self.load_from_asc_bytes(input.as_bytes())
    }

    /// Select one certificate by its primary-key fingerprint.
    pub fn with_key(mut self, fingerprint: &[u8]) -> Result<Self, Error> {
        self.certs
            .retain(|cert| cert.fingerprint().as_bytes() == fingerprint);
        if self.certs.is_empty() {
            Err(Error::KeyNotFoundError {
                key_ref: hex::encode(fingerprint),
            })
        } else {
            Ok(self)
        }
    }
}

struct Helper {
    certs: Vec<Cert>,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(self
            .certs
            .iter()
            .filter(|cert| {
                ids.is_empty()
                    || cert
                        .keys()
                        .any(|key| ids.iter().any(|id| id.aliases(key.key().key_handle())))
            })
            .cloned()
            .collect())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        for layer in structure {
            if let MessageLayer::SignatureGroup { results } = layer {
                let mut last_error = None;
                for result in results {
                    match result {
                        Ok(_) => return Ok(()),
                        Err(error) => last_error = Some(error),
                    }
                }
                if let Some(error) = last_error {
                    return Err(openpgp::Error::from(error).into());
                }
            }
        }
        Err(openpgp::Error::BadSignature("no valid detached signature".to_owned()).into())
    }
}

impl traits::Verifying for Verifier {
    type Signature = Vec<u8>;

    fn verify(&self, mut data: impl io::Read, signature: &[u8]) -> Result<(), Error> {
        let info = parse_signature_info(signature)?;
        if self.certs.is_empty() {
            return Err(Error::KeyNotFoundError {
                key_ref: info
                    .fingerprint()
                    .or(info.key_id())
                    .unwrap_or("no issuer fingerprint in signature")
                    .to_owned(),
            });
        }

        let parsed_signature = parse_signature(signature)?;
        let has_issuer = parsed_signature.issuer_fingerprints().next().is_some()
            || parsed_signature.issuers().next().is_some();
        let has_matching_key = self.certs.iter().any(|cert| {
            cert.keys().any(|key| {
                parsed_signature
                    .issuer_fingerprints()
                    .any(|fingerprint| fingerprint == &key.key().fingerprint())
                    || parsed_signature
                        .issuers()
                        .any(|key_id| key_id == &key.key().keyid())
            })
        });
        if has_issuer && !has_matching_key {
            return Err(Error::KeyNotFoundError {
                key_ref: info
                    .fingerprint()
                    .or(info.key_id())
                    .unwrap_or("unknown OpenPGP key")
                    .to_owned(),
            });
        }

        let policy = StandardPolicy::new();
        let helper = Helper {
            certs: self.certs.clone(),
        };
        let key_ref = info
            .fingerprint()
            .or(info.key_id())
            .unwrap_or("unknown OpenPGP key")
            .to_owned();
        let mut verifier = DetachedVerifierBuilder::from_bytes(signature)
            .map_err(|error| verification_error(error, &key_ref))?
            .with_policy(&policy, None, helper)
            .map_err(|error| verification_error(error, &key_ref))?;
        let mut data_bytes = Vec::new();
        data.read_to_end(&mut data_bytes).map_err(Error::Io)?;
        verifier
            .verify_bytes(&data_bytes)
            .map_err(|error| verification_error(error, key_ref))
    }
}

fn signature_algorithm(algorithm: PublicKeyAlgorithm) -> SignatureAlgorithm {
    #[allow(deprecated)]
    match algorithm {
        PublicKeyAlgorithm::RSAEncryptSign | PublicKeyAlgorithm::RSASign => SignatureAlgorithm::RSA,
        PublicKeyAlgorithm::DSA => SignatureAlgorithm::DSA,
        PublicKeyAlgorithm::ECDSA => SignatureAlgorithm::ECDSA,
        PublicKeyAlgorithm::EdDSA => SignatureAlgorithm::EdDSALegacy,
        PublicKeyAlgorithm::Ed25519 => SignatureAlgorithm::Ed25519,
        PublicKeyAlgorithm::Ed448 => SignatureAlgorithm::Ed448,
        other => SignatureAlgorithm::Unsupported(other.into()),
    }
}

fn signature_hash_algorithm(algorithm: HashAlgorithm) -> SignatureHashAlgorithm {
    match algorithm {
        HashAlgorithm::SHA1 => SignatureHashAlgorithm::SHA1,
        HashAlgorithm::SHA256 => SignatureHashAlgorithm::SHA256,
        HashAlgorithm::SHA384 => SignatureHashAlgorithm::SHA384,
        HashAlgorithm::SHA512 => SignatureHashAlgorithm::SHA512,
        HashAlgorithm::SHA224 => SignatureHashAlgorithm::SHA224,
        HashAlgorithm::SHA3_256 => SignatureHashAlgorithm::SHA3_256,
        HashAlgorithm::SHA3_512 => SignatureHashAlgorithm::SHA3_512,
        other => SignatureHashAlgorithm::Unsupported(other.into()),
    }
}

fn parse_signature(signature: &[u8]) -> Result<Signature, Error> {
    match Packet::from_bytes(signature)
        .map_err(|error| verification_error(error, "unknown OpenPGP key"))?
    {
        Packet::Signature(signature) => Ok(signature),
        _ => Err(Error::NoSignatureFound),
    }
}

pub(crate) fn parse_signature_info(signature: &[u8]) -> Result<SignatureInfo, Error> {
    let signature = parse_signature(signature)?;
    let created = signature
        .signature_creation_time()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| u32::try_from(duration.as_secs()).ok());

    Ok(SignatureInfo::new(
        signature
            .issuer_fingerprints()
            .next()
            .map(|fingerprint| hex::encode(fingerprint.as_bytes())),
        signature
            .issuers()
            .next()
            .map(|key_id| hex::encode(key_id.as_bytes())),
        signature.version().into(),
        Some(signature_algorithm(signature.pk_algo())),
        Some(signature_hash_algorithm(signature.hash_algo())),
        created,
    ))
}
