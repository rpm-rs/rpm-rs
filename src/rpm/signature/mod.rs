mod traits;
pub use self::traits::*;

#[cfg(feature = "signature-meta")]
mod meta;
#[cfg(feature = "signature-meta")]
pub use self::meta::*;

#[cfg(feature = "signature-pgp")]
pub mod pgp;

#[cfg(feature = "signature-sequoia")]
pub mod sequoia;

#[cfg(feature = "signature-pgp")]
pub(crate) fn parse_signature_info(signature: &[u8]) -> Result<SignatureInfo, crate::Error> {
    pgp::Verifier::parse_signature(signature).map(|signature| pgp::signature_info(&signature))
}

#[cfg(all(not(feature = "signature-pgp"), feature = "signature-sequoia"))]
pub(crate) fn parse_signature_info(signature: &[u8]) -> Result<SignatureInfo, crate::Error> {
    sequoia::parse_signature_info(signature)
}

/// test helper to print signatures
pub fn echo_signature(scope: &str, signature: &[u8]) {
    log::debug!(
        "{}: [len={}] [{:#04X?}, {:#04X?}, {:#04X?}, {:#04X?}, {:#04X?}, ...]",
        scope,
        signature.len(),
        signature[0],
        signature[1],
        signature[2],
        signature[3],
        signature[4]
    );
}
