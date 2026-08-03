use std::fs;
use std::path::Path;

use hex;
use rpm::{self};

#[cfg(feature = "signature-pgp")]
use rpm::signature::pgp::{Signer, Verifier};
#[cfg(feature = "signature-sequoia")]
use rpm::signature::sequoia::{Signer, Verifier};

mod common;

fn test_timestamp() -> rpm::Timestamp {
    rpm::Timestamp(1_780_000_000)
}

/// Resign an already-signed package with new keys, and verify it with the new keys
#[test]
fn test_rpm_file_signatures_resign() -> Result<(), Box<dyn std::error::Error>> {
    let pkg_path = common::pkgs::v4::RPM_BASIC_RSA_SIGNED;

    // test RSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::RSA_4K_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::RSA_4K_PUBLIC)?,
        "v4_rsa_resigned_pkg.rpm",
    )?;

    // test RSA - with secret key protected by a passphrase
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::RSA_3K_PROTECTED_PRIVATE)?,
        Some(common::keys::v4::RSA_3K_PASSPHRASE.to_string()),
        &fs::read(common::keys::v4::RSA_3K_PROTECTED_PUBLIC)?,
        "v4_rsa_resigned_pkg.rpm",
    )?;

    // test EdDSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::ED25519_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::ED25519_PUBLIC)?,
        "v4_eddsa_resigned_pkg.rpm",
    )?;

    // test ECDSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v4::ECDSA_NISTP256_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::ECDSA_NISTP256_PUBLIC)?,
        "v4_ecdsa_resigned_pkg.rpm",
    )?;

    let pkg_path = common::pkgs::v6::RPM_BASIC_RSA_SIGNED;

    // test v6 RSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v6::RSA_4K_PRIVATE)?,
        None,
        &fs::read(common::keys::v6::RSA_4K_PUBLIC)?,
        "v6_rsa_resigned_pkg.rpm",
    )?;

    // test v6 EdDSA
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v6::ED25519_PRIVATE)?,
        None,
        &fs::read(common::keys::v6::ED25519_PUBLIC)?,
        "v6_eddsa_resigned_pkg.rpm",
    )?;

    #[cfg(feature = "signature-pgp")]
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &fs::read(common::keys::v6::MLDSA65_ED25519_PRIVATE)?,
        None,
        &fs::read(common::keys::v6::MLDSA65_ED25519_PUBLIC)?,
        "v6_mldsa_resigned_pkg.rpm",
    )?;

    Ok(())
}

/// Test parsing packages that were built and signed by RPM
#[test]
fn parse_externally_signed_rpm_and_verify() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    // v4 RSA
    open_and_verify(
        common::pkgs::v4::RPM_BASIC_RSA_SIGNED,
        common::keys::v4::RSA_4K_PUBLIC,
    )?;

    // v4 ECDSA
    open_and_verify(
        common::pkgs::v4::RPM_BASIC_ECDSA_SIGNED,
        common::keys::v4::ECDSA_NISTP256_PUBLIC,
    )?;

    // v4 EdDSA
    open_and_verify(
        common::pkgs::v4::RPM_BASIC_EDDSA_SIGNED,
        common::keys::v4::ED25519_PUBLIC,
    )?;

    // v6 RSA
    open_and_verify(
        common::pkgs::v6::RPM_BASIC_RSA_SIGNED,
        common::keys::v6::RSA_4K_PUBLIC,
    )?;

    // v6 EdDSA
    open_and_verify(
        common::pkgs::v6::RPM_BASIC_EDDSA_SIGNED,
        common::keys::v6::ED25519_PUBLIC,
    )?;

    #[cfg(feature = "signature-pgp")]
    open_and_verify(
        common::pkgs::v6::RPM_BASIC_MLDSA_SIGNED,
        common::keys::v6::MLDSA65_ED25519_PUBLIC,
    )?;

    // v6 multiple signatures (EdDSA + RSA)
    let package = rpm::Package::open(common::pkgs::v6::RPM_BASIC_MULTI_SIGNED)?;
    let verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;
    package.verify_signature(&verifier)?;
    let verifier = Verifier::from_asc_file(common::keys::v6::RSA_4K_PUBLIC)?;
    package.verify_signature(&verifier)?;

    // check_signatures with one key: verify fingerprints match expectations
    let sigs = package.signatures()?;
    assert_eq!(sigs.len(), 2);
    let all_fingerprints: Vec<_> = sigs.iter().map(|s| s.fingerprint().unwrap()).collect();

    // RSA verifier: the RSA signature should verify, the other should fail
    let report = package.check_signatures(&verifier)?;
    assert_eq!(report.signatures.len(), 2);
    assert!(report.is_ok(), "at least one signature should verify");

    let verified: Vec<_> = report
        .signatures
        .iter()
        .filter(|s| s.is_verified())
        .collect();
    let failed: Vec<_> = report
        .signatures
        .iter()
        .filter(|s| !s.is_verified())
        .collect();
    assert_eq!(verified.len(), 1);
    assert_eq!(failed.len(), 1);

    // The verified signature's fingerprint should be one we know about
    let verified_fp = verified[0].info.fingerprint().unwrap();
    assert!(
        all_fingerprints.contains(&verified_fp),
        "verified fingerprint {verified_fp} should be in the package's signature list"
    );

    // The failed signature should have a different fingerprint and an error
    let failed_fp = failed[0].info.fingerprint().unwrap();
    assert_ne!(
        verified_fp, failed_fp,
        "verified and failed should be different signatures"
    );
    assert!(failed[0].error.is_some());

    Ok(())
}

/// Test an attempt to verify the signature of a package that is not signed
#[test]
fn test_verify_unsigned_package() -> Result<(), Box<dyn std::error::Error>> {
    // v4
    let verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
    let pkg = rpm::Package::open(common::pkgs::v4::RPM_EMPTY)?;
    assert!(matches!(
        pkg.verify_signature(&verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    // check_signatures report: digests ok, no signatures
    let report = pkg.check_signatures(&verifier)?;
    assert!(report.digests.is_ok());
    assert!(report.signatures.is_empty());
    assert!(!report.is_ok());
    assert!(matches!(
        report.into_result(),
        Err(rpm::Error::NoSignatureFound)
    ));

    // v6
    let verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;
    let pkg = rpm::Package::open(common::pkgs::v6::RPM_EMPTY)?;
    assert!(matches!(
        pkg.verify_signature(&verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    let report = pkg.check_signatures(&verifier)?;
    assert!(report.digests.is_ok());
    assert!(report.signatures.is_empty());

    Ok(())
}

/// Test that verifying with an empty verifier (no keys loaded) fails
#[test]
fn test_verify_with_empty_verifier() -> Result<(), Box<dyn std::error::Error>> {
    let verifier = Verifier::new();

    // v4
    let pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?;
    assert!(matches!(
        pkg.verify_signature(&verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    // check_signatures report: signature present but failed
    let report = pkg.check_signatures(&verifier)?;
    assert!(report.digests.is_ok());
    assert_eq!(report.signatures.len(), 1);
    assert!(!report.signatures[0].is_verified());
    assert!(!report.is_ok());

    // v6
    let pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC_RSA_SIGNED)?;
    assert!(matches!(
        pkg.verify_signature(&verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    Ok(())
}

/// Test an attempt to verify the signature of a package using the wrong key type
#[test]
fn test_verify_package_with_wrong_key_type() -> Result<(), Box<dyn std::error::Error>> {
    let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
    let rsa_verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
    let rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
        .build_and_sign(&rsa_signer)?;

    let eddsa_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
    let eddsa_verifier = Verifier::from_asc_file(common::keys::v4::ED25519_PUBLIC)?;
    let eddsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
        .build_and_sign(&eddsa_signer)?;

    // test EdDSA key with RSA-signed package
    assert!(matches!(
        rsa_pkg.verify_signature(&eddsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    // test RSA key with EdDSA-signed package
    assert!(matches!(
        eddsa_pkg.verify_signature(&rsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    // v6 wrong key type
    let v6_rsa_signer = Signer::from_asc_file(common::keys::v6::RSA_4K_PRIVATE)?;
    let v6_rsa_verifier = Verifier::from_asc_file(common::keys::v6::RSA_4K_PUBLIC)?;
    let v6_rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
        .build_and_sign(&v6_rsa_signer)?;

    let v6_eddsa_signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
    let v6_eddsa_verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;
    let v6_eddsa_pkg =
        rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
            .build_and_sign(&v6_eddsa_signer)?;

    // test v6 EdDSA key with v6 RSA-signed package
    assert!(matches!(
        v6_rsa_pkg.verify_signature(&v6_eddsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    // test v6 RSA key with v6 EdDSA-signed package
    assert!(matches!(
        v6_eddsa_pkg.verify_signature(&v6_rsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    // cross-version: v4 key with v6-signed package
    assert!(matches!(
        v6_rsa_pkg.verify_signature(&rsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    // cross-version: v6 key with v4-signed package
    assert!(matches!(
        rsa_pkg.verify_signature(&v6_rsa_verifier),
        Err(rpm::Error::KeyNotFoundError { key_ref: _ })
    ));

    Ok(())
}

/// Test resigning a package across key versions (v4 package with v6 keys and vice versa)
#[test]
fn test_cross_version_resign() -> Result<(), Box<dyn std::error::Error>> {
    // Resign a v4 package with v6 keys
    let v4_pkg_path = common::pkgs::v4::RPM_BASIC_RSA_SIGNED;

    resign_and_verify_with_keys(
        v4_pkg_path.as_ref(),
        &fs::read(common::keys::v6::RSA_4K_PRIVATE)?,
        None,
        &fs::read(common::keys::v6::RSA_4K_PUBLIC)?,
        "cross_v4_with_v6_rsa_resigned_pkg.rpm",
    )?;

    resign_and_verify_with_keys(
        v4_pkg_path.as_ref(),
        &fs::read(common::keys::v6::ED25519_PRIVATE)?,
        None,
        &fs::read(common::keys::v6::ED25519_PUBLIC)?,
        "cross_v4_with_v6_eddsa_resigned_pkg.rpm",
    )?;

    #[cfg(feature = "signature-pgp")]
    resign_and_verify_with_keys(
        v4_pkg_path.as_ref(),
        &fs::read(common::keys::v6::MLDSA65_ED25519_PRIVATE)?,
        None,
        &fs::read(common::keys::v6::MLDSA65_ED25519_PUBLIC)?,
        "cross_v4_with_v6_mldsa_resigned_pkg.rpm",
    )?;

    // Resign a v6 package with v4 keys
    let v6_pkg_path = common::pkgs::v6::RPM_BASIC_RSA_SIGNED;

    resign_and_verify_with_keys(
        v6_pkg_path.as_ref(),
        &fs::read(common::keys::v4::RSA_4K_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::RSA_4K_PUBLIC)?,
        "cross_v6_with_v4_rsa_resigned_pkg.rpm",
    )?;

    resign_and_verify_with_keys(
        v6_pkg_path.as_ref(),
        &fs::read(common::keys::v4::ED25519_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::ED25519_PUBLIC)?,
        "cross_v6_with_v4_eddsa_resigned_pkg.rpm",
    )?;

    resign_and_verify_with_keys(
        v6_pkg_path.as_ref(),
        &fs::read(common::keys::v4::ECDSA_NISTP256_PRIVATE)?,
        None,
        &fs::read(common::keys::v4::ECDSA_NISTP256_PUBLIC)?,
        "cross_v6_with_v4_ecdsa_resigned_pkg.rpm",
    )?;

    Ok(())
}

/// Open a package and verify its signature with the given public key.
#[track_caller]
fn open_and_verify(
    pkg_path: impl AsRef<Path>,
    public_key_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let verifier = Verifier::from_asc_file(public_key_path)?;
    let package = rpm::Package::open(pkg_path)?;
    package.verify_signature(&verifier)?;
    Ok(())
}

/// Resign a package with the given key, write it out, re-open it, and verify the new signature.
#[track_caller]
fn resign_and_verify_with_keys(
    pkg_path: &Path,
    signing_key: &[u8],
    signing_key_passphrase: Option<String>,
    verification_key: &[u8],
    pkg_out_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut package = rpm::Package::open(pkg_path)?;
    let original_header_and_payload_size = package
        .metadata
        .signature
        .get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_SIZE)
        .ok();
    let mut signer = Signer::from_asc_bytes(signing_key)?;
    if let Some(passphrase) = signing_key_passphrase {
        signer = signer.with_key_passphrase(passphrase);
    }
    package.sign_with_timestamp(&signer, test_timestamp())?;

    let out_file = Path::new(common::CARGO_OUT_DIR).join(pkg_out_path.as_ref());
    package.write_file(&out_file)?;

    let package = rpm::Package::open(&out_file)?;

    // Resigning the package should not change the size.
    //
    // Note that this size does not include the signature header, so is unaffected by changes in
    // the signature value. Only v4 packages have RPMSIGTAG_SIZE.
    if let Some(original_size) = original_header_and_payload_size {
        let new_header_and_payload_size = package
            .metadata
            .signature
            .get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_SIZE)?;
        assert_eq!(original_size, new_header_and_payload_size);
    }

    let verifier = Verifier::from_asc_bytes(verification_key).unwrap();
    package
        .verify_signature(&verifier)
        .expect("failed to verify signature");
    Ok(())
}

#[cfg(feature = "payload")]
mod keyring {
    use super::*;

    /// Sign with a key from the keyring signer and verify with the keyring verifier.
    #[test]
    fn test_sign_with_keyring_signer() -> Result<(), Box<dyn std::error::Error>> {
        // v4
        let keyring_signer = Signer::from_asc_bytes(&fs::read(common::keys::v4::KEYRING_PRIVATE)?)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring signer test")
            .build_and_sign(&keyring_signer)?;

        let keyring_verifier = Verifier::from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        pkg.verify_signature(&keyring_verifier)?;

        #[cfg(feature = "signature-pgp")]
        {
            let keyring_signer =
                Signer::from_asc_bytes(&fs::read(common::keys::v6::KEYRING_PRIVATE)?)?;
            let pkg =
                rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring signer test")
                    .build_and_sign(&keyring_signer)?;

            let keyring_verifier = Verifier::from_asc_file(common::keys::v6::KEYRING_PUBLIC)?;
            pkg.verify_signature(&keyring_verifier)?;
        }

        Ok(())
    }

    /// Sign with an individual key and verify using a keyring that contains that key
    /// (among others). The verifier should find the matching key automatically.
    #[test]
    fn test_verify_with_keyring() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();

        // v4
        let keyring_verifier = Verifier::from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;

        let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&rsa_signer)?;
        rsa_pkg.verify_signature(&keyring_verifier)?;

        let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let ed_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&ed_signer)?;
        ed_pkg.verify_signature(&keyring_verifier)?;

        // v6
        let keyring_verifier = Verifier::from_asc_file(common::keys::v6::KEYRING_PUBLIC)?;

        let rsa_signer = Signer::from_asc_file(common::keys::v6::RSA_4K_PRIVATE)?;
        let rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&rsa_signer)?;
        rsa_pkg.verify_signature(&keyring_verifier)?;

        let ed_signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
        let ed_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&ed_signer)?;
        ed_pkg.verify_signature(&keyring_verifier)?;

        Ok(())
    }

    /// Sign with individual keys and verify using a verifier built by loading
    /// each key separately via `load_from_asc_file`.
    #[test]
    fn test_verify_with_loaded_keys() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();

        let mut verifier = Verifier::new();
        verifier.load_from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
        verifier.load_from_asc_file(common::keys::v4::ED25519_PUBLIC)?;

        // Sign with RSA key, verify with combined verifier
        let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "loaded keys test")
            .build_and_sign(&rsa_signer)?;
        rsa_pkg.verify_signature(&verifier)?;

        // Sign with Ed25519 key, verify with the same combined verifier
        let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let ed_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "loaded keys test")
            .build_and_sign(&ed_signer)?;
        ed_pkg.verify_signature(&verifier)?;

        Ok(())
    }

    /// Verify that a keyring verifier fails when the signing key is NOT in the keyring.
    #[test]
    fn test_verify_with_keyring_wrong_key() -> Result<(), Box<dyn std::error::Error>> {
        // v4: the keyring contains RSA-4K, RSA-3K-protected, and Ed25519 — but NOT ECDSA
        let keyring_verifier = Verifier::from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;

        let ecdsa_signer = Signer::from_asc_file(common::keys::v4::ECDSA_NISTP256_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&ecdsa_signer)?;

        assert!(
            pkg.verify_signature(&keyring_verifier).is_err(),
            "verification should fail when signing key is not in the v4 keyring"
        );

        // v6: sign with a v4 key that is not in the v6 keyring
        let keyring_verifier = Verifier::from_asc_file(common::keys::v6::KEYRING_PUBLIC)?;

        let v4_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "keyring test")
            .build_and_sign(&v4_signer)?;

        assert!(
            pkg.verify_signature(&keyring_verifier).is_err(),
            "verification should fail when signing key is not in the v6 keyring"
        );

        Ok(())
    }

    /// Use `Verifier::with_key` to select a specific certificate from a keyring
    /// and verify a package signed with that certificate's key.
    #[test]
    fn test_verify_with_key_selection() -> Result<(), Box<dyn std::error::Error>> {
        // Sign a package with the RSA key
        let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "with_key test")
            .build_and_sign(&rsa_signer)?;

        // Get the signer's fingerprint from the package signature
        let sigs = pkg.signatures()?;
        assert_eq!(sigs.len(), 1);
        let signer_fpr_bytes = hex::decode(sigs[0].fingerprint().unwrap())?;

        // Load the full keyring, then narrow to the matching key
        let keyring_verifier = Verifier::from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        let filtered_verifier = keyring_verifier.with_key(&signer_fpr_bytes)?;
        pkg.verify_signature(&filtered_verifier)?;

        Ok(())
    }

    /// `Verifier::with_key` should fail when the requested fingerprint is not in the keyring.
    #[test]
    fn test_verify_with_key_not_found() -> Result<(), Box<dyn std::error::Error>> {
        let keyring_verifier = Verifier::from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        let bogus_fingerprint = [0xDE, 0xAD, 0xBE, 0xEF];
        assert!(matches!(
            keyring_verifier.with_key(&bogus_fingerprint),
            Err(rpm::Error::KeyNotFoundError { key_ref: _ })
        ));
        Ok(())
    }

    /// `Verifier::with_key` should fail verification when the selected key does not
    /// match the key that signed the package, even though the keyring contains the
    /// correct key.
    #[test]
    fn test_verify_with_key_selects_wrong_cert() -> Result<(), Box<dyn std::error::Error>> {
        // Sign with Ed25519, but filter the keyring to only the RSA key
        let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "with_key test")
            .build_and_sign(&ed_signer)?;

        // Get the RSA key's fingerprint from a package signed with it
        let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let rsa_pkg = rpm::PackageBuilder::new("bar", "1.0.0", "MIT", "x86_64", "helper")
            .build_and_sign(&rsa_signer)?;
        let rsa_sigs = rsa_pkg.signatures()?;
        let rsa_fpr_bytes = hex::decode(rsa_sigs[0].fingerprint().unwrap())?;

        // Filter keyring to only the RSA cert, then try to verify the Ed25519-signed package
        let keyring_verifier = Verifier::from_asc_file(common::keys::v4::KEYRING_PUBLIC)?;
        let rsa_only_verifier = keyring_verifier.with_key(&rsa_fpr_bytes)?;
        assert!(
            pkg.verify_signature(&rsa_only_verifier).is_err(),
            "verification should fail when with_key selects a cert that didn't sign the package"
        );

        Ok(())
    }

    /// Verify that `with_key` selecting by primary key fingerprint works when the
    /// signature was actually made by a subkey of that certificate. This is the
    /// typical v6 case where the primary key is certification-only and a subkey
    /// is used for signing.
    #[test]
    fn test_verify_with_key_matches_primary_when_subkey_signs()
    -> Result<(), Box<dyn std::error::Error>> {
        // v6 Ed25519: primary key is certification-only, subkey has signing flag.
        // The signer auto-selects the signing subkey.
        let signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "subkey test")
            .build_and_sign(&signer)?;

        // The signature's issuer fingerprint is the subkey, not the primary key
        let sigs = pkg.signatures()?;
        assert_eq!(sigs.len(), 1);
        let subkey_fpr = sigs[0].fingerprint().unwrap();

        // Load the public key and get the primary key fingerprint
        let verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;

        // Get the primary key fingerprint by parsing the public cert directly
        let primary_fpr = {
            use pgp::composed::{Deserializable, SignedPublicKey};
            use pgp::types::KeyDetails;
            let (key, _) = SignedPublicKey::from_armor_file(common::keys::v6::ED25519_PUBLIC)?;
            hex::encode(key.fingerprint().as_bytes())
        };

        // Confirm the primary key fingerprint differs from the signing subkey fingerprint
        assert_ne!(
            primary_fpr, *subkey_fpr,
            "primary and subkey fingerprints should differ for v6 keys"
        );

        // with_key filters by primary fingerprint, but verification should still succeed
        // because the subkey belongs to that certificate
        let filtered_verifier = verifier.with_key(&hex::decode(&primary_fpr)?)?;
        pkg.verify_signature(&filtered_verifier)?;

        Ok(())
    }
}

/// Test that verify_digests succeeds independently of signature verification,
/// and that check_digests() reports the correct per-digest status for v4 vs v6.
#[test]
fn test_verify_digests_standalone() -> Result<(), Box<dyn std::error::Error>> {
    // Unsigned packages should still have valid digests
    rpm::Package::open(common::pkgs::v4::RPM_EMPTY)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v4::RPM_BASIC)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v6::RPM_EMPTY)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v6::RPM_BASIC)?.verify_digests()?;

    // Signed packages should also have valid digests
    rpm::Package::open(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v4::RPM_BASIC_EDDSA_SIGNED)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v4::RPM_BASIC_ECDSA_SIGNED)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v6::RPM_BASIC_RSA_SIGNED)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v6::RPM_BASIC_EDDSA_SIGNED)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v6::RPM_BASIC_MLDSA_SIGNED)?.verify_digests()?;
    rpm::Package::open(common::pkgs::v6::RPM_BASIC_MULTI_SIGNED)?.verify_digests()?;

    // Self-built packages should have valid digests
    let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "digest test").build()?;
    pkg.verify_digests()?;

    let signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
    let signed_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "digest test")
        .build_and_sign(&signer)?;
    signed_pkg.verify_digests()?;

    // check_digests() on a v4 package: SHA-1 present, SHA3-256 not present
    let report = rpm::Package::open(common::pkgs::v4::RPM_BASIC)?.check_digests()?;
    assert!(report.header_sha1.is_verified());
    assert!(report.header_sha256.is_verified());
    assert!(report.header_sha3_256.is_not_present());
    assert!(report.payload_sha256.is_verified());
    assert!(report.payload_sha512.is_not_present());
    assert!(report.payload_sha3_256.is_not_present());
    // v4 fixtures built by rpmbuild may not have ALT tags
    assert!(
        report.payload_sha256_alt.is_not_present()
            || report.payload_sha256_alt.is_verified()
            || report.payload_sha256_alt.is_mismatch()
    );
    assert!(report.is_ok());

    // check_digests() on a v6 package (uncompressed): SHA3-256 present, SHA-1 not present
    // Both primary and ALT digests verify because payload == uncompressed archive
    let report = rpm::Package::open(common::pkgs::v6::RPM_BASIC)?.check_digests()?;
    assert!(report.header_sha256.is_verified());
    assert!(report.header_sha3_256.is_verified());
    assert!(report.header_sha1.is_not_present());
    assert!(report.payload_sha256.is_verified());
    assert!(report.payload_sha512.is_verified());
    assert!(report.payload_sha3_256.is_verified());
    assert!(report.payload_sha256_alt.is_verified());
    assert!(report.payload_sha512_alt.is_verified());
    assert!(report.payload_sha3_256_alt.is_verified());
    assert!(report.is_ok());

    Ok(())
}

/// Test the signatures() API returns correct info for signed and unsigned packages
#[test]
fn test_signatures() -> Result<(), Box<dyn std::error::Error>> {
    use rpm::signature::{SignatureAlgorithm, SignatureHashAlgorithm, SignatureVersion};

    // Unsigned packages should return an empty Vec
    assert!(
        rpm::Package::open(common::pkgs::v4::RPM_EMPTY)?
            .signatures()?
            .is_empty()
    );
    assert!(
        rpm::Package::open(common::pkgs::v6::RPM_EMPTY)?
            .signatures()?
            .is_empty()
    );

    // v4 RSA
    let pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?;
    let sigs = pkg.signatures()?;
    assert_eq!(sigs.len(), 1);
    assert!(sigs[0].fingerprint().is_some());
    assert!(sigs[0].key_id().is_some());
    assert_eq!(sigs[0].version(), SignatureVersion::V4);
    assert_eq!(sigs[0].algorithm(), Some(SignatureAlgorithm::RSA));
    assert!(sigs[0].created().is_some());

    // v4 EdDSA
    let pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC_EDDSA_SIGNED)?;
    let sigs = pkg.signatures()?;
    assert_eq!(sigs.len(), 1);
    assert!(sigs[0].fingerprint().is_some());
    assert!(sigs[0].key_id().is_some());
    assert_eq!(sigs[0].algorithm(), Some(SignatureAlgorithm::EdDSALegacy));

    // v4 ECDSA
    let pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC_ECDSA_SIGNED)?;
    let sigs = pkg.signatures()?;
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].algorithm(), Some(SignatureAlgorithm::ECDSA));

    // v6 RSA - no key_id expected
    let pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC_RSA_SIGNED)?;
    let sigs = pkg.signatures()?;
    assert_eq!(sigs.len(), 1);
    assert!(sigs[0].fingerprint().is_some());
    assert!(sigs[0].key_id().is_none());
    assert_eq!(sigs[0].version(), SignatureVersion::V6);
    assert_eq!(sigs[0].algorithm(), Some(SignatureAlgorithm::RSA));

    // v6 EdDSA
    let pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC_EDDSA_SIGNED)?;
    let sigs = pkg.signatures()?;
    assert_eq!(sigs.len(), 1);
    assert_eq!(sigs[0].algorithm(), Some(SignatureAlgorithm::Ed25519));

    // Sequoia 2.3 can parse the packet but does not classify the draft-PQC algorithm.
    let pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC_MLDSA_SIGNED)?;
    let sigs = pkg.signatures()?;
    assert_eq!(sigs.len(), 1);
    #[cfg(feature = "signature-pgp")]
    assert_eq!(
        sigs[0].algorithm(),
        Some(SignatureAlgorithm::MlDsa65Ed25519)
    );
    #[cfg(feature = "signature-sequoia")]
    assert_eq!(
        sigs[0].algorithm(),
        Some(SignatureAlgorithm::Unsupported(30))
    );

    // v6 multi-signed
    let pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC_MULTI_SIGNED)?;
    let sigs = pkg.signatures()?;
    assert_eq!(sigs.len(), 2);
    assert!(sigs.iter().all(|s| s.fingerprint().is_some()));

    // hash algorithm is present
    assert!(sigs.iter().all(|s| s.hash_algorithm().is_some()));
    // all hash algorithms should be recognized (not Unsupported)
    for sig in &sigs {
        assert!(!matches!(
            sig.hash_algorithm(),
            Some(SignatureHashAlgorithm::Unsupported(_))
        ),);
    }

    Ok(())
}

/// Test that sign() appends a signature rather than replacing existing ones
#[test]
fn test_sign_appends_signature() -> Result<(), Box<dyn std::error::Error>> {
    // v4
    let rsa_verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
    let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
    let ed_verifier = Verifier::from_asc_file(common::keys::v4::ED25519_PUBLIC)?;

    let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?;
    pkg.verify_signature(&rsa_verifier)?;
    assert_eq!(pkg.signatures()?.len(), 1);

    let sha1_before = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA1)?
        .to_owned();

    // Append a second signature
    pkg.sign(&ed_signer)?;

    // Both signatures should be verifiable
    pkg.verify_signature(&rsa_verifier)?;
    pkg.verify_signature(&ed_verifier)?;
    assert_eq!(pkg.signatures()?.len(), 2);

    // SHA1 digest should be preserved
    let sha1_after = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA1)?;
    assert_eq!(
        sha1_before, sha1_after,
        "SHA1 digest should be preserved when appending a signature"
    );

    pkg.verify_digests()?;

    // v6
    let v6_rsa_verifier = Verifier::from_asc_file(common::keys::v6::RSA_4K_PUBLIC)?;
    let v6_ed_signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
    let v6_ed_verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;

    let mut pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC_RSA_SIGNED)?;
    pkg.verify_signature(&v6_rsa_verifier)?;
    assert_eq!(pkg.signatures()?.len(), 1);

    pkg.sign(&v6_ed_signer)?;

    pkg.verify_signature(&v6_rsa_verifier)?;
    pkg.verify_signature(&v6_ed_verifier)?;
    assert_eq!(pkg.signatures()?.len(), 2);

    pkg.verify_digests()?;

    Ok(())
}

/// Test that clear_signatures() + sign() replaces all previous signatures
#[test]
fn test_clear_then_sign_replaces() -> Result<(), Box<dyn std::error::Error>> {
    // v4
    let rsa_verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
    let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
    let ed_verifier = Verifier::from_asc_file(common::keys::v4::ED25519_PUBLIC)?;

    let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?;
    pkg.verify_signature(&rsa_verifier)?;

    let sha1_before = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA1)?
        .to_owned();

    // Clear and re-sign with a different key
    pkg.clear_signatures()?;
    pkg.sign(&ed_signer)?;

    // Only the new signature should be present
    pkg.verify_signature(&ed_verifier)?;
    assert!(
        pkg.verify_signature(&rsa_verifier).is_err(),
        "original RSA signature should be gone after clear + re-sign"
    );
    assert_eq!(pkg.signatures()?.len(), 1);

    // SHA1 digest should be preserved
    let sha1_after = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA1)?;
    assert_eq!(
        sha1_before, sha1_after,
        "SHA1 digest should be preserved through clear + re-sign"
    );

    pkg.verify_digests()?;

    // v6
    let v6_rsa_verifier = Verifier::from_asc_file(common::keys::v6::RSA_4K_PUBLIC)?;
    let v6_ed_signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
    let v6_ed_verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;

    let mut pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC_RSA_SIGNED)?;
    pkg.verify_signature(&v6_rsa_verifier)?;

    // Clear and re-sign with a different key
    pkg.clear_signatures()?;
    pkg.sign(&v6_ed_signer)?;

    pkg.verify_signature(&v6_ed_verifier)?;
    assert!(
        pkg.verify_signature(&v6_rsa_verifier).is_err(),
        "original RSA signature should be gone after clear + re-sign"
    );
    assert_eq!(pkg.signatures()?.len(), 1);

    pkg.verify_digests()?;

    Ok(())
}

/// Test that signing a package twice with the same key replaces the previous signature
#[test]
fn test_sign_twice_with_same_key_replaces() -> Result<(), Box<dyn std::error::Error>> {
    // v4
    let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
    let rsa_verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;

    let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC)?;
    assert_eq!(pkg.signatures()?.len(), 0);

    pkg.sign(&rsa_signer)?;
    assert_eq!(pkg.signatures()?.len(), 1);
    pkg.verify_signature(&rsa_verifier)?;

    pkg.sign(&rsa_signer)?;
    assert_eq!(
        pkg.signatures()?.len(),
        1,
        "duplicate signature should be replaced"
    );
    pkg.verify_signature(&rsa_verifier)?;

    pkg.verify_digests()?;

    // v6
    let v6_ed_signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
    let v6_ed_verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;

    let mut pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC)?;
    assert_eq!(pkg.signatures()?.len(), 0);

    pkg.sign(&v6_ed_signer)?;
    assert_eq!(pkg.signatures()?.len(), 1);
    pkg.verify_signature(&v6_ed_verifier)?;

    pkg.sign(&v6_ed_signer)?;
    assert_eq!(
        pkg.signatures()?.len(),
        1,
        "duplicate signature should be replaced"
    );
    pkg.verify_signature(&v6_ed_verifier)?;

    pkg.verify_digests()?;

    Ok(())
}

/// Test that clearing signatures restores the package to its unsigned state
#[test]
fn test_clear_package_signatures() -> Result<(), Box<dyn std::error::Error>> {
    /// Sign a package, clear its signatures, and verify the signature header matches unsigned state.
    #[track_caller]
    fn sign_clear_and_verify(
        signing_key: &[u8],
        verification_key: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let unsigned_pkg = rpm::PackageBuilder::new(
            "roundtrip",
            "1.0.0",
            "MIT",
            "x86_64",
            "spins round and round",
        )
        .build()?;

        let cleared_pkg = {
            let mut pkg = unsigned_pkg.clone();
            let signer: Signer = Signer::from_asc_bytes(signing_key)?;
            pkg.sign(signer)?;
            pkg.clear_signatures()?;
            pkg
        };

        cleared_pkg.verify_digests()?;
        assert_eq!(
            cleared_pkg.metadata.signature,
            unsigned_pkg.metadata.signature
        );

        // Verification should fail because signatures were cleared
        let verifier = Verifier::from_asc_bytes(verification_key)?;
        assert!(matches!(
            cleared_pkg.verify_signature(verifier),
            Err(rpm::Error::NoSignatureFound)
        ));

        Ok(())
    }

    sign_clear_and_verify(
        &fs::read(common::keys::v4::ED25519_PRIVATE)?,
        &fs::read(common::keys::v4::ED25519_PUBLIC)?,
    )?;
    sign_clear_and_verify(
        &fs::read(common::keys::v4::ECDSA_NISTP256_PRIVATE)?,
        &fs::read(common::keys::v4::ECDSA_NISTP256_PUBLIC)?,
    )?;
    sign_clear_and_verify(
        &fs::read(common::keys::v4::RSA_4K_PRIVATE)?,
        &fs::read(common::keys::v4::RSA_4K_PUBLIC)?,
    )?;
    sign_clear_and_verify(
        &fs::read(common::keys::v6::RSA_4K_PRIVATE)?,
        &fs::read(common::keys::v6::RSA_4K_PUBLIC)?,
    )?;
    sign_clear_and_verify(
        &fs::read(common::keys::v6::ED25519_PRIVATE)?,
        &fs::read(common::keys::v6::ED25519_PUBLIC)?,
    )?;
    #[cfg(feature = "signature-pgp")]
    sign_clear_and_verify(
        &fs::read(common::keys::v6::MLDSA65_ED25519_PRIVATE)?,
        &fs::read(common::keys::v6::MLDSA65_ED25519_PUBLIC)?,
    )?;

    Ok(())
}

/// Test that clear_signatures() preserves digests and file signatures (IMA)
#[test]
fn test_clear_signatures_preserves_digests_and_file_signatures()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC_IMA_SIGNED)?;

    // Verify the package has file signatures and digests before clearing
    let file_sigs_before: Vec<String> = pkg
        .metadata
        .signature
        .get_entry_data_as_string_array(rpm::IndexSignatureTag::RPMSIGTAG_FILESIGNATURES)?
        .into_iter()
        .map(String::from)
        .collect();
    assert!(
        !file_sigs_before.is_empty(),
        "IMA-signed package should have file signatures"
    );

    let file_sig_len_before = pkg
        .metadata
        .signature
        .get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_FILESIGNATURE_LENGTH)?;

    let sha1_before = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA1)?
        .to_owned();

    let sha256_before = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA256)?
        .to_owned();

    // Clear OpenPGP signatures
    pkg.clear_signatures()?;

    // OpenPGP signature should be gone
    assert!(
        pkg.metadata
            .signature
            .get_entry_data_as_string_array(rpm::IndexSignatureTag::RPMSIGTAG_OPENPGP)
            .is_err(),
        "OpenPGP signatures should be cleared"
    );

    // File signatures (IMA) should be preserved
    let file_sigs_after: Vec<String> = pkg
        .metadata
        .signature
        .get_entry_data_as_string_array(rpm::IndexSignatureTag::RPMSIGTAG_FILESIGNATURES)?
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(
        file_sigs_before, file_sigs_after,
        "file signatures should be preserved after clearing OpenPGP signatures"
    );

    let file_sig_len_after = pkg
        .metadata
        .signature
        .get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_FILESIGNATURE_LENGTH)?;
    assert_eq!(
        file_sig_len_before, file_sig_len_after,
        "file signature length should be preserved after clearing OpenPGP signatures"
    );

    // Header digests should be preserved
    let sha1_after = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA1)?;
    assert_eq!(
        sha1_before, sha1_after,
        "SHA1 digest should be preserved after clearing OpenPGP signatures"
    );

    let sha256_after = pkg
        .metadata
        .signature
        .get_entry_data_as_string(rpm::IndexSignatureTag::RPMSIGTAG_SHA256)?;
    assert_eq!(
        sha256_before, sha256_after,
        "SHA256 digest should be preserved after clearing OpenPGP signatures"
    );

    // Digests should still be valid
    pkg.verify_digests()?;

    Ok(())
}

/// Test that decompress_payload() decompresses in-place and ALT digests verify
#[test]
fn test_decompress_payload_and_verify() -> Result<(), Box<dyn std::error::Error>> {
    let sig_content_length = |sig: &rpm::Header<rpm::IndexSignatureTag>| -> Option<u64> {
        sig.get_entry_data_as_u32(rpm::IndexSignatureTag::RPMSIGTAG_SIZE)
            .map(|v| v as u64)
            .or_else(|_| sig.get_entry_data_as_u64(rpm::IndexSignatureTag::RPMSIGTAG_LONGSIZE))
            .ok()
    };

    // --- v6 compressed fixture: full ALT digest coverage ---
    let mut pkg = rpm::Package::open(common::pkgs::v6::compressed::RPM_BASIC_ZSTD)?;

    // Before decompression: primary digests verify
    let report = pkg.check_digests()?;
    assert!(report.payload_sha256.is_verified());
    assert!(report.payload_sha512.is_verified());
    assert!(report.payload_sha3_256.is_verified());
    // ALT digests mismatch (payload is compressed, ALT is for uncompressed)
    assert!(report.payload_sha256_alt.is_mismatch());
    assert!(report.payload_sha512_alt.is_mismatch());
    assert!(report.payload_sha3_256_alt.is_mismatch());
    // Overall verification passes (primary set passes)
    assert!(report.is_ok());
    pkg.verify_digests()?;

    // Decompress
    pkg.decompress_payload()?;

    // After decompression: ALT digests verify, primary digests mismatch
    let report = pkg.check_digests()?;
    assert!(report.payload_sha256.is_mismatch());
    assert!(report.payload_sha256_alt.is_verified());
    assert!(report.payload_sha512_alt.is_verified());
    assert!(report.payload_sha3_256_alt.is_verified());
    // Overall verification passes (ALT set passes)
    assert!(report.is_ok());
    pkg.verify_digests()?;

    // Header digests should still be fine
    assert!(report.header_sha256.is_verified());
    assert!(report.header_sha3_256.is_verified());

    // Signature header should have been rebuilt: legacy header+payload tags stripped
    let sig = &pkg.metadata.signature;
    assert!(
        !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_MD5),
        "legacy MD5 tag should be stripped"
    );
    assert!(
        !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_PGP),
        "legacy PGP tag should be stripped"
    );
    assert!(
        !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_GPG),
        "legacy GPG tag should be stripped"
    );

    // --- v4 built package: content-length update ---
    let mut pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "decompress test")
        .using_config(rpm::BuildConfig::v4().compression(rpm::CompressionType::Zstd))
        .build()?;
    pkg.verify_digests()?;

    let content_length_before = sig_content_length(&pkg.metadata.signature);
    assert!(
        content_length_before.is_some(),
        "v4 package should have content-length"
    );

    pkg.decompress_payload()?;
    pkg.verify_digests()?;

    let header_bytes = pkg.header_bytes()?;
    let expected_content_length = header_bytes.len() as u64 + pkg.payload.len() as u64;
    let content_length_after = sig_content_length(&pkg.metadata.signature);
    assert_eq!(
        content_length_after,
        Some(expected_content_length),
        "content-length should reflect decompressed payload"
    );
    assert_ne!(
        content_length_after, content_length_before,
        "content-length should have changed after decompression"
    );

    Ok(())
}

/// Test decompress_payload() with different compression formats
#[test]
fn test_decompress_payload_formats() -> Result<(), Box<dyn std::error::Error>> {
    for path in [
        common::pkgs::v6::compressed::RPM_BASIC_ZSTD,
        common::pkgs::v6::compressed::RPM_BASIC_GZIP,
        common::pkgs::v6::compressed::RPM_BASIC_XZ,
    ] {
        let mut pkg = rpm::Package::open(path)?;
        pkg.verify_digests()?;
        pkg.decompress_payload()?;
        pkg.verify_digests()?;
    }
    Ok(())
}

/// Test that decompress_payload() is a no-op for uncompressed packages
#[test]
fn test_decompress_payload_noop_for_uncompressed() -> Result<(), Box<dyn std::error::Error>> {
    let mut pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC)?;
    let original_payload = pkg.payload.clone();

    pkg.decompress_payload()?;

    assert_eq!(pkg.payload, original_payload);
    pkg.verify_digests()?;

    Ok(())
}

mod tampering {
    use super::*;

    /// Test that tampering with the payload is detected by verify_digests
    #[test]
    fn test_tampered_payload_detected() -> Result<(), Box<dyn std::error::Error>> {
        // Signed v4 package
        let signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let mut pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "tamper test")
            .build_and_sign(&signer)?;

        // Sanity check: digests pass before tampering
        pkg.verify_digests()?;

        // Tamper with the payload
        if let Some(byte) = pkg.payload.last_mut() {
            *byte ^= 0xFF;
        }

        assert!(
            pkg.verify_digests().is_err(),
            "verify_digests should fail after payload tampering"
        );

        // check_digests should show which specific digests failed
        let report = pkg.check_digests()?;
        assert!(
            report.payload_sha256.is_mismatch(),
            "payload SHA-256 should mismatch"
        );
        // Header-only digests should still be fine
        assert!(report.header_sha1.is_verified());
        assert!(report.header_sha256.is_verified());
        // result() should return a descriptive error
        let err = report.result().unwrap_err();
        assert!(
            err.to_string().contains("mismatch"),
            "error should mention mismatch: {err}"
        );

        // Signature verification should also fail (it calls verify_digests internally)
        let verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
        assert!(
            pkg.verify_signature(&verifier).is_err(),
            "verify_signature should fail after payload tampering"
        );

        // Signed v6 package
        let signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
        let mut pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "tamper test")
            .using_config(rpm::BuildConfig::v6())
            .build_and_sign(&signer)?;

        pkg.verify_digests()?;

        if let Some(byte) = pkg.payload.last_mut() {
            *byte ^= 0xFF;
        }

        assert!(
            pkg.verify_digests().is_err(),
            "verify_digests should fail after payload tampering (v6)"
        );

        // v6 report should show payload digests failed but header digests ok
        let report = pkg.check_digests()?;
        assert!(!report.is_ok());
        assert!(report.payload_sha256.is_mismatch());
        assert!(report.header_sha256.is_verified());
        assert!(report.header_sha3_256.is_verified());

        Ok(())
    }

    /// Test that tampering with a decompressed payload is detected
    #[test]
    fn test_tampered_decompressed_payload_detected() -> Result<(), Box<dyn std::error::Error>> {
        let mut pkg = rpm::Package::open(common::pkgs::v6::compressed::RPM_BASIC_ZSTD)?;

        pkg.decompress_payload()?;
        pkg.verify_digests()?;

        // Tamper with the decompressed payload
        if let Some(byte) = pkg.payload.last_mut() {
            *byte ^= 0xFF;
        }

        // Both primary and ALT should mismatch
        let report = pkg.check_digests()?;
        assert!(report.payload_sha256.is_mismatch());
        assert!(report.payload_sha256_alt.is_mismatch());
        assert!(!report.is_ok());
        assert!(pkg.verify_digests().is_err());

        Ok(())
    }

    /// Test that tampering with the header is detected by signature verification
    #[test]
    fn test_tampered_header_detected() -> Result<(), Box<dyn std::error::Error>> {
        #[track_caller]
        fn tamper_header_and_verify(
            signing_key_path: &str,
            verification_key_path: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let signer = Signer::from_asc_file(signing_key_path)?;
            let verifier = Verifier::from_asc_file(verification_key_path)?;
            let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "tamper test")
                .build_and_sign(&signer)?;

            let offsets = pkg.metadata.get_package_segment_offsets();

            let mut bytes = Vec::new();
            pkg.write(&mut bytes)?;

            // Tamper with a byte near the end of the header's data store
            // This test is a little sensitive because of alignment / padding bytes where
            // corruption isn't necessarily detected.
            let tamper_offset = offsets.payload as usize - 1;
            bytes[tamper_offset] ^= 0xFF;

            let tampered_pkg = rpm::Package::parse(&mut bytes.as_slice())?;
            assert!(
                tampered_pkg.verify_signature(&verifier).is_err(),
                "verify_signature should fail after header tampering"
            );

            Ok(())
        }

        // v4
        tamper_header_and_verify(
            common::keys::v4::RSA_4K_PRIVATE,
            common::keys::v4::RSA_4K_PUBLIC,
        )?;

        // v6
        tamper_header_and_verify(
            common::keys::v6::ED25519_PRIVATE,
            common::keys::v6::ED25519_PUBLIC,
        )?;

        Ok(())
    }
}

mod signature_roundtrip {
    use super::*;

    /// Test that sign, write, read-back preserves both signature and digest validity
    #[test]
    fn test_signature_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        /// Build, sign, write, re-open, and verify both digests and signature.
        #[track_caller]
        fn roundtrip(
            signing_key_path: &str,
            verification_key_path: &str,
            out_name: &str,
        ) -> Result<(), Box<dyn std::error::Error>> {
            let signer = Signer::from_asc_file(signing_key_path)?;
            let pkg =
                rpm::PackageBuilder::new("roundtrip", "1.0.0", "MIT", "x86_64", "integrity test")
                    .build_and_sign(&signer)?;

            let out_file = Path::new(common::CARGO_OUT_DIR).join(out_name);
            pkg.write_file(&out_file)?;

            let reopened = rpm::Package::open(&out_file)?;
            reopened.verify_digests()?;

            let verifier = Verifier::from_asc_file(verification_key_path)?;
            reopened.verify_signature(&verifier)?;

            Ok(())
        }

        // v4
        roundtrip(
            common::keys::v4::RSA_4K_PRIVATE,
            common::keys::v4::RSA_4K_PUBLIC,
            "roundtrip_v4_rsa.rpm",
        )?;
        roundtrip(
            common::keys::v4::ED25519_PRIVATE,
            common::keys::v4::ED25519_PUBLIC,
            "roundtrip_v4_eddsa.rpm",
        )?;
        roundtrip(
            common::keys::v4::ECDSA_NISTP256_PRIVATE,
            common::keys::v4::ECDSA_NISTP256_PUBLIC,
            "roundtrip_v4_ecdsa.rpm",
        )?;

        // v6
        roundtrip(
            common::keys::v6::RSA_4K_PRIVATE,
            common::keys::v6::RSA_4K_PUBLIC,
            "roundtrip_v6_rsa.rpm",
        )?;
        roundtrip(
            common::keys::v6::ED25519_PRIVATE,
            common::keys::v6::ED25519_PUBLIC,
            "roundtrip_v6_eddsa.rpm",
        )?;
        #[cfg(feature = "signature-pgp")]
        roundtrip(
            common::keys::v6::MLDSA65_ED25519_PRIVATE,
            common::keys::v6::MLDSA65_ED25519_PUBLIC,
            "roundtrip_v6_mldsa.rpm",
        )?;

        Ok(())
    }

    /// Test that a multi-signed package survives a write-read roundtrip with both signatures intact
    #[test]
    fn test_multi_signature_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        // v4: sign with RSA then EdDSA, write, re-read, verify both
        let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let rsa_verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
        let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let ed_verifier = Verifier::from_asc_file(common::keys::v4::ED25519_PUBLIC)?;

        let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC)?;
        pkg.sign(&rsa_signer)?;
        pkg.sign(&ed_signer)?;
        assert_eq!(pkg.signatures()?.len(), 2);

        let out_file = Path::new(common::CARGO_OUT_DIR).join("multi_sig_roundtrip_v4.rpm");
        pkg.write_file(&out_file)?;

        let reopened = rpm::Package::open(&out_file)?;
        assert_eq!(reopened.signatures()?.len(), 2);
        reopened.verify_signature(&rsa_verifier)?;
        reopened.verify_signature(&ed_verifier)?;
        reopened.verify_digests()?;

        // v6: sign with RSA then EdDSA, write, re-read, verify both
        let v6_rsa_signer = Signer::from_asc_file(common::keys::v6::RSA_4K_PRIVATE)?;
        let v6_rsa_verifier = Verifier::from_asc_file(common::keys::v6::RSA_4K_PUBLIC)?;
        let v6_ed_signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
        let v6_ed_verifier = Verifier::from_asc_file(common::keys::v6::ED25519_PUBLIC)?;

        let mut pkg = rpm::Package::open(common::pkgs::v6::RPM_BASIC)?;
        pkg.sign(&v6_rsa_signer)?;
        pkg.sign(&v6_ed_signer)?;
        assert_eq!(pkg.signatures()?.len(), 2);

        let out_file = Path::new(common::CARGO_OUT_DIR).join("multi_sig_roundtrip_v6.rpm");
        pkg.write_file(&out_file)?;

        let reopened = rpm::Package::open(&out_file)?;
        assert_eq!(reopened.signatures()?.len(), 2);
        reopened.verify_signature(&v6_rsa_verifier)?;
        reopened.verify_signature(&v6_ed_verifier)?;
        reopened.verify_digests()?;

        Ok(())
    }
}

mod correct_signature_tags {
    use super::*;

    /// Test that signing with an RSA key produces a legacy RPMSIGTAG_RSA tag,
    /// and signing with an EdDSA/ECDSA key produces a legacy RPMSIGTAG_DSA tag.
    #[test]
    fn test_legacy_signature_tags() -> Result<(), Box<dyn std::error::Error>> {
        // RSA key -> RPMSIGTAG_RSA present, RPMSIGTAG_DSA absent
        let rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC)?;
        pkg.sign(&rsa_signer)?;

        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_RSA)
                .is_ok(),
            "RSA-signed package should have RPMSIGTAG_RSA"
        );
        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_DSA)
                .is_err(),
            "RSA-signed package should not have RPMSIGTAG_DSA"
        );

        // EdDSA key -> RPMSIGTAG_DSA present, RPMSIGTAG_RSA absent
        let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC)?;
        pkg.sign(&ed_signer)?;

        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_DSA)
                .is_ok(),
            "EdDSA-signed package should have RPMSIGTAG_DSA"
        );
        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_RSA)
                .is_err(),
            "EdDSA-signed package should not have RPMSIGTAG_RSA"
        );

        // ECDSA key -> RPMSIGTAG_DSA present, RPMSIGTAG_RSA absent
        let ecdsa_signer = Signer::from_asc_file(common::keys::v4::ECDSA_NISTP256_PRIVATE)?;
        let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC)?;
        pkg.sign(&ecdsa_signer)?;

        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_DSA)
                .is_ok(),
            "ECDSA-signed package should have RPMSIGTAG_DSA"
        );
        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_RSA)
                .is_err(),
            "ECDSA-signed package should not have RPMSIGTAG_RSA"
        );

        // Multi-signed (RSA + EdDSA): the last-added key type determines the legacy tag.
        // Only one of RPMSIGTAG_RSA or RPMSIGTAG_DSA should be present.
        let mut pkg = rpm::Package::open(common::pkgs::v4::RPM_BASIC)?;
        pkg.sign(&rsa_signer)?;
        pkg.sign(&ed_signer)?;

        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_DSA)
                .is_ok(),
            "last signature (EdDSA) should produce RPMSIGTAG_DSA"
        );
        assert!(
            pkg.metadata
                .signature
                .get_entry_data_as_binary(rpm::IndexSignatureTag::RPMSIGTAG_RSA)
                .is_err(),
            "RPMSIGTAG_RSA should not be present when last signature is EdDSA"
        );

        Ok(())
    }

    /// Test that building and signing a v4 package produces the expected signature header tags
    #[test]
    fn test_v4_signed_package_signature_tags() -> Result<(), Box<dyn std::error::Error>> {
        let signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "v4 sig tags test")
            .using_config(rpm::BuildConfig::v4())
            .build_and_sign(&signer)?;
        let sig = &pkg.metadata.signature;

        // v4 should have: SHA-1, SHA-256, size, reserved space, and legacy RSA
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SHA1),
            "v4 signed package should have RPMSIGTAG_SHA1"
        );
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SHA256),
            "v4 signed package should have RPMSIGTAG_SHA256"
        );
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SIZE),
            "v4 signed package should have RPMSIGTAG_SIZE"
        );
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_RESERVEDSPACE),
            "v4 signed package should have RPMSIGTAG_RESERVEDSPACE"
        );
        assert!(
            // we add SIGTAG_OPENPGP for v4 packages - it doesn't hurt and it simplifies the code
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_OPENPGP),
            "we expect to have RPMSIGTAG_OPENPGP"
        );
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_RSA),
            "v4 RSA-signed package should have RPMSIGTAG_RSA"
        );

        // v4 should NOT have: SHA3-256 or v6-style reserved tag
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SHA3_256),
            "v4 signed package should not have RPMSIGTAG_SHA3_256"
        );
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_RESERVED),
            "v4 signed package should not have RPMSIGTAG_RESERVED"
        );

        Ok(())
    }

    /// Test that building and signing a v6 package produces the expected signature header tags
    #[test]
    fn test_v6_signed_package_signature_tags() -> Result<(), Box<dyn std::error::Error>> {
        let signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "v6 sig tags test")
            .using_config(rpm::BuildConfig::v6())
            .build_and_sign(&signer)?;
        let sig = &pkg.metadata.signature;

        // v6 should have: SHA-256, SHA3-256, v6 reserved tag, and OpenPGP
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SHA256),
            "v6 signed package should have RPMSIGTAG_SHA256"
        );
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SHA3_256),
            "v6 signed package should have RPMSIGTAG_SHA3_256"
        );
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_RESERVED),
            "v6 signed package should have RPMSIGTAG_RESERVED"
        );
        assert!(
            sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_OPENPGP),
            "v6 signed package should have RPMSIGTAG_OPENPGP"
        );

        // v6 should NOT have: SHA-1, size, v4 reserved space, or legacy RSA/DSA tags
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SHA1),
            "v6 signed package should not have RPMSIGTAG_SHA1"
        );
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_SIZE),
            "v6 signed package should not have RPMSIGTAG_SIZE"
        );
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_LONGSIZE),
            "v6 signed package should not have RPMSIGTAG_LONGSIZE"
        );
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_RESERVEDSPACE),
            "v6 signed package should not have RPMSIGTAG_RESERVEDSPACE"
        );
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_RSA),
            "v6 signed package should not have RPMSIGTAG_RSA"
        );
        assert!(
            !sig.entry_is_present(rpm::IndexSignatureTag::RPMSIGTAG_DSA),
            "v6 signed package should not have RPMSIGTAG_DSA"
        );

        Ok(())
    }
}

mod in_place_signing {
    use super::*;

    /// Resign a package in-place with the *same* key to verify deduplication.
    #[test]
    fn test_resign_in_place_same_key() -> Result<(), Box<dyn std::error::Error>> {
        resign_in_place_and_verify(
            common::pkgs::v4::RPM_BASIC_RSA_SIGNED,
            &fs::read(common::keys::v4::RSA_4K_PRIVATE)?,
            &[&fs::read(common::keys::v4::RSA_4K_PUBLIC)?],
            1,
            "resign_in_place_same_key.rpm",
        )?;

        Ok(())
    }

    /// Resign a package in-place with a different key and verify the result.
    /// Checks file size is unchanged, header+payload untouched, both the
    /// original and new signatures verify, and the signature count is 2.
    #[test]
    fn test_resign_in_place_different_keys() -> Result<(), Box<dyn std::error::Error>> {
        // v4: RSA-signed package, add EdDSA signature
        resign_in_place_and_verify(
            common::pkgs::v4::RPM_BASIC_RSA_SIGNED,
            &fs::read(common::keys::v4::ED25519_PRIVATE)?,
            &[
                &fs::read(common::keys::v4::RSA_4K_PUBLIC)?,
                &fs::read(common::keys::v4::ED25519_PUBLIC)?,
            ],
            2,
            "resign_in_place_v4.rpm",
        )?;

        // v6: RSA-signed package, add EdDSA signature
        resign_in_place_and_verify(
            common::pkgs::v6::RPM_BASIC_RSA_SIGNED,
            &fs::read(common::keys::v6::ED25519_PRIVATE)?,
            &[
                &fs::read(common::keys::v6::RSA_4K_PUBLIC)?,
                &fs::read(common::keys::v6::ED25519_PUBLIC)?,
            ],
            2,
            "resign_in_place_v6.rpm",
        )?;

        Ok(())
    }

    /// Sign an unsigned package in-place.
    #[test]
    fn test_resign_in_place_unsigned() -> Result<(), Box<dyn std::error::Error>> {
        // v4: unsigned package, sign with EdDSA
        resign_in_place_and_verify(
            common::pkgs::v4::RPM_BASIC,
            &fs::read(common::keys::v4::ED25519_PRIVATE)?,
            &[&fs::read(common::keys::v4::ED25519_PUBLIC)?],
            1,
            "resign_in_place_unsigned_v4.rpm",
        )?;

        // v6: unsigned package, sign with EdDSA
        resign_in_place_and_verify(
            common::pkgs::v6::RPM_BASIC,
            &fs::read(common::keys::v6::ED25519_PRIVATE)?,
            &[&fs::read(common::keys::v6::ED25519_PUBLIC)?],
            1,
            "resign_in_place_unsigned_v6.rpm",
        )?;

        Ok(())
    }

    /// Resigning in-place when the new signature is too large for the reserved space
    /// should return InsufficientReservedSpace.
    #[test]
    fn test_resign_in_place_insufficient_space() -> Result<(), Box<dyn std::error::Error>> {
        // Build a signed package, then strip its reserved space so there is no room
        // for a larger signature.
        let signer = Signer::from_asc_bytes(&fs::read(common::keys::v4::ED25519_PRIVATE)?)?;
        let mut pkg =
            rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "no reserved space")
                .build_and_sign(&signer)?;

        // Rebuild the signature header with zero reserved space
        let compact_sig = rpm::SignatureHeaderBuilder::from_existing(&pkg.metadata.signature)?
            .reserved_space(Some(0))
            .build()?;
        pkg.metadata.signature = compact_sig;

        let out = Path::new(common::CARGO_OUT_DIR).join("resign_in_place_no_space.rpm");
        pkg.write_file(&out)?;

        // Now try to resign in-place with a much larger key (RSA 4096).
        // The RSA signature is ~500 bytes larger than EdDSA, so it won't fit.
        let big_signer = Signer::from_asc_bytes(&fs::read(common::keys::v4::RSA_4K_PRIVATE)?)?;
        let result = rpm::Package::resign_in_place(&out, &big_signer);

        assert!(
            matches!(result, Err(rpm::Error::InsufficientReservedSpace { .. })),
            "expected InsufficientReservedSpace error, got: {result:?}"
        );

        Ok(())
    }

    /// Resigning in-place a package that has no reserved space tag at all
    /// should return InsufficientReservedSpace.
    #[test]
    fn test_resign_in_place_no_reserved_tag() -> Result<(), Box<dyn std::error::Error>> {
        let signer = Signer::from_asc_bytes(&fs::read(common::keys::v4::ED25519_PRIVATE)?)?;
        let pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "no reserved tag")
            .using_config(rpm::BuildConfig::default().reserved_space(None))
            .build_and_sign(&signer)?;

        let out = Path::new(common::CARGO_OUT_DIR).join("resign_in_place_no_reserved_tag.rpm");
        pkg.write_file(&out)?;

        let result = rpm::Package::resign_in_place(&out, &signer);
        assert!(
            matches!(result, Err(rpm::Error::InsufficientReservedSpace { .. })),
            "expected InsufficientReservedSpace error, got: {result:?}"
        );

        Ok(())
    }

    /// Clear signatures from a signed on-disk package in-place.
    /// File size must be unchanged, digests must still verify, and no signatures remain.
    /// Then re-sign in-place to verify the reclaimed reserved space is usable.
    #[test]
    fn test_clear_signatures_in_place() -> Result<(), Box<dyn std::error::Error>> {
        // Start with signed v4 package
        let out = Path::new(common::CARGO_OUT_DIR).join("clear_sig_in_place.rpm");
        fs::copy(common::pkgs::v4::RPM_BASIC_RSA_SIGNED, &out)?;
        let original_size = fs::metadata(&out)?.len();

        // Clear signatures in-place
        rpm::Package::clear_signatures_in_place(&out)?;
        assert_eq!(
            fs::metadata(&out)?.len(),
            original_size,
            "file size must not change"
        );

        // Header and payload must be byte-identical
        let original_bytes = fs::read(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?;
        let cleared_bytes = fs::read(&out)?;
        let orig_meta = rpm::PackageMetadata::open(common::pkgs::v4::RPM_BASIC_RSA_SIGNED)?;
        let orig_offsets = orig_meta.get_package_segment_offsets();
        assert_eq!(
            &original_bytes[orig_offsets.header as usize..],
            &cleared_bytes[orig_offsets.header as usize..],
            "header and payload must be untouched"
        );

        // Digests should pass, signatures should be gone
        let pkg = rpm::Package::open(&out)?;
        pkg.verify_digests()?;
        assert!(pkg.signatures()?.is_empty(), "expected no signatures");

        let verifier = Verifier::from_asc_file(common::keys::v4::RSA_4K_PUBLIC)?;
        assert!(
            matches!(
                pkg.verify_signature(verifier),
                Err(rpm::Error::NoSignatureFound)
            ),
            "verification should fail with NoSignatureFound"
        );

        // Re-sign in-place to verify the reclaimed reserved space is usable
        let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        rpm::Package::resign_in_place(&out, &ed_signer)?;
        assert_eq!(
            fs::metadata(&out)?.len(),
            original_size,
            "file size must not change after re-signing"
        );

        let pkg = rpm::Package::open(&out)?;
        pkg.verify_digests()?;
        let ed_verifier = Verifier::from_asc_file(common::keys::v4::ED25519_PUBLIC)?;
        pkg.verify_signature(&ed_verifier)?;
        assert_eq!(pkg.signatures()?.len(), 1);

        Ok(())
    }

    /// Apply two small signatures sequentially in-place and verify both are present,
    /// the file size is unchanged, and header+payload are untouched.
    #[test]
    fn test_apply_multiple_signatures_in_place() -> Result<(), Box<dyn std::error::Error>> {
        let out = Path::new(common::CARGO_OUT_DIR).join("apply_multi_sig_in_place.rpm");
        fs::copy(common::pkgs::v4::RPM_BASIC, &out)?;
        let original_size = fs::metadata(&out)?.len();

        // Extract header bytes and sign externally with EdDSA
        let ed_signer = Signer::from_asc_file(common::keys::v4::ED25519_PRIVATE)?;
        let metadata = rpm::PackageMetadata::open(&out)?;
        let header_bytes = metadata.header_bytes()?;
        let ed_sig =
            rpm::signature::Signing::sign(&ed_signer, header_bytes.as_slice(), test_timestamp())?;

        // First in-place apply
        rpm::Package::apply_signature_in_place(&out, ed_sig)?;
        assert_eq!(
            fs::metadata(&out)?.len(),
            original_size,
            "file size changed after first apply"
        );

        // Extract header bytes again (unchanged) and sign with ECDSA
        let ecdsa_signer = Signer::from_asc_file(common::keys::v4::ECDSA_NISTP256_PRIVATE)?;
        let metadata = rpm::PackageMetadata::open(&out)?;
        let header_bytes = metadata.header_bytes()?;
        let ecdsa_sig = rpm::signature::Signing::sign(
            &ecdsa_signer,
            header_bytes.as_slice(),
            test_timestamp(),
        )?;

        // Second in-place apply
        rpm::Package::apply_signature_in_place(&out, ecdsa_sig)?;
        assert_eq!(
            fs::metadata(&out)?.len(),
            original_size,
            "file size changed after second apply"
        );

        // Header and payload must be byte-identical to original
        let original_bytes = fs::read(common::pkgs::v4::RPM_BASIC)?;
        let resigned_bytes = fs::read(&out)?;
        let orig_meta = rpm::PackageMetadata::open(common::pkgs::v4::RPM_BASIC)?;
        let orig_offsets = orig_meta.get_package_segment_offsets();
        assert_eq!(
            &original_bytes[orig_offsets.header as usize..],
            &resigned_bytes[orig_offsets.header as usize..],
            "header and payload must be untouched"
        );

        // Both signatures must verify
        let pkg = rpm::Package::open(&out)?;
        pkg.verify_digests()?;

        let ed_verifier = Verifier::from_asc_file(common::keys::v4::ED25519_PUBLIC)?;
        pkg.verify_signature(&ed_verifier)?;

        let ecdsa_verifier = Verifier::from_asc_file(common::keys::v4::ECDSA_NISTP256_PUBLIC)?;
        pkg.verify_signature(&ecdsa_verifier)?;

        assert_eq!(pkg.signatures()?.len(), 2, "expected 2 signatures");

        Ok(())
    }

    #[track_caller]
    fn resign_in_place_and_verify(
        src: &str,
        signing_key: &[u8],
        verification_keys: &[&[u8]],
        expected_sig_count: usize,
        out_name: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let out = Path::new(common::CARGO_OUT_DIR).join(out_name);
        fs::copy(src, &out)?;

        let original_bytes = fs::read(src)?;

        let signer = Signer::from_asc_bytes(signing_key)?;
        rpm::Package::resign_in_place(&out, &signer)?;

        // File size must be unchanged (in-place means no shifting)
        let resigned_bytes = fs::read(&out)?;
        assert_eq!(
            original_bytes.len(),
            resigned_bytes.len(),
            "in-place resign must not change file size"
        );

        // Main header and payload must be byte-identical
        let orig_meta = rpm::PackageMetadata::open(src)?;
        let orig_offsets = orig_meta.get_package_segment_offsets();
        assert_eq!(
            &original_bytes[orig_offsets.header as usize..],
            &resigned_bytes[orig_offsets.header as usize..],
            "main header and payload must be untouched"
        );

        let package = rpm::Package::open(&out)?;
        package.verify_digests()?;

        // Each verification key must verify
        for key in verification_keys {
            let verifier = Verifier::from_asc_bytes(key)?;
            package.verify_signature(&verifier)?;
        }

        let sigs = package.signatures()?;
        assert_eq!(
            sigs.len(),
            expected_sig_count,
            "expected {expected_sig_count} signature(s), got {}",
            sigs.len()
        );

        Ok(())
    }
}
