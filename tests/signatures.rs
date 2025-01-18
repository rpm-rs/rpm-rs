use std::path::Path;

use chrono::TimeZone;

use rpm::{
    self,
    signature::pgp::{Signer, Verifier},
};

mod common;

/// Resign an already-signed package with new keys, and verify it with the new keys
#[test]
fn test_rpm_file_signatures_resign() -> Result<(), Box<dyn std::error::Error>> {
    let pkg_path = common::rpm_basic_pkg_path_rsa_signed();

    // test RSA
    let (signing_key, verification_key) = common::load_rsa_keys();
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &signing_key,
        None,
        &verification_key,
        "rsa_resigned_pkg.rpm",
    )?;

    // test RSA - with secret key protected by a passphrase
    let (signing_key, verification_key) = common::load_protected_rsa_keys();
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &signing_key,
        Some(common::test_protected_private_key_passphrase()),
        &verification_key,
        "rsa_resigned_pkg.rpm",
    )?;

    // test EdDSA
    let (signing_key, verification_key) = common::load_eddsa_keys();
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &signing_key,
        None,
        &verification_key,
        "eddsa_resigned_pkg.rpm",
    )?;

    let pkg_path = common::rpm_basic_pkg_path_eddsa_signed();

    // test RSA
    let (signing_key, verification_key) = common::load_rsa_keys();
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &signing_key,
        None,
        &verification_key,
        "rsa_resigned_pkg.rpm",
    )?;

    // test RSA - with secret key protected by a passphrase
    let (signing_key, verification_key) = common::load_protected_rsa_keys();
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &signing_key,
        Some(common::test_protected_private_key_passphrase()),
        &verification_key,
        "rsa_resigned_pkg.rpm",
    )?;

    // test EdDSA
    let (signing_key, verification_key) = common::load_eddsa_keys();
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &signing_key,
        None,
        &verification_key,
        "eddsa_resigned_pkg.rpm",
    )?;

    // test ECDSA
    let (signing_key, verification_key) = common::load_ecdsa_keys();
    resign_and_verify_with_keys(
        pkg_path.as_ref(),
        &signing_key,
        None,
        &verification_key,
        "ecdsa_resigned_pkg.rpm",
    )
}

// @todo: we could really just use a fixture for this, better than rebuilding?
/// Test verifying the signature of a package that has been signed
#[test]
fn parse_externally_signed_rpm_and_verify() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    // test RSA
    let (signing_key, verification_key) = common::load_rsa_keys();
    build_parse_sign_and_verify(&signing_key, &verification_key, "rsa_signed_pkg.rpm")?;

    // test EdDSA
    let (signing_key, verification_key) = common::load_eddsa_keys();
    build_parse_sign_and_verify(&signing_key, &verification_key, "eddsa_signed_pkg.rpm")?;

    // test ECDSA
    let (signing_key, verification_key) = common::load_ecdsa_keys();
    build_parse_sign_and_verify(&signing_key, &verification_key, "ecdsa_signed_pkg.rpm")?;

    Ok(())
}

/// Test an attempt to verify the signature of a package that is not signed
#[test]
fn test_verify_unsigned_package() -> Result<(), Box<dyn std::error::Error>> {
    let pkg = rpm::Package::open(common::rpm_empty_path())?;

    // test RSA
    let verification_key = common::rsa_public_key();
    let verifier = Verifier::load_from_asc_bytes(verification_key.as_ref())?;
    assert!(matches!(
        pkg.verify_signature(verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    // test EdDSA
    let verification_key = common::eddsa_public_key();
    let verifier = Verifier::load_from_asc_bytes(verification_key.as_ref())?;
    assert!(matches!(
        pkg.verify_signature(verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    // test ECDSA
    let verification_key = common::ecdsa_public_key();
    let verifier = Verifier::load_from_asc_bytes(verification_key.as_ref())?;
    assert!(matches!(
        pkg.verify_signature(verifier),
        Err(rpm::Error::NoSignatureFound)
    ));

    Ok(())
}

/// Test an attempt to verify the signature of a package using the wrong key type
#[test]
fn test_verify_package_with_wrong_key_type() -> Result<(), Box<dyn std::error::Error>> {
    let rsa_signer = Signer::load_from_asc_bytes(&common::rsa_private_key())?;
    let rsa_verifier = Verifier::load_from_asc_bytes(&common::rsa_public_key())?;
    let rsa_pkg = rpm::PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "an empty package")
        .build_and_sign(&rsa_signer)?;

    let eddsa_signer = Signer::load_from_asc_bytes(&common::eddsa_private_key())?;
    let eddsa_verifier = Verifier::load_from_asc_bytes(&common::eddsa_public_key())?;
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

    Ok(())
}

#[track_caller]
fn resign_and_verify_with_keys(
    pkg_path: &Path,
    signing_key: &[u8],
    signing_key_passphrase: Option<String>,
    verification_key: &[u8],
    pkg_out_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut package = rpm::Package::open(pkg_path)?;
    let mut signer = Signer::load_from_asc_bytes(signing_key)?;
    if let Some(passphrase) = signing_key_passphrase {
        signer = signer.with_key_passphrase(passphrase);
    }
    package.sign_with_timestamp(&signer, 1_600_000_000)?;

    let out_file = common::cargo_out_dir().join(pkg_out_path.as_ref());
    package.write_file(&out_file)?;

    let package = rpm::Package::open(&out_file)?;
    let verifier = Verifier::load_from_asc_bytes(verification_key).unwrap();
    package
        .verify_signature(&verifier)
        .expect("failed to verify signature");
    Ok(())
}

#[track_caller]
fn build_parse_sign_and_verify(
    signing_key: &[u8],
    verification_key: &[u8],
    pkg_out_path: impl AsRef<Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();

    let cargo_file = common::cargo_manifest_dir().join("Cargo.toml");

    let mut pkg = rpm::PackageBuilder::new(
        "roundtrip",
        "1.0.0",
        "MIT",
        "x86_64",
        "spins round and round",
    )
    .compression(rpm::CompressionType::Gzip)
    .with_file(
        cargo_file.to_str().unwrap(),
        rpm::FileOptions::new("/etc/foobar/hugo/bazz.toml")
            .mode(rpm::FileMode::regular(0o777))
            .is_config(),
    )?
    .with_file(
        cargo_file.to_str().unwrap(),
        rpm::FileOptions::new("/etc/Cargo.toml"),
    )?
    .epoch(3)
    .pre_install_script("echo preinst")
    .add_changelog_entry("you", "yada yada", chrono::Utc.timestamp_opt(1, 0).unwrap())
    .requires(rpm::Dependency::any("rpm-sign".to_string()))
    .build()?;

    assert_eq!(3, pkg.metadata.get_epoch()?);

    // sign
    let signer: Signer = Signer::load_from_asc_bytes(signing_key)?;
    pkg.sign(signer)?;

    let out_file = common::cargo_out_dir().join(pkg_out_path.as_ref());
    pkg.write_file(&out_file)?;

    // verify
    let package = rpm::Package::open(&out_file)?;
    let verifier = Verifier::load_from_asc_bytes(verification_key)?;
    package.verify_signature(verifier)?;

    Ok(())
}
