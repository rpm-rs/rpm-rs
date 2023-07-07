use rpm::signature::pgp::{Signer, Verifier};
use rpm::*;

mod common;

#[test]
fn test_rpm_file_signatures_resign() -> Result<(), Box<dyn std::error::Error>> {
    let rpm_file_path = common::rpm_ima_signed_file_path();
    let mut package = RPMPackage::open(rpm_file_path)?;

    let private_key_content = std::fs::read(common::test_private_key_path())?;
    let signer = Signer::load_from_asc_bytes(&private_key_content)?;

    package.sign_with_timestamp(&signer, 1_600_000_000)?;

    let public_key_content = std::fs::read(common::test_public_key_path())?;
    let verifier = Verifier::load_from_asc_bytes(&public_key_content).unwrap();
    package
        .verify_signature(&verifier)
        .expect("failed to verify signature");
    Ok(())
}

#[test]
fn parse_externally_signed_rpm_and_verify() -> Result<(), Box<dyn std::error::Error>> {
    let _ = env_logger::try_init();
    let (signing_key, verification_key) = common::load_asc_keys();

    let cargo_file = common::cargo_manifest_dir().join("Cargo.toml");
    let out_file = common::cargo_out_dir().join("roundtrip.rpm");

    {
        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())?;

        let mut f = std::fs::File::create(&out_file)?;
        let mut pkg = RPMBuilder::new(
            "roundtrip",
            "1.0.0",
            "MIT",
            "x86_64",
            "spins round and round",
        )
        .compression(CompressionType::Gzip)
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/foobar/hugo/bazz.toml")
                .mode(FileMode::regular(0o777))
                .is_config(),
        )?
        .with_file(
            cargo_file.to_str().unwrap(),
            RPMFileOptions::new("/etc/Cargo.toml"),
        )?
        .epoch(3)
        .pre_install_script("echo preinst")
        .add_changelog_entry("you", "yada yada", 1)
        .requires(Dependency::any("rpm-sign".to_string()))
        .build_and_sign(&signer)?;

        pkg.write(&mut f)?;
        let epoch = pkg.metadata.get_epoch()?;
        assert_eq!(3, epoch);
    }

    // verify
    {
        let out_file = std::fs::File::open(&out_file).expect("should be able to open rpm file");
        let mut buf_reader = std::io::BufReader::new(out_file);
        let mut package = RPMPackage::parse(&mut buf_reader)?;

        let verifier = Verifier::load_from_asc_bytes(verification_key.as_ref())?;

        package.verify_signature(verifier)?;
    }

    Ok(())
}
