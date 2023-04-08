#![allow(dead_code)]

pub fn test_protected_private_key_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/signing_keys/secret_rsa4096_protected.asc")
}

pub fn test_protected_public_key_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/signing_keys/public_rsa4096_protected.asc")
}

pub fn test_protected_private_key_passphrase() -> String {
    "thisisN0Tasecuredpassphrase".to_owned()
}

pub fn rpm_empty_source_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/SRPMS/rpm-empty-0-0.src.rpm")
}

pub fn rpm_empty_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/RPMS/x86_64/rpm-empty-0-0.x86_64.rpm")
}

pub fn rpm_basic_pkg_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/RPMS/noarch/rpm-basic-2.3.4-5.el9.noarch.rpm")
}

pub fn rpm_basic_pkg_path_rsa_signed() -> std::path::PathBuf {
    cargo_manifest_dir()
        .join("tests/assets/RPMS/signed/noarch/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm")
}

pub fn rpm_basic_pkg_path_eddsa_signed() -> std::path::PathBuf {
    cargo_manifest_dir()
        .join("tests/assets/RPMS/signed/noarch/rpm-basic-with-ed25519-2.3.4-5.el9.noarch.rpm")
}

pub fn rpm_basic_source_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/SRPMS/rpm-basic-2.3.4-5.el9.src.rpm")
}

pub fn rpm_basic_source_path_eddsa_signed() -> std::path::PathBuf {
    cargo_manifest_dir()
        .join("tests/assets/SRPMS/signed/rpm-basic-with-ed25517-2.3.4-5.el9.src.rpm")
}

pub fn rpm_basic_source_path_rsa_signed() -> std::path::PathBuf {
    cargo_manifest_dir()
        .join("tests/assets/SRPMS/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.src.rpm")
}

pub fn rpm_with_patch_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/RPMS/noarch/rpm-with-patch-1.0-0.noarch.rpm")
}

pub fn rpm_file_attrs_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("tests/assets/RPMS/noarch/rpm-file-attrs-1.0-1.noarch.rpm")
}

pub fn cargo_manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

pub fn cargo_out_dir() -> std::path::PathBuf {
    cargo_manifest_dir().join("target")
}

pub fn load_rsa_keys() -> (Vec<u8>, Vec<u8>) {
    (rsa_private_key(), rsa_public_key())
}

pub fn rsa_private_key() -> Vec<u8> {
    let private_key = cargo_manifest_dir().join("tests/assets/signing_keys/secret_rsa4096.asc");
    std::fs::read(private_key).unwrap()
}

pub fn rsa_public_key() -> Vec<u8> {
    let public_key = cargo_manifest_dir().join("tests/assets/signing_keys/public_rsa4096.asc");
    std::fs::read(public_key).unwrap()
}

pub fn load_protected_rsa_keys() -> (Vec<u8>, Vec<u8>) {
    let signing_key = include_bytes!("../tests/assets/signing_keys/secret_rsa4096_protected.asc");
    let verification_key =
        include_bytes!("../tests/assets/signing_keys/public_rsa4096_protected.asc");
    (signing_key.to_vec(), verification_key.to_vec())
}

pub fn eddsa_private_key() -> Vec<u8> {
    let private_key = cargo_manifest_dir().join("tests/assets/signing_keys/secret_ed25519.asc");
    std::fs::read(private_key).unwrap()
}

pub fn eddsa_public_key() -> Vec<u8> {
    let public_key = cargo_manifest_dir().join("tests/assets/signing_keys/public_ed25519.asc");
    std::fs::read(public_key).unwrap()
}

pub fn load_eddsa_keys() -> (Vec<u8>, Vec<u8>) {
    (eddsa_private_key(), eddsa_public_key())
}

pub fn ecdsa_private_key() -> Vec<u8> {
    let private_key =
        cargo_manifest_dir().join("test_assets/fixture_packages/signing_keys/secret_nistp256.asc");
    std::fs::read(private_key).unwrap()
}

pub fn ecdsa_public_key() -> Vec<u8> {
    let public_key =
        cargo_manifest_dir().join("test_assets/fixture_packages/signing_keys/public_nistp256.asc");
    std::fs::read(public_key).unwrap()
}

pub fn load_ecdsa_keys() -> (Vec<u8>, Vec<u8>) {
    (ecdsa_private_key(), ecdsa_public_key())
}
