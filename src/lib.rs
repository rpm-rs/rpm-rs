//! # rpm-rs
//!
//! A pure Rust library for parsing and creating RPM files.
//!
//! ## Features
//!
//! - Easy to use API
//! - Pure Rust for easy integration in larger projects
//! - Independence of spec files - pure programmatic interface for packaging
//! - Compatibility from Enterprise Linux 8 (RHEL, Alma, Rocky, CentOS Stream) to Fedora
//!
//! All supported compression types are behind feature flags. All of them except bzip2 are enabled
//! by default. They can be disabled if these compression algorithms are unused.
//!
//! ## Examples
//!
//! ### Read package and access metadata
//!
//! #### Check basic metadata
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pkg = rpm::Package::open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//!
//! let name = pkg.metadata.get_name()?;
//! let version = pkg.metadata.get_version()?;
//! let release = pkg.metadata.get_release()?;
//! let arch = pkg.metadata.get_arch()?;
//!
//! println!("{}-{}-{}.{}", name, version, release, arch);
//!
//! for changelog in pkg.metadata.get_changelog_entries()? {
//!     println!("{}\n{}\n", changelog.name, changelog.description);
//! }
//!
//! // `PackageMetadata` provides direct access to Package metadata without reading the payload
//! // as `Package` does. If you don't need the payload, it is more convenient and efficient to use.
//!
//! let metadata = rpm::PackageMetadata::open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//!
//! assert_eq!(metadata.get_name()?, pkg.metadata.get_name()?);
//! assert_eq!(metadata.get_version()?, pkg.metadata.get_version()?);
//!
//! for changelog in metadata.get_changelog_entries()? {
//!     println!("{}\n{}\n", changelog.name, changelog.description);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! #### Query dependencies
//!
//! ```
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pkg = rpm::Package::open("tests/assets/RPMS/v6/rpm-rich-deps-1.0-1.noarch.rpm")?;
//!
//! for dep in pkg.metadata.get_requires()? {
//!     println!("{dep}");
//!     // e.g. "glibc >= 2.17", "bash", "rpm-libs = 4.14.3-1.el8"
//! }
//!
//! // Other dependency types: get_provides(), get_conflicts(), get_obsoletes(),
//! // get_recommends(), get_suggests(), get_enhances(), get_supplements()
//! # Ok(())
//! # }
//! ```
//!
//! #### Inspect package signatures
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::SignatureVersion;
//!
//! let pkg = rpm::Package::open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")?;
//!
//! for sig in pkg.signatures()? {
//!     println!("Version: {:?}", sig.version());
//!     println!("Algorithm: {:?}", sig.algorithm());
//!     println!("Hash algorithm: {:?}", sig.hash_algorithm());
//!     if let Some(fp) = sig.fingerprint() {
//!         println!("Fingerprint: {}", fp);
//!     }
//!     if let Some(kid) = sig.key_id() {
//!         println!("Key ID: {}", kid);
//!     }
//!     if sig.version() == SignatureVersion::V6 {
//!         println!("This is a v6 signature");
//!     }
//! }
//!
//! // Raw OpenPGP signature packets are also available
//! for raw_sig in pkg.raw_signatures()? {
//!     println!("Signature packet: {} bytes", raw_sig.len());
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! #### List and read file contents
//!
//! ```
//! # #[cfg(feature = "payload")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let pkg = rpm::Package::open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//!
//! // List file metadata without reading the payload
//! for entry in pkg.metadata.get_file_entries()? {
//!     println!("{} ({} bytes, {:o})", entry.path().display(), entry.size(), entry.permissions());
//! }
//!
//! // Iterate over file contents (decompresses the payload)
//! for entry in pkg.files()? {
//!     let file = entry?;
//!     println!("{}: {} bytes", file.metadata.path().display(), file.content.len());
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "payload"))]
//! # fn main() {}
//! ```
//!
//! #### Extract package contents to disk
//!
//! Extract all files, directories, and symlinks from the package payload into a target directory -
//! files are written relative to the target directory (not installed to their absolute paths).
//!
//! ```no_run
//! # #[cfg(feature = "payload")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // The directory must not already exist and its parent must exist.
//! let pkg = rpm::Package::open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//! pkg.extract("./extracted-pkg")?;
//! // Creates ./extracted-pkg/ with the package's file tree inside it
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "payload"))]
//! # fn main() {}
//! ```
//!
//! ### Verify signatures
//!
//! #### Verify using a keyring with multiple certificates
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::Verifier;
//!
//! // Keyring files containing multiple OpenPGP certificates are supported.
//! // The verifier will try each certificate until it finds one that matches.
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.asc")?;
//!
//! let pkg = rpm::Package::open("./tests/assets/RPMS/v4/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm")?;
//! pkg.verify_signature(verifier)?;
//!
//! // You can also narrow down to a specific certificate by fingerprint:
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.asc")?
//!     .with_key(&hex::decode("d996aedc0d64d1e621b95ad2e964f9fb30d073b5")?)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! #### Check individual signatures and digests
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::Verifier;
//!
//! let pkg = rpm::Package::open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")?;
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc")?;
//!
//! let report = pkg.check_signatures(verifier)?;
//!
//! // Check overall pass/fail
//! assert!(report.is_ok());
//!
//! // Or inspect individual digest results
//! if report.digests.header_sha256.is_verified() {
//!     println!("SHA-256 header digest: OK");
//! }
//! match &report.digests.header_sha3_256 {
//!     rpm::DigestStatus::Verified => println!("SHA3-256 header digest: OK"),
//!     rpm::DigestStatus::NotPresent => println!("SHA3-256 header digest: not present"),
//!     rpm::DigestStatus::NotChecked => println!("SHA3-256 header digest: not checked"),
//!     rpm::DigestStatus::Mismatch { expected, actual } => {
//!         println!("SHA3-256 header digest: MISMATCH (expected {expected}, got {actual})");
//!     }
//! }
//!
//! // Inspect each signature with its metadata and whether it was verified (only one signature must verify to "pass")
//! for sig in &report.signatures {
//!     let key_ref = sig.info.fingerprint()
//!         .or(sig.info.key_id())
//!         .unwrap_or("unknown");
//!     match sig.result() {
//!         Ok(()) => println!("Signature {key_ref}: OK"),
//!         Err(err) => println!("Signature {key_ref}: FAILED: {err}"),
//!     }
//! }
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Sign packages
//!
//! #### Sign an existing package and verify package signature
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::{Signer, Verifier};
//!
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.secret")?;
//! let verifier = Verifier::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc")?;
//!
//! let mut pkg = rpm::Package::open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")?;
//! pkg.sign(signer)?;
//! # let dir = tempfile::tempdir()?;
//! # let sig_path = dir.path().join("with_signature.rpm");
//! # pkg.write_to(&sig_path)?;
//! # let pkg = rpm::Package::open(&sig_path)?;
//! pkg.verify_signature(verifier)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! #### Sign with a specific subkey
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::Signer;
//!
//! let subkey_fingerprint = hex::decode("715619ae2365d909eb991ff97a509cd76a0bac92f0e17c1c2525812852cedfc5")?;
//!
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret")?
//!     .with_signing_key(&subkey_fingerprint)?;
//!
//! let mut pkg = rpm::Package::open("./tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//! pkg.sign(signer)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Remote / HSM signing
//!
//! There are two approaches for signing with keys that are not directly
//! accessible as local key files (e.g. HSMs, remote signing services, or
//! cloud KMS):
//!
//! **Option 1: Implement the [`signature::Signing`] trait.** If the signing
//! call can be made synchronously (even over a network round-trip), implement
//! the trait and pass it to the standard [`Package::sign`] or
//! [`Package::resign_in_place`] methods. [`BasicKeySigner`](signature::pgp::BasicKeySigner)
//! bridges any [`pgp::SigningKey`] to the rpm-rs `Signing` trait, and
//! the [`pgp::adapter`] module provides ready-made `SigningKey`
//! implementations ([`RsaSigner`](pgp::adapter::RsaSigner),
//! [`EcdsaSigner`](pgp::adapter::EcdsaSigner)) that wrap any Rust Crypto
//! [`signature::Signer`] — making it straightforward to plug in key
//! backends such as PKCS#11 tokens or cloud KMS clients. See
//! `examples/hsm-signing.rs` for a complete example.
//!
//! **Option 2: Split extract / sign / apply.** If signing is fully
//! asynchronous or out-of-band (different process, different machine, a
//! queue or webhook), extract the header bytes, send them to the signer,
//! and apply the returned signature separately:
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::{Signer, Verifier};
//! use rpm::signature::Signing;
//!
//! // Step 1: Extract the header bytes to be signed.
//! // Only reads the metadata, not the payload.
//! let metadata = rpm::PackageMetadata::open("./tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//! let header_bytes = metadata.header_bytes()?;
//!
//! // Step 2: Sign the header bytes (this would normally happen on a remote system).
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.secret")?;
//! let signature = signer.sign(header_bytes.as_slice(), rpm::Timestamp(1_600_000_000))?;
//!
//! // Step 3: Apply the signature.
//! // For in-memory packages:
//! let mut pkg = rpm::Package::open("./tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
//! pkg.apply_signature(signature.clone())?;
//!
//! // Or apply directly to an on-disk package without loading the payload:
//! # let dir = tempfile::tempdir()?;
//! # let pkg_path = dir.path().join("test.rpm");
//! # std::fs::copy("./tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm", &pkg_path)?;
//! rpm::Package::apply_signature_in_place(&pkg_path, signature)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! #### In-place signing and clearing of signatures
//!
//! For large packages, it is often desirable to sign or clear signatures without reading
//! or rewriting the payload. These methods modify only the signature header on disk,
//! using the reserved space to keep the file size unchanged:
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use rpm::signature::pgp::Signer;
//!
//! # let dir = tempfile::tempdir()?;
//! # let pkg_path = dir.path().join("test.rpm");
//! # std::fs::copy("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm", &pkg_path)?;
//! // Re-sign a package on disk (reads only the metadata, not the payload)
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.secret")?;
//! rpm::Package::resign_in_place(&pkg_path, &signer)?;
//!
//! // Remove all signatures, converting their space to reserved space
//! // so that signatures can be added back later
//! rpm::Package::clear_signatures_in_place(&pkg_path)?;
//!
//! // Re-sign the cleared package — the reserved space from clearing is reused
//! rpm::Package::resign_in_place(&pkg_path, &signer)?;
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "signature-pgp"))]
//! # fn main() {}
//! ```
//!
//! ### Build a new package
//!
//! ```
//! # #[cfg(all(unix, feature = "signature-pgp"))]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let _ = env_logger::Builder::new().filter_level(log::LevelFilter::Trace).is_test(true).try_init();
//! use rpm::signature::pgp::Signer;
//!
//! // For reproducible builds, set source_date to the timestamp of the last commit in your VCS
//! let build_config = rpm::BuildConfig::default()
//!     .compression(rpm::CompressionType::Gzip)
//!     .source_date(1_600_000_000);
//! let signer = Signer::from_asc_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret")?;
//! let pkg = rpm::PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
//!     .using_config(build_config)
//!     // set default ownership and permissions for files and directories, similar to %defattr
//!     // in an RPM spec file. Pass None for any field to leave it unchanged (like `-` in %defattr).
//!     .default_file_attrs(Some(0o644), Some("myuser".into()), Some("mygroup".into()))
//!     .default_dir_attrs(Some(0o755), Some("myuser".into()), Some("mygroup".into()))
//!     // add a file with no special options
//!     // by default, files will be owned by the "root" user and group, and inherit their permissions
//!     // from the on-disk file.
//!     .with_file(
//!         "./tests/assets/SOURCES/multiplication_tables.py",
//!         rpm::FileOptions::new("/usr/bin/awesome"),
//!     )?
//!     // you can set permissions, capabilities and other metadata (user, group, etc.) manually
//!     .with_file(
//!         "./tests/assets/SOURCES/example_config.toml",
//!         rpm::FileOptions::new("/etc/awesome/second.toml")
//!             .permissions(0o644)
//!             .caps("cap_sys_admin,cap_net_admin=pe")?
//!             .user("hugo"),
//!     )?
//!     // Add a file - setting flags on it equivalent to `%config(noreplace)`
//!     .with_file(
//!         "./tests/assets/SOURCES/example_config.toml",
//!         rpm::FileOptions::new("/etc/awesome/config.toml")
//!             .config().noreplace(),
//!     )?
//!     // add a file from in-memory content instead of reading from disk
//!     .with_file_contents(
//!         "hello world!",
//!         rpm::FileOptions::new("/usr/share/awesome/greeting.txt"),
//!     )?
//!     // binary content works too
//!     .with_file_contents(
//!         b"\x00\x01\x02\x03".as_slice(),
//!         rpm::FileOptions::new("/usr/share/awesome/data.bin").permissions(0o600),
//!     )?
//!     // symlinks don't require a source file
//!     .with_symlink(
//!         rpm::FileOptions::symlink("/usr/bin/awesome_link", "/usr/bin/awesome"),
//!     )?
//!     // directories can be created with explicit ownership and permissions
//!     // this does not add any directory contents, just declares a directory
//!     .with_dir_entry(
//!         rpm::FileOptions::dir("/var/log/awesome").permissions(0o750),
//!     )?
//!     // recursively add all files from a directory on disk, using a closure to customize
//!     // the file options for each entry (e.g. marking all files as documentation)
//!     .with_dir("./tests/assets/SOURCES", "/usr/share/awesome", |o| o.doc())?
//!     // ghost files / directories are not included in the package payload, but their metadata
//!     // (ownership, permissions, etc.) is tracked by RPM. This is commonly used for files
//!     // created at runtime (e.g. log files, PID files).
//!     .with_ghost(
//!         rpm::FileOptions::ghost("/var/log/awesome/app.log"),
//!     )?
//!     .pre_install_script("echo preinst")
//!     // Alternatively, use scriptlet builder api to specify flags and interpreter/arguments
//!     .post_trans_script(
//!         rpm::Scriptlet::new("echo posttrans")
//!             .flags(rpm::ScriptletFlags::EXPAND)
//!             .prog(vec!["/bin/blah/bash", "-c"])
//!     )
//!     .build_host(gethostname::gethostname().to_str().unwrap_or("host"))
//!     .add_changelog_entry(
//!         "Max Mustermann <max@example.com> - 0.1-29",
//!         "- was awesome, eh?",
//!         chrono::DateTime::parse_from_rfc2822("Wed, 19 Apr 2023 23:16:09 GMT")
//!             .expect("Date 1 is correct. qed"),
//!     )
//!     .add_changelog_entry(
//!         "Charlie Yom <test2@example.com> - 0.1-28",
//!         "- yeah, it was",
//!         // Raw timestamp for 1996-08-14 05:20:00
//!         840_000_000,
//!     )
//!     .requires(rpm::Dependency::any("wget"))
//!     .vendor("corporation or individual")
//!     .url("www.github.com/repo")
//!     .vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")
//!     .build_and_sign(signer)?;
//!
//! // Write to a specific file
//! # let dir = tempfile::tempdir()?;
//! pkg.write_to(dir.path().join("awesome.rpm"))?;
//!
//! // Or write to a directory with auto-generated filename (`test-1.0.0-1.x86_64.rpm`)
//! pkg.write_to(dir.path())?;
//! # Ok(())
//! # }
//! # #[cfg(not(all(unix, feature = "signature-pgp")))]
//! # fn main() {}
//! ```

#![allow(unknown_lints, clippy::uninlined_format_args)]

mod errors;
pub use crate::errors::*;

pub(crate) mod constants;
pub use crate::constants::*;

mod rpm;
pub use crate::rpm::*;

#[cfg(feature = "python")]
pub mod python;
