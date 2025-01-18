//! # rpm-rs
//!
//! A library providing API to parse rpms as well as
//! creating rpms from individual files.
//!
//! All supported compression types are behind feature flags. All of them except bzip2 are enabled
//! by default. They can be disable if these compression algorithms are unused.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "signature-pgp")]
//! use rpm::{
//!     signature::pgp::{
//!         Signer,
//!         Verifier
//!     },
//! };
//! use std::str::FromStr;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let _ = env_logger::Builder::new().filter_level(log::LevelFilter::Trace).is_test(true).try_init();
//! # #[cfg(feature = "signature-pgp")]
//! # {
//! let raw_secret_key = std::fs::read("./tests/assets/signing_keys/secret_rsa4096.asc")?;
//! // It's recommended to use timestamp of last commit in your VCS
//! let source_date = 1_600_000_000;
//! let pkg = rpm::PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
//!     .compression(rpm::CompressionType::Gzip)
//!     .with_file(
//!         "./tests/assets/SOURCES/example_config.toml",
//!         rpm::FileOptions::new("/etc/awesome/config.toml").is_config(),
//!     )?
//!     // file mode is inherited from source file
//!     .with_file(
//!         "./tests/assets/SOURCES/multiplication_tables.py",
//!         rpm::FileOptions::new("/usr/bin/awesome"),
//!     )?
//!     .with_file(
//!         "./tests/assets/SOURCES/example_config.toml",
//!         // you can set a custom mode and custom user too
//!         rpm::FileOptions::new("/etc/awesome/second.toml")
//!             .mode(rpm::FileMode::regular(0o644))
//!             .user("hugo"),
//!     )?
//!     .pre_install_script("echo preinst")
//!     // If you don't need reproducible builds,
//!     // you can remove the following line
//!     .source_date(source_date)
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
//!     .build_and_sign(Signer::load_from_asc_bytes(&raw_secret_key)?)?;
//! let mut f = std::fs::File::create("/tmp/awesome.rpm")?;
//! pkg.write(&mut f)?;
//!
//! // reading
//! let raw_pub_key = std::fs::read("tests/assets/signing_keys/public_rsa4096.asc")?;
//! let pkg = rpm::Package::open("/tmp/awesome.rpm")?;
//! // verifying
//! pkg.verify_signature(Verifier::load_from_asc_bytes(&raw_pub_key)?)?;
//! # }
//! # Ok(())
//! # }
//! ```

#![allow(unknown_lints, clippy::uninlined_format_args)]

mod errors;
pub use crate::errors::*;

pub(crate) mod constants;
pub use crate::constants::*;

mod version;
pub use crate::version::*;

mod rpm;
pub use crate::rpm::*;
