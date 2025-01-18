[![crates.io](https://img.shields.io/crates/v/rpm.svg)](https://crates.io/crates/rpm)
[![docs.rs](https://docs.rs/rpm/badge.svg)](https://docs.rs/rpm)
[![MSRV](https://img.shields.io/badge/rustc-1.75.0+-ab6000.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

## RPM-RS

A pure rust library for parsing and creating RPM files.

### Goals

- Easy to use API
- Pure rust to make it easy to use in larger Projects
- Independence of Spec files. Pure programmatic interface for Packaging.
- Compatibility from Enterprise Linux 8 (RHEL, Alma, Rocky, CentOS Stream) to Fedora (I may extend test cases for SUSE)

### Non Goals

RPM has a lot of cryptic features. I do not want to re-implement all of them. This library focuses on
the ones that I assume as useful.
This library does not build software like rpmbuild. It is meant for finished artifacts that need to be packaged as RPM.

### Status

- [x] RPM Creation
- [x] Basic RPM Reading
- [x] RPM Signing and Signature Verification
- [x] High Level API for RPM Reading

### Examples

```rust
use rpm::signature::pgp::{Signer, Verifier};

let raw_secret_key = std::fs::read("./tests/assets/signing_keys/secret_ed25519.asc")?;
// It's recommended to use timestamp of last commit in your VCS
let source_date = 1_600_000_000;
let pkg = rpm::PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
    .compression(rpm::CompressionType::Gzip)
    .with_file(
        "./tests/assets/SOURCES/example_config.toml",
        rpm::FileOptions::new("/etc/awesome/config.toml")
            .is_config()
            .is_no_replace(),
    )?
    // file mode is inherited from source file
    .with_file(
        "./tests/assets/SOURCES/multiplication_tables.py",
        rpm::FileOptions::new("/usr/bin/awesome"),
    )?
    .with_file(
        "./tests/assets/SOURCES/example_config.toml",
        // you can set a custom mode and custom user too
        rpm::FileOptions::new("/etc/awesome/second.toml")
            .mode(rpm::FileMode::regular(0o644))
            .caps("cap_sys_admin,cap_net_admin=pe")?
            .user("hugo"),
    )?
    .pre_install_script("echo preinst")
    // Alternatively, use scriptlet builder api to specify flags and interpreter/arguments
    .post_trans_script(
        Scriptlet::new("echo posttrans")
            .flags(ScriptletFlags::EXPAND)
            .prog(vec!["/bin/blah/bash", "-c"])
    )
    // If you don't need reproducible builds,
    // you can remove the following line
    .source_date(source_date)
    .build_host(gethostname::gethostname().to_str().unwrap_or("host"))
    .add_changelog_entry(
        "Max Mustermann <max@example.com> - 0.1-29",
        "- was awesome, eh?",
        chrono::DateTime::parse_from_rfc2822("Wed, 19 Apr 2023 23:16:09 GMT")
            .expect("Date 1 is correct. qed"),
    )
    .add_changelog_entry(
        "Charlie Yom <test2@example.com> - 0.1-28",
        "- yeah, it was",
        // Raw timestamp for 1996-08-14 05:20:00
        840_000_000,
    )
    .requires(rpm::Dependency::any("wget"))
    .vendor("corporation or individual")
    .url("www.github.com/repo")
    .vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")
    .build_and_sign(Signer::load_from_asc_bytes(&raw_secret_key)?)?;

pkg.write_file("./awesome.rpm")?;

// reading
let raw_pub_key = std::fs::read("/path/to/gpg.key.pub")?;
let pkg = rpm::Package::open("tests/assets/RPMS/signed/noarch/rpm-basic-with-ed25519-2.3.4-5.el9.noarch.rpm")?;

let name = pkg.metadata.get_name()?;
let version = pkg.metadata.get_version()?;
let release = pkg.metadata.get_release()?;
let arch = pkg.metadata.get_arch()?;

println!("{}-{}-{}.{}", name, version, release, arch);

for changelog in pkg.metadata.get_changelog_entries()? {
    println!("{}\n{}\n", changelog.name, changelog.description);
}

// verifying
pkg.verify_signature(Verifier::load_from_asc_bytes(&raw_pub_key)?)?;
```
