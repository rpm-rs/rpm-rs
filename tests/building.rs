use std::io::Cursor;

use bstr::ByteSlice;
use pretty_assertions;

use rpm::*;

mod common;

/// Build an empty package and compare it to one built by rpmbuild
#[test]
fn test_empty_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let empty_rpm = Package::open(common::rpm_empty_path())?;
    let built_empty_rpm = PackageBuilder::new("rpm-empty", "0", "LGPL", "x86-64", "")
        .compression(CompressionType::None)
        .build()?;

    // @TODO: currently failing due to missing tags, different checksums, offsets etc.
    // empty_rpm.canonicalize()?;
    // built_empty_rpm.canonicalize()?;
    // pretty_assertions::assert_eq!(empty_rpm.metadata, built_empty_rpm.metadata);

    // Test that the payload generated is equivalent
    pretty_assertions::assert_str_eq!(
        format!("{:?}", &empty_rpm.content.as_bstr()),
        format!("{:?}", &built_empty_rpm.content.as_bstr()),
    );

    Ok(())
}

/// Build an empty source package and compare it to one built by rpmbuild
/// Blocked on completion of source package support
#[ignore = "https://github.com/rpm-rs/rpm/issues/66"]
#[test]
fn test_empty_source_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let empty_rpm = Package::open(common::rpm_empty_source_path())?;
    let built_empty_rpm = PackageBuilder::new("rpm-empty", "0", "LGPL", "x86-64", "").build()?;

    // @TODO: currently failing due to missing tags, different checksums, offsets etc.
    // empty_rpm.canonicalize()?;
    // built_empty_rpm.canonicalize()?;
    // pretty_assertions::assert_eq!(empty_rpm.metadata, built_empty_rpm.metadata);

    // Test that the payload generated is equivalent
    pretty_assertions::assert_str_eq!(
        format!("{:?}", &empty_rpm.content.as_bstr()),
        format!("{:?}", &built_empty_rpm.content.as_bstr()),
    );

    Ok(())
}

#[test]
fn test_rpm_builder() -> Result<(), Box<dyn std::error::Error>> {
    let mut buff = std::io::Cursor::new(Vec::<u8>::new());

    let pkg = PackageBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
        .description(
            "This is an awesome package.

However, it does nothing.",
        )
        .compression(rpm::CompressionType::Gzip)
        .with_file(
            "Cargo.toml",
            FileOptions::new("/etc/awesome/config.toml")
                .is_config()
                .is_no_replace(),
        )?
        // file mode is inherited from source file
        .with_file("Cargo.toml", FileOptions::new("/usr/bin/awesome"))?
        .with_file(
            "Cargo.toml",
            // you can set a custom mode and custom user too
            FileOptions::new("/etc/awesome/second.toml")
                .mode(0o100744)
                .caps("cap_sys_admin,cap_sys_ptrace=pe")?
                .user("hugo"),
        )?
        .with_file(
            "./tests/assets/SOURCES/empty_file_for_symlink_create",
            FileOptions::new("/usr/bin/awesome_link")
                .mode(0o120644)
                .symlink("/usr/bin/awesome"),
        )?
        .pre_install_script("echo preinst")
        .post_install_script(Scriptlet::new("echo postinst").prog(vec!["/bin/blah/bash", "-c"]))
        .pre_trans_script(Scriptlet::new("echo pretrans").flags(ScriptletFlags::EXPAND))
        .post_trans_script(
            Scriptlet::new("echo posttrans")
                .flags(ScriptletFlags::EXPAND)
                .prog(vec!["/bin/blah/bash", "-c"]),
        )
        .post_untrans_script(&String::from("echo postuntrans"))
        .add_changelog_entry("me", "was awesome, eh?", 1_681_411_811)
        .add_changelog_entry("you", "yeah, it was", 850_984_797)
        .requires(Dependency::any("wget"))
        .vendor("dummy vendor")
        .url("dummy url")
        .vcs("dummy vcs")
        .build()?;

    pkg.write(&mut buff)?;

    // check that generated packages has source rpm tag to be more compatibly recognized as RPM binary packages
    pkg.metadata.get_source_rpm()?;

    pkg.verify_digests()?;

    // check various metadata on the files
    pkg.metadata.get_file_entries()?.iter().for_each(|f| {
        if f.path.as_os_str() == "/etc/awesome/second.toml" {
            assert_eq!(
                f.clone().caps.unwrap(),
                "cap_sys_admin,cap_sys_ptrace=pe".to_string()
            );
            assert_eq!(f.ownership.user, "hugo".to_string());
        } else if f.path.as_os_str() == "/etc/awesome/config.toml" {
            assert_eq!(f.caps, Some("".to_string()));
            assert_eq!(f.flags, FileFlags::CONFIG | FileFlags::NOREPLACE);
        } else if f.path.as_os_str() == "/usr/bin/awesome" {
            assert_eq!(f.mode, FileMode::from(0o100644));
        } else if f.path.as_os_str() == "/usr/bin/awesome_link" {
            assert_eq!(f.mode, FileMode::from(0o120644));
        }
    });

    // Test scriptlet builder fn branches
    let preinst = pkg.metadata.get_pre_install_script()?;
    assert_eq!(preinst.script.as_str(), "echo preinst");
    assert!(preinst.flags.is_none());
    assert!(preinst.program.is_none());

    let postinst = pkg.metadata.get_post_install_script()?;
    assert_eq!(postinst.script.as_str(), "echo postinst");
    assert!(postinst.flags.is_none());
    assert_eq!(
        postinst.program,
        Some(vec!["/bin/blah/bash".to_string(), "-c".to_string()])
    );

    let pretrans = pkg.metadata.get_pre_trans_script()?;
    assert_eq!(pretrans.script.as_str(), "echo pretrans");
    assert_eq!(pretrans.flags, Some(ScriptletFlags::EXPAND));
    assert!(pretrans.program.is_none());

    let posttrans = pkg.metadata.get_post_trans_script()?;
    assert_eq!(posttrans.script.as_str(), "echo posttrans");
    assert_eq!(posttrans.flags, Some(ScriptletFlags::EXPAND));
    assert_eq!(
        posttrans.program,
        Some(vec!["/bin/blah/bash".to_string(), "-c".to_string()])
    );

    let postuntrans = pkg.metadata.get_post_untrans_script()?;
    assert_eq!(postuntrans.script.as_str(), "echo postuntrans");
    assert!(postuntrans.flags.is_none());
    assert!(postuntrans.program.is_none());

    assert!(pkg.metadata.get_pre_untrans_script().is_err());

    Ok(())
}

#[test]
#[ignore = "missing config() dependencies and some other stuff, need to flesh out files"]
fn test_rpm_file_attrs_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let mut buff = std::io::Cursor::new(Vec::<u8>::new());

    let pkg = PackageBuilder::new(
        "rpm-file-attrs",
        "1.0",
        "MIT",
        "noarch",
        "Test RPM file attributes",
    )
    .release("1")
    .description("Test RPM file attributes")
    .compression(rpm::CompressionType::None)
    .build_host("localhost")
    .with_file(
        "./tests/assets/RPMS/noarch/rpm-file-attrs-1.0-1.noarch.rpm",
        FileOptions::new("/bin/test").caps("cap_sys_admin,cap_sys_ptrace=pe")?,
    )?
    // TODO files
    .build()?;

    let metadata = &pkg.metadata;

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![
            // TODO: understand what this means and why it is both provided and required
            Dependency::config("rpm-file-attrs", "1.0-1"),
            Dependency::eq("rpm-file-attrs", "1.0-1"),
        ]
    );
    assert_eq!(
        metadata.get_requires().unwrap(),
        vec![
            Dependency::config("rpm-file-attrs", "1.0-1"),
            Dependency::rpmlib("CompressedFileNames", "3.0.4-1"),
            Dependency::rpmlib("FileCaps", "4.6.1-1"),
            Dependency::rpmlib("FileDigests", "4.6.0-1"),
            Dependency::rpmlib("PayloadFilesHavePrefix", "4.0-1"),
        ]
    );
    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    // These are soft requirements because of the build-time policy when these packages were created on Fedora 39
    // Probably if built on some later version they would be hard requirements?
    // https://github.com/rpm-software-management/rpm/blob/bb4aaaa2e8e4bdfc02f9d98ab2982074051c4eb2/docs/manual/users_and_groups.md?plain=1#L36C11-L36C11
    assert_eq!(
        metadata.get_recommends().unwrap(),
        vec![Dependency::group("jane"), Dependency::user("jane"),]
    );

    pkg.write(&mut buff)?;

    // check that generated packages has source rpm tag to be more compatibly recognized as RPM binary packages
    pkg.metadata.get_source_rpm()?;

    pkg.verify_digests()?;

    Ok(())
}

/// Read a package, write it, and read it back - check for equivalence.
#[test]
fn test_rpm_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    let paths = vec![
        common::rpm_basic_pkg_path(),
        common::rpm_basic_pkg_path_eddsa_signed(),
        common::rpm_basic_pkg_path_rsa_signed(),
        common::rpm_basic_source_path(),
        common::rpm_empty_path(),
        common::rpm_empty_source_path(),
        common::rpm_file_attrs_path(),
        common::rpm_with_patch_path(),
    ];

    for path in paths {
        let mut buf = Vec::new();
        let rpm = Package::open(path)?;
        rpm.write(&mut buf)?;
        let roundtripped_rpm = Package::parse(&mut Cursor::new(buf))?;

        assert_eq!(rpm, roundtripped_rpm);
    }
    Ok(())
}
