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

    // Current issues:
    // ===============
    // Lead: archnum is set to zero

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

/// Build a basic package and compare it to one built by rpmbuild (using rpm-basic.spec)
#[ignore]
#[test]
fn test_basic_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let original_rpm = Package::open(common::rpm_basic_pkg_path())?;
    let built_rpm = PackageBuilder::new(
        "rpm-basic",
        "2.3.4",
        "MPL-2.0",
        "noarch",
        "A package for exercising basic features of RPM",
    )
    .epoch(1)
    .release("5")
    .description("This package attempts to exercise basic features of RPM packages.")
    .vendor("Los Pollos Hermanos")
    .url("http://www.savewalterwhite.com/")
    .vcs("https://github.com/rpm-rs/rpm")
    .group("Development/Tools")
    .packager("Walter White")
    .compression(CompressionType::None)
    .build_host("localhost")
    .source_date(1681068559)
    .provides(Dependency::any("/usr/bin/ls"))
    .provides(Dependency::any("aaronpaul"))
    .provides(Dependency::any("breaking(bad)"))
    .provides(Dependency::config("rpm-basic", "1:2.3.4-5.el9"))
    .provides(Dependency::eq("rpm-basic", "1:2.3.4-5.el9"))
    .provides(Dependency::eq("shock", "33"))
    .requires(Dependency::script_pre("/usr/sbin/ego"))
    .requires(Dependency::config("rpm-basic", "1:2.3.4-5.el9"))
    .requires(Dependency::greater_eq("methylamine", "1.0.0-1"))
    .requires(Dependency::less_eq("morality", "2"))
    .requires(Dependency::script_post("regret"))
    .conflicts(Dependency::greater("hank", "35"))
    .obsoletes(Dependency::less("gusfring", "32.1-0"))
    .obsoletes(Dependency::less("tucosalamanca", "444"))
    .supplements(Dependency::eq("comedy", "0:11.1-4"))
    .suggests(Dependency::any("chilipowder"))
    .enhances(Dependency::greater("purity", "9000"))
    .recommends(Dependency::any("SaulGoodman(CriminalLawyer)"))
    .recommends(Dependency::greater("huel", "9:11.0-0"))
    .with_file(
        "./tests/assets/SOURCES/example_config.toml",
        FileOptions::new("/etc/rpm-basic/example_config.toml").is_config(),
    )?
    .with_file(
        "./tests/assets/SOURCES/multiplication_tables.py",
        FileOptions::new("/usr/bin/rpm-basic"),
    )?
    .with_file(
        "",
        FileOptions::new("/usr/lib/rpm-basic").mode(FileMode::Dir { permissions: 0o644 }),
    )?
    .with_file(
        "",
        FileOptions::new("/usr/lib/rpm-basic/module").mode(FileMode::Dir { permissions: 0o755 }),
    )?
    .with_file(
        "./tests/assets/SOURCES/module/__init__.py",
        FileOptions::new("/usr/lib/rpm-basic/module/__init__.py"),
    )?
    .with_file(
        "./tests/assets/SOURCES/module/hello.py",
        FileOptions::new("/usr/lib/rpm-basic/module/hello.py"),
    )?
    .with_file(
        "",
        FileOptions::new("/usr/lib/rpm-basic/module").mode(FileMode::Dir { permissions: 0o755 }),
    )?
    .with_file(
        "",
        FileOptions::new("/usr/share/doc/rpm-basic").mode(FileMode::Regular { permissions: 0o644 }),
    )?
    .with_file(
        "",
        FileOptions::new("/usr/share/doc/rpm-basic/README").is_doc(),
    )?
    .with_file(
        "./tests/assets/SOURCES/example_data.xml",
        FileOptions::new("/usr/share/rpm-basic/example_data.xml"),
    )?
    .with_file(
        "",
        FileOptions::new("/var/log/rpm-basic/basic.log").is_ghost(),
    )?
    .with_file(
        "",
        FileOptions::new("/var/tmp/rpm-basic").mode(FileMode::Dir { permissions: 0o755 }),
    )?
    .add_changelog_entry(
        "Walter White <ww@savewalterwhite.com> - 3.3.3-3",
        "- I'm not in the meth business. I'm in the empire business.",
        1623672000,
    )
    .add_changelog_entry(
        "Gustavo Fring <gus@lospolloshermanos.com> - 2.2.2-2",
        "- Never Make The Same Mistake Twice.",
        1619352000,
    )
    .add_changelog_entry(
        "Mike Ehrmantraut <mike@lospolloshermanos.com> - 1.1.1-1",
        "- Just because you shot Jesse James, don't make you Jesse James.",
        1619352000,
    )
    .build()?;

    // @TODO: currently failing due to missing tags, different checksums, offsets etc.
    // empty_rpm.canonicalize()?;
    // built_empty_rpm.canonicalize()?;
    // pretty_assertions::assert_eq!(empty_rpm.metadata, built_empty_rpm.metadata);

    // Test that the payload generated is equivalent
    pretty_assertions::assert_str_eq!(
        format!("{:?}", &original_rpm.content.as_bstr()),
        format!("{:?}", &built_rpm.content.as_bstr()),
    );

    Ok(())
}

/// Build a package with all different kinds of file attrs and compare it to one built by rpmbuild (using rpm-file-attrs.spec)
#[ignore]
#[test]
fn test_file_attrs_package_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    let empty_rpm = Package::open(common::rpm_empty_path())?;
    let built_empty_rpm = PackageBuilder::new(
        "rpm-file-attrs",
        "1.0",
        "MIT",
        "noarch",
        "Test RPM file attributes",
    )
    .release("1")
    .description("Test RPM file attributes")
    .compression(CompressionType::None)
    .build_host("localhost")
    .source_date(1681068559)
    .with_file(
        "",
        FileOptions::new("/opt/rpm-file-attrs").mode(FileMode::Dir { permissions: 0o755 }),
    )?
    .with_file_contents(
        "artifact",
        FileOptions::new("/opt/rpm-file-attrs/artifact").is_artifact(),
    )?
    .with_file_contents(
        "config",
        FileOptions::new("/opt/rpm-file-attrs/config").is_config(),
    )?
    .with_file_contents(
        "config_noreplace",
        FileOptions::new("/opt/rpm-file-attrs/config_noreplace").is_config_noreplace(),
    )?
    .with_file_contents(
        "different-owner-and-group",
        FileOptions::new("/opt/rpm-file-attrs/different-owner-and-group")
            .user("jane")
            .group("bob")
            .mode(FileMode::Regular { permissions: 0o655 }),
    )?
    .with_file(
        "",
        FileOptions::new("/opt/rpm-file-attrs/dir").mode(FileMode::Dir { permissions: 0o755 }),
    )?
    .with_file_contents("normal", FileOptions::new("/opt/rpm-file-attrs/dir/normal"))?
    .with_file_contents("doc", FileOptions::new("/opt/rpm-file-attrs/doc").is_doc())?
    .with_file_contents(
        "empty_caps",
        FileOptions::new("/opt/rpm-file-attrs/empty_caps").caps("=")?,
    )?
    .with_file_contents(
        "empty_caps2",
        FileOptions::new("/opt/rpm-file-attrs/empty_caps2").caps("")?,
    )?
    .with_file_contents(
        "example-binary",
        FileOptions::new("/opt/rpm-file-attrs/example-binary")
            .mode(FileMode::Regular { permissions: 0o644 }),
    )?
    .with_file_contents(
        "example-confidential-file",
        FileOptions::new("/opt/rpm-file-attrs/example-confidential-file")
            .mode(FileMode::Regular { permissions: 0o600 }),
    )?
    .with_file_contents("ghost", FileOptions::new("/opt/rpm-file-attrs/ghost").is_ghost())?
    .with_file_contents(
        "license",
        FileOptions::new("/opt/rpm-file-attrs/license").is_license(),
    )?
    .with_file_contents(
        "missingok",
        FileOptions::new("/opt/rpm-file-attrs/missingok").is_missingok(),
    )?
    .with_file("normal", FileOptions::new("/opt/rpm-file-attrs/normal"))?
    .with_file(
        "readme",
        FileOptions::new("/opt/rpm-file-attrs/readme").is_readme(),
    )?
    .with_file(
        "",
        FileOptions::new("/opt/rpm-file-attrs/symlink")
            .symlink("normal")
            .mode(FileMode::SymbolicLink { permissions: 0o777 }),
    )?
    .with_file(
        "",
        FileOptions::new("/opt/rpm-file-attrs/symlink_dir")
            .mode(FileMode::Dir { permissions: 0o755 }),
    )?
    .with_file("", FileOptions::new("/opt/rpm-file-attrs/symlink_dir/dir"))?
    .with_file_contents(
        "with_caps",
        FileOptions::new("/opt/rpm-file-attrs/with_caps")
            .symlink("../dir")
            .mode(FileMode::Dir { permissions: 0o755 })
            .caps("cap_sys_ptrace,cap_sys_admin=ep")?,
    )?
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
