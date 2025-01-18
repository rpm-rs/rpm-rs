use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use rpm::*;
use std::path::PathBuf;

use pretty_assertions::assert_eq;

mod common;

#[test]
fn test_package_segment_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    assert_boundaries(common::rpm_empty_path().as_ref())?;
    assert_boundaries(common::rpm_empty_source_path().as_ref())?;
    assert_boundaries(common::rpm_basic_pkg_path().as_ref())?;
    assert_boundaries(common::rpm_basic_pkg_path_eddsa_signed().as_ref())?;
    assert_boundaries(common::rpm_basic_pkg_path_rsa_signed().as_ref())?;

    let constructed_pkg =
        rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "").build()?;
    constructed_pkg.write(&mut File::create("/tmp/empty_pkg.rpm")?)?;
    assert_boundaries(Path::new("/tmp/empty_pkg.rpm"))?;

    #[cfg(feature = "signature-meta")]
    {
        use rpm::signature::pgp::Signer;
        let signing_key = common::rsa_private_key();
        let signer = Signer::load_from_asc_bytes(signing_key.as_ref())?;
        let constructed_pkg_with_sig =
            rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "")
                .build_and_sign(signer)?;
        constructed_pkg_with_sig.write(&mut File::create("/tmp/empty_pkg_with_sig.rpm")?)?;
        assert_boundaries(Path::new("/tmp/empty_pkg_with_sig.rpm"))?;
    }

    fn assert_boundaries(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut f = File::open(path)?;
        let package = rpm::Package::open(path)?;
        let offsets = package.metadata.get_package_segment_offsets();

        // Verify that we see an RPM magic #
        let mut buf = [0u8; 4];
        f.read_exact(&mut buf)?;

        assert_eq!(buf, RPM_MAGIC);

        // Seek to the start of the sig header and verify that we see a header magic #
        f.seek(SeekFrom::Start(offsets.signature_header))?;
        let mut buf = [0u8; 3];
        f.read_exact(&mut buf)?;

        assert_eq!(buf, HEADER_MAGIC);

        // Seek to the start of the header and verify that we see a header magic #
        f.seek(SeekFrom::Start(offsets.header))?;
        let mut buf = [0u8; 3];
        f.read_exact(&mut buf)?;

        assert_eq!(buf, HEADER_MAGIC);

        // Seek to the start of the payload and verify that we see a magic # appropriate for the payload type
        f.seek(SeekFrom::Start(offsets.payload))?;
        let mut buf = [0u8; 10];
        f.read_exact(&mut buf)?;

        let payload_magic: &[u8] = match package.metadata.get_payload_compressor().unwrap() {
            CompressionType::Gzip => &[0x1f, 0x8b],
            CompressionType::Zstd => &[0x28, 0xb5, 0x2f, 0xfd],
            CompressionType::Xz => &[0xfd, 0x37, 0x7a, 0x58, 0x5a],
            CompressionType::Bzip2 => &[0x42, 0x5a],
            CompressionType::None => &[0x30, 0x37, 0x30, 0x37, 0x30, 0x31], // CPIO archive magic #
        };

        assert!(buf.starts_with(payload_magic));

        Ok(())
    }

    Ok(())
}

#[test]
fn test_file_attrs() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::rpm_file_attrs_path())?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-file-attrs");
    assert!(metadata.get_epoch().is_err());
    assert_eq!(metadata.get_version().unwrap(), "1.0");
    assert_eq!(metadata.get_release().unwrap(), "1");
    assert_eq!(metadata.get_arch().unwrap(), "noarch");
    assert_eq!(
        metadata.get_description().unwrap(),
        "Test RPM file attributes"
    );
    assert_eq!(metadata.get_summary().unwrap(), "Test RPM file attributes");
    assert_eq!(metadata.get_license().unwrap(), "MIT");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert_eq!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    );
    assert_eq!(metadata.get_installed_size().unwrap(), 201);

    assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
    assert!(matches!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    ));
    assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));

    assert_eq!(
        metadata.get_file_entries().unwrap(),
        vec![
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs"),
                mode: FileMode::Dir { permissions: 0o755 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/artifact"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 9,
                flags: FileFlags::ARTIFACT,
                digest: Some(FileDigest {
                    digest: "5b3513f580c8397212ff2c8f459c199efc0c90e4354a5f3533adf0a3fff3a530"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/config"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 7,
                flags: FileFlags::CONFIG,
                digest: Some(FileDigest {
                    digest: "f612b89bcdbc401379f644d7e48572e3470f77dcd4c39416405d80952ad7089e"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/config_noreplace"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 17,
                flags: FileFlags::CONFIG | FileFlags::NOREPLACE,
                digest: Some(FileDigest {
                    digest: "65aef2d1dcd07b86831d536703f71f74916d81189bd69a168dad2ce1815a5136"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/different-owner-and-group"),
                mode: FileMode::Regular { permissions: 0o655 },
                ownership: FileOwnership {
                    user: "jane".to_owned(),
                    group: "bob".to_owned(),
                },
                modified_at: Timestamp(1681068559,),
                size: 26,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "6e19af479b7cdab8d446f20a1e0368afe4c8fb01421efcbdb1ff4c72b4a7b1de"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                },),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/dir"),
                mode: FileMode::Dir { permissions: 0o755 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559,),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/dir/normal"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 14,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "378c7c38d6e7208fcca00a748a4e94272f4ae3a2b99c1b85a9d25179d187f13d"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                },),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/doc"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 4,
                flags: FileFlags::DOC,
                digest: Some(FileDigest {
                    digest: "30a4ab973ef8fd561d930d55502df855108ca0b081454b0e761d5141f3778780"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/empty_caps"),
                mode: FileMode::Regular { permissions: 0o655 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 11,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "f2e132eb12bc8635acd67bb066d4df2dfbde5b508223ef682632000616646431"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("=".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/empty_caps2"),
                mode: FileMode::Regular { permissions: 0o655 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 12,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "ebc4ec9a7a5e144dad5a7bca3e93d8565b71e8938cbb78b6c5e067af478b20bc"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("=".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/example-binary"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 15,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "1c48d874093f64b1571fc4df5e900e1e36764d1c78019332fafbe144921e4886"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/example-confidential-file"),
                mode: FileMode::Regular { permissions: 0o600 },
                ownership: FileOwnership {
                    user: "jane".to_owned(),
                    group: "jane".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 26,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "712e0fa274215e73c83de99659471615d53cd52177fdd6906ca3309b2989ebcd"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/ghost"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 6,
                flags: FileFlags::GHOST,
                digest: None,
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/license"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 8,
                flags: FileFlags::LICENSE,
                digest: Some(FileDigest {
                    digest: "c0c56958ef8be5c1979366896b7e0c7206949a5aa2b23f51429c7f56b10990d3"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/missingok"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 10,
                flags: FileFlags::MISSINGOK,
                digest: Some(FileDigest {
                    digest: "d977a3636e681e2c767015b261b1fac79e5d651dafe66caf5449428ed2873970"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/normal"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 7,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "83d7d4df18591f6a966c7999355338c625e5a2f7c9cb0c35f11d3ed9f725e022"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/readme"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 7,
                flags: FileFlags::README,
                digest: Some(FileDigest {
                    digest: "00d75b5176b48ccc71d91bcc1d7b90fc2820429b1629b77fd1d5f4c5dcee4f6d"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/symlink"),
                mode: FileMode::SymbolicLink { permissions: 0o777 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 6,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: "normal".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/symlink_dir"),
                mode: FileMode::Dir { permissions: 0o755 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/symlink_dir/dir"),
                mode: FileMode::SymbolicLink { permissions: 0o777 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 6,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: "../dir".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/with_caps"),
                mode: FileMode::Regular { permissions: 0o655 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(1681068559),
                size: 10,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "cabc71f9ccd28c9887e9fc608c4420ad5b4b9a44d7146143cd77015b4b259a62"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("cap_sys_ptrace,cap_sys_admin=ep".to_owned()),
                linkto: "".to_owned(),
                ima_signature: None,
            },
        ]
    );
    assert!(metadata.get_changelog_entries().unwrap().is_empty());

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![
            // TODO: understand what this means and why it is both provided and required
            Dependency::config("rpm-file-attrs", "1.0-1".to_owned()),
            Dependency::eq("rpm-file-attrs".to_owned(), "1.0-1".to_owned()),
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
        vec![
            Dependency::group("bob"),
            Dependency::group("jane"),
            Dependency::user("jane"),
        ]
    );

    Ok(())
}

#[test]
fn test_basic_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::rpm_basic_pkg_path())?;
    let metadata = &package.metadata;

    // TODO: make these correct and available
    //     assert_eq!(metadata.signature.index_entries.len(), 7);
    //     assert_eq!(metadata.signature.index_entries[0].num_items, 16);
    //     assert_eq!(metadata.signature.index_header.data_section_size, 1156);

    //     assert_eq!(
    //         metadata.get_package_segment_offsets(),
    //         PackageSegmentOffsets {
    //             lead: 0,
    //             signature_header: 96,
    //             header: 1384,
    //             payload: 148172
    //         }
    //     );

    //     let mut buf = Vec::new();

    //     package.metadata.lead.write(&mut buf)?;
    //     assert_eq!(96, buf.len());

    //     let lead = Lead::parse(&buf)?;
    //     assert!(package.metadata.lead == lead);

    //     buf = Vec::new();
    //     package.metadata.signature.write_signature(&mut buf)?;
    //     let signature = Header::parse_signature(&mut buf.as_slice())?;

    //     assert_eq!(
    //         package.metadata.signature.index_header,
    //         signature.index_header
    //     );

    //     for i in 0..signature.index_entries.len() {
    //         assert_eq!(
    //             signature.index_entries[i],
    //             package.metadata.signature.index_entries[i]
    //         );
    //     }
    //     assert_eq!(
    //         package.metadata.signature.index_entries,
    //         signature.index_entries
    //     );

    //     buf = Vec::new();
    //     package.metadata.header.write(&mut buf)?;
    //     let header = Header::parse(&mut buf.as_slice())?;
    //     assert_eq!(package.metadata.header, header);

    //     buf = Vec::new();
    //     package.write(&mut buf)?;
    //     let second_pkg = Package::parse(&mut buf.as_slice())?;
    //     assert_eq!(package.content.len(), second_pkg.content.len());
    //     assert!(package.metadata == second_pkg.metadata);

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-basic");
    assert_eq!(metadata.get_epoch().unwrap(), 1);
    assert_eq!(metadata.get_version().unwrap(), "2.3.4");
    assert_eq!(metadata.get_release().unwrap(), "5.el9");
    assert_eq!(metadata.get_arch().unwrap(), "noarch");
    assert_eq!(
        metadata.get_description().unwrap(),
        "This package attempts to exercise basic features of RPM packages."
    );
    assert_eq!(
        metadata.get_summary().unwrap(),
        "A package for exercising basic features of RPM"
    );
    assert_eq!(metadata.get_license().unwrap(), "MPL-2.0");
    assert_eq!(
        metadata.get_url().unwrap(),
        "http://www.savewalterwhite.com/"
    );
    assert_eq!(metadata.get_packager().unwrap(), "Walter White");
    assert_eq!(metadata.get_vendor().unwrap(), "Los Pollos Hermanos");
    assert_eq!(metadata.get_group().unwrap(), "Development/Tools");
    assert_eq!(metadata.get_vcs().unwrap(), "https://github.com/rpm-rs/rpm");
    assert_eq!(metadata.get_cookie().unwrap(), "localhost 1681068559");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert_eq!(
        metadata.get_file_paths().unwrap(),
        vec![
            PathBuf::from("/etc/rpm-basic/example_config.toml"),
            PathBuf::from("/usr/bin/rpm-basic"),
            PathBuf::from("/usr/lib/rpm-basic"),
            PathBuf::from("/usr/lib/rpm-basic/module"),
            PathBuf::from("/usr/lib/rpm-basic/module/__init__.py"),
            PathBuf::from("/usr/lib/rpm-basic/module/hello.py"),
            PathBuf::from("/usr/share/doc/rpm-basic"),
            PathBuf::from("/usr/share/doc/rpm-basic/README"),
            PathBuf::from("/usr/share/rpm-basic/example_data.xml"),
            PathBuf::from("/var/log/rpm-basic/basic.log"),
            PathBuf::from("/var/tmp/rpm-basic"),
        ]
    );
    assert_eq!(
        metadata.get_file_entries().unwrap(),
        vec![
            FileEntry {
                path: PathBuf::from("/etc/rpm-basic/example_config.toml"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 31,
                flags: FileFlags::CONFIG,
                digest: Some(FileDigest {
                    digest: "53a79039d2d619dd41cd04d550d94c531ec634cda9457f25031c141d8e4820e8"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/bin/rpm-basic"),
                mode: FileMode::Regular {
                    permissions: 0o0644
                },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 118,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "a2919ab787acdb6f6ae85a8f18c4e983745988ac6c1cd0ec75c8971196d2953c"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256
                }),
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic"),
                mode: FileMode::Dir {
                    permissions: 0o0755
                },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic/module"),
                mode: FileMode::Dir {
                    permissions: 0o0755
                },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic/module/__init__.py"),
                mode: FileMode::Regular {
                    permissions: 0o0644
                },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic/module/hello.py"),
                mode: FileMode::Regular {
                    permissions: 0o0644
                },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 53,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "b184c98581244d04ffbe7e17af060daf515a1e79f869d5ac6fffb8276ea61ca1"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/share/doc/rpm-basic"),
                mode: FileMode::Dir { permissions: 0o755 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/share/doc/rpm-basic/README"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 31,
                flags: FileFlags::DOC,
                digest: Some(FileDigest {
                    digest: "7b4da30e634d1513f7524f07bd2598967d7c9ef65a623bae31709a8ddb7c4277"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/usr/share/rpm-basic/example_data.xml"),
                mode: FileMode::Regular { permissions: 0o644 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 95,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: "951d8433ea613c80a0515341edccc5b59f78ad6ed71b12127c0a3407d04b250e"
                        .to_owned(),
                    algo: DigestAlgorithm::Sha2_256
                }),
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/var/log/rpm-basic/basic.log"),
                mode: FileMode::Regular { permissions: 0 },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::GHOST,
                digest: None,
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
            FileEntry {
                path: PathBuf::from("/var/tmp/rpm-basic"),
                mode: FileMode::Dir {
                    permissions: 0o0755
                },
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(1681068559),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: "".to_owned(),
                ima_signature: None,
            },
        ]
    );

    assert_eq!(
        metadata.get_changelog_entries().unwrap(),
        vec![
            ChangelogEntry {
                name: "Walter White <ww@savewalterwhite.com> - 3.3.3-3".to_owned(),
                timestamp: 1623672000,
                description: "- I'm not in the meth business. I'm in the empire business."
                    .to_owned()
            },
            ChangelogEntry {
                name: "Gustavo Fring <gus@lospolloshermanos.com> - 2.2.2-2".to_owned(),
                timestamp: 1619352000,
                description: "- Never Make The Same Mistake Twice.".to_owned()
            },
            ChangelogEntry {
                name: "Mike Ehrmantraut <mike@lospolloshermanos.com> - 1.1.1-1".to_owned(),
                timestamp: 1617192000,
                description: "- Just because you shot Jesse James, don't make you Jesse James."
                    .to_owned()
            },
        ]
    );

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![
            Dependency::any("/usr/bin/ls"),
            Dependency::any("aaronpaul"),
            Dependency::any("breaking(bad)"),
            Dependency::config("rpm-basic", "1:2.3.4-5.el9"),
            Dependency::eq("rpm-basic", "1:2.3.4-5.el9"),
            Dependency::eq("shock", "33")
        ]
    );
    assert_eq!(
        metadata.get_requires().unwrap(),
        vec![
            Dependency::script_pre("/usr/sbin/ego"),
            Dependency::config("rpm-basic", "1:2.3.4-5.el9"),
            Dependency::greater_eq("methylamine", "1.0.0-1"),
            Dependency::less_eq("morality", "2"),
            Dependency::script_post("regret"),
            Dependency::rpmlib("CompressedFileNames", "3.0.4-1"),
            Dependency::rpmlib("FileDigests", "4.6.0-1"),
            Dependency::rpmlib("PayloadFilesHavePrefix", "4.0-1"),
        ]
    );
    assert_eq!(
        metadata.get_conflicts().unwrap(),
        vec![Dependency::greater("hank", "35")]
    );
    assert_eq!(
        metadata.get_obsoletes().unwrap(),
        vec![
            Dependency::less("gusfring", "32.1-0"),
            Dependency::less("tucosalamanca", "444"),
        ]
    );
    assert_eq!(
        metadata.get_supplements().unwrap(),
        vec![Dependency::eq("comedy", "0:11.1-4")]
    );
    assert_eq!(
        metadata.get_suggests().unwrap(),
        vec![Dependency::any("chilipowder")]
    );
    assert_eq!(
        metadata.get_enhances().unwrap(),
        vec![Dependency::greater("purity", "9000")]
    );
    assert_eq!(
        metadata.get_recommends().unwrap(),
        vec![
            Dependency::any("SaulGoodman(CriminalLawyer)"),
            Dependency::greater("huel", "9:11.0-0"),
        ]
    );

    Ok(())
}

#[test]
fn test_empty_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::rpm_empty_path())?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-empty");
    assert!(metadata.get_epoch().is_err());
    assert_eq!(metadata.get_version().unwrap(), "0");
    assert_eq!(metadata.get_release().unwrap(), "0");
    assert_eq!(metadata.get_arch().unwrap(), "x86_64");
    assert_eq!(metadata.get_description().unwrap(), "");
    assert_eq!(metadata.get_summary().unwrap(), "\"\"");
    assert_eq!(metadata.get_license().unwrap(), "LGPL");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert_eq!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    );
    assert_eq!(metadata.get_installed_size().unwrap(), 0);

    assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
    assert!(matches!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    ));
    assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));

    assert!(metadata.get_file_paths()?.is_empty());
    assert!(metadata.get_file_entries()?.is_empty());
    assert!(metadata.get_changelog_entries().unwrap().is_empty());

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![
            Dependency::eq("rpm-empty", "0-0"),
            Dependency::eq("rpm-empty(x86-64)", "0-0"),
        ]
    );
    assert_eq!(
        metadata.get_requires().unwrap(),
        vec![
            Dependency::rpmlib("CompressedFileNames", "3.0.4-1"),
            Dependency::rpmlib("FileDigests", "4.6.0-1"),
            Dependency::rpmlib("PayloadFilesHavePrefix", "4.0-1"),
        ]
    );
    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    Ok(())
}

#[test]
fn test_empty_source_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::rpm_empty_source_path())?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), true);
    assert_eq!(metadata.get_name().unwrap(), "rpm-empty");
    assert!(metadata.get_epoch().is_err());
    assert_eq!(metadata.get_version().unwrap(), "0");
    assert_eq!(metadata.get_release().unwrap(), "0");
    assert_eq!(metadata.get_arch().unwrap(), "x86_64");
    assert_eq!(metadata.get_description().unwrap(), "");
    assert_eq!(metadata.get_summary().unwrap(), "\"\"");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");
    assert_eq!(metadata.get_license().unwrap(), "LGPL");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
    assert!(matches!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    ));
    assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));

    assert_eq!(
        metadata.get_file_entries().unwrap(),
        vec![FileEntry {
            path: PathBuf::from("rpm-empty.spec"),
            mode: FileMode::Regular { permissions: 0o644 },
            ownership: FileOwnership {
                user: "root".to_owned(),
                group: "root".to_owned()
            },
            modified_at: Timestamp(1681068559),
            size: 162,
            flags: FileFlags::SPECFILE,
            digest: Some(FileDigest {
                digest: "c72be74016e47dd5fec1021d399c945c2dae699e9c80c968c00a95e6ac82857c"
                    .to_owned(),
                algo: DigestAlgorithm::Sha2_256,
            }),
            caps: None,
            linkto: "".to_owned(),
            ima_signature: None,
        },]
    );
    assert!(metadata.get_changelog_entries().unwrap().is_empty());

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![Dependency::eq("rpm-empty", "0-0")]
    );
    assert_eq!(
        metadata.get_requires().unwrap(),
        vec![
            Dependency::rpmlib("CompressedFileNames", "3.0.4-1"),
            Dependency::rpmlib("FileDigests", "4.6.0-1"),
        ]
    );

    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    Ok(())
}
