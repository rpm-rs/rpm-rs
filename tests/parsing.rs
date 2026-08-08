use std::fs::File;
#[cfg(feature = "payload")]
use std::io::Write;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use pretty_assertions::assert_eq;
use rpm::*;

mod common;

const COOKIE: &str = "localhost 1681068559";

/// Verify that the lead, signature header, header, and payload boundaries
/// of each fixture RPM (v4, v6, signed, unsigned, constructed) point to
/// valid magic bytes for their respective segment types.
#[test]
fn test_package_segment_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    assert_boundaries(common::pkgs::v4::RPM_EMPTY.as_ref())?;
    assert_boundaries(common::pkgs::v4::RPM_BASIC.as_ref())?;
    assert_boundaries(common::pkgs::v4::RPM_BASIC_EDDSA_SIGNED.as_ref())?;
    assert_boundaries(common::pkgs::v4::RPM_BASIC_ECDSA_SIGNED.as_ref())?;
    assert_boundaries(common::pkgs::v4::RPM_BASIC_RSA_SIGNED.as_ref())?;
    assert_boundaries(common::pkgs::v4::RPM_BASIC_IMA_SIGNED.as_ref())?;
    assert_boundaries(common::pkgs::v4::src::RPM_EMPTY_SRC.as_ref())?;
    assert_boundaries(common::pkgs::v4::src::RPM_BASIC_SRC.as_ref())?;

    assert_boundaries(common::pkgs::v6::RPM_EMPTY.as_ref())?;
    assert_boundaries(common::pkgs::v6::RPM_BASIC.as_ref())?;
    assert_boundaries(common::pkgs::v6::RPM_BASIC_MLDSA_SIGNED.as_ref())?;
    assert_boundaries(common::pkgs::v6::RPM_BASIC_MULTI_SIGNED.as_ref())?;

    #[cfg(feature = "payload")]
    {
        let mut temp = tempfile::NamedTempFile::new()?;

        let constructed_pkg =
            rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "").build()?;
        constructed_pkg.write(&mut temp)?;
        temp.flush()?;
        assert_boundaries(temp.path())?;
        temp.close()?;
    }

    #[cfg(all(feature = "payload", feature = "signature-meta"))]
    {
        #[cfg(feature = "signature-pgp")]
        use rpm::signature::pgp::Signer;
        #[cfg(feature = "signature-sequoia")]
        use rpm::signature::sequoia::Signer;
        let signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let constructed_pkg_with_sig =
            rpm::PackageBuilder::new("empty-package", "0", "MIT", "x86_64", "")
                .build_and_sign(signer)?;

        let mut temp = tempfile::NamedTempFile::new()?;

        constructed_pkg_with_sig.write(&mut temp)?;
        temp.flush()?;
        assert_boundaries(temp.path())?;
        temp.close()?;
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

        match package.metadata.get_payload_compressor().unwrap() {
            CompressionType::Gzip => assert!(buf.starts_with(&[0x1f, 0x8b])),
            CompressionType::Zstd => assert!(buf.starts_with(&[0x28, 0xb5, 0x2f, 0xfd])),
            CompressionType::Xz => assert!(buf.starts_with(&[0xfd, 0x37, 0x7a, 0x58, 0x5a])),
            CompressionType::Bzip2 => assert!(buf.starts_with(&[0x42, 0x5a])),
            CompressionType::None => {
                // CPIO magic "070701" or RPM "stripped" CPIO magic "07070X"
                assert!(buf.starts_with(b"070701") || buf.starts_with(b"07070X"));
            }
        };

        Ok(())
    }

    Ok(())
}

/// Parse the rpm-file-attrs fixture and verify metadata
#[test]
fn test_file_attrs() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::pkgs::v6::RPM_FILE_ATTRS)?;
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
    assert_eq!(
        metadata.get_build_time().unwrap(),
        common::FIXTURE_SOURCE_DATE as u64
    );

    assert_eq!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    );
    assert_eq!(metadata.get_installed_size().unwrap(), 301);

    assert_eq!(metadata.get_cookie().unwrap(), COOKIE);
    assert_eq!(
        metadata.get_source_rpm().unwrap(),
        "rpm-file-attrs-1.0-1.src.rpm"
    );
    assert_eq!(
        metadata.get_file_digest_algorithm().unwrap(),
        DigestAlgorithm::Sha2_256
    );

    assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
    assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));
    assert!(matches!(
        metadata.get_packager(),
        Err(Error::TagNotFound(_))
    ));
    assert!(matches!(metadata.get_vcs(), Err(Error::TagNotFound(_))));

    // File metadata and content assertions are in payload.rs::test_files_file_attrs
    assert_eq!(metadata.get_file_entries().unwrap().len(), 26);
    assert_eq!(metadata.get_file_paths().unwrap().len(), 26);
    assert!(metadata.get_changelog_entries().unwrap().is_empty());

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![
            // TODO: understand what this means and why it is both provided and required
            Dependency::config("rpm-file-attrs", "1.0-1".to_owned()),
            // Auto-generated sysusers provides from /usr/lib/sysusers.d/rpm-file-attrs.conf
            Dependency {
                name: "group(bob)".to_owned(),
                flags: DependencyFlags::FIND_PROVIDES,
                version: "".to_owned(),
            },
            Dependency {
                name: "group(bob)".to_owned(),
                flags: DependencyFlags::EQUAL | DependencyFlags::FIND_PROVIDES,
                version: "ZyBib2IgLSAiQm9iIGdyb3VwIgAA".to_owned(),
            },
            Dependency {
                name: "group(jane)".to_owned(),
                flags: DependencyFlags::FIND_PROVIDES,
                version: "".to_owned(),
            },
            Dependency::eq("rpm-file-attrs".to_owned(), "1.0-1".to_owned()),
            Dependency {
                name: "user(bob)".to_owned(),
                flags: DependencyFlags::EQUAL | DependencyFlags::FIND_PROVIDES,
                version: "dSBib2IgLSAiQm9iIHVzZXIi".to_owned(),
            },
            Dependency {
                name: "user(jane)".to_owned(),
                flags: DependencyFlags::EQUAL | DependencyFlags::FIND_PROVIDES,
                version: "dSBqYW5lIC0gIkphbmUgdXNlciIA".to_owned(),
            },
        ]
    );
    assert_eq!(
        metadata.get_requires().unwrap(),
        vec![
            Dependency::config("rpm-file-attrs", "1.0-1"),
            Dependency::group("bob"),
            Dependency::group("jane"),
            Dependency::rpmlib("FileCaps", "4.6.1-1"),
            Dependency::rpmlib("LargeFiles", "4.12.0-1"),
            Dependency::user("jane"),
        ]
    );
    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    // Signature header checksums (v6 package)
    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "269fab2852005f88bf651d90756cd17113d23d6bf0c8e28ede612611c1a4c1c8"
    );
    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256)
            .unwrap(),
        "92ebb502d4eba6038db150e02a4e3811976d12f26472a8a8cd789539d5422a77"
    );

    // Payload digest
    assert_eq!(
        metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADSHA256)
            .unwrap(),
        vec!["1bc45cd34f5965dd00700bbf00bf7f1dd0f9a5a060be994428611ad32d3c6f3d"]
    );

    Ok(())
}

/// Parse the rpm-file-types fixture and verify metadata, focusing on unusual
/// file names (spaces, special characters) and binary content (PNG image).
#[test]
fn test_file_types() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::pkgs::v6::RPM_FILE_TYPES)?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-file-types");
    assert_eq!(metadata.get_epoch().unwrap(), 0);
    assert_eq!(metadata.get_version().unwrap(), "1.0");
    assert_eq!(metadata.get_release().unwrap(), "1");
    assert_eq!(metadata.get_arch().unwrap(), "noarch");
    assert_eq!(
        metadata.get_description().unwrap(),
        "A package for exercising RPM handling of different file content types\nand unusual file paths."
    );
    assert_eq!(
        metadata.get_summary().unwrap(),
        "Test RPM handling of various file content types and paths"
    );
    assert_eq!(metadata.get_license().unwrap(), "MIT");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(
        metadata.get_build_time().unwrap(),
        common::FIXTURE_SOURCE_DATE as u64
    );

    assert_eq!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    );
    assert_eq!(metadata.get_installed_size().unwrap(), 2048);

    assert_eq!(metadata.get_cookie().unwrap(), COOKIE);
    assert_eq!(
        metadata.get_source_rpm().unwrap(),
        "rpm-file-types-1.0-1.src.rpm"
    );
    assert_eq!(
        metadata.get_file_digest_algorithm().unwrap(),
        DigestAlgorithm::Sha2_256
    );

    assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
    assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));
    assert!(matches!(
        metadata.get_packager(),
        Err(Error::TagNotFound(_))
    ));
    assert!(matches!(metadata.get_vcs(), Err(Error::TagNotFound(_))));

    // File metadata and content assertions are in payload.rs::test_files_file_types
    assert_eq!(metadata.get_file_entries().unwrap().len(), 3);
    assert_eq!(metadata.get_file_paths().unwrap().len(), 3);
    assert!(metadata.get_changelog_entries().unwrap().is_empty());

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![Dependency::eq("rpm-file-types", "0:1.0-1")]
    );
    assert_eq!(
        metadata.get_requires().unwrap(),
        vec![Dependency::rpmlib("LargeFiles", "4.12.0-1")]
    );
    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    // Signature header checksums (v6 package)
    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "7874f3b5b4cce3bfb26c3899ffdb5c3f13aeaec4f2b45e9f47e212776a0037fa"
    );
    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256)
            .unwrap(),
        "dc8a28fd295c68837f45a81be188b869d52cdec557048629656f81f18909788f"
    );

    // Payload digest
    assert_eq!(
        metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADSHA256)
            .unwrap(),
        vec!["247ac97e28b950c53f1fa3b34d9eb55d53100d12f60c785b2b8ce6c497fd3231"]
    );

    Ok(())
}

/// Parse the rpm-hardlinks fixture and verify metadata, including
/// inode deduplication and nlink tracking.
#[test]
fn test_hardlinks_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::pkgs::v6::RPM_HARDLINKS)?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-hardlinks");
    assert!(matches!(metadata.get_epoch(), Err(Error::TagNotFound(_))));
    assert_eq!(metadata.get_version().unwrap(), "1.0");
    assert_eq!(metadata.get_release().unwrap(), "1");
    assert_eq!(metadata.get_arch().unwrap(), "noarch");
    assert_eq!(
        metadata.get_description().unwrap(),
        "A package for exercising RPM hard link handling in the payload.\n\
         Contains sets of hard-linked files to test inode deduplication\n\
         and the RPMTAG_FILEINODES / RPMTAG_FILENLINKS tags."
    );
    assert_eq!(
        metadata.get_summary().unwrap(),
        "Test RPM hard link handling"
    );
    assert_eq!(metadata.get_license().unwrap(), "MIT");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(metadata.get_build_time().unwrap(), 1681068559);

    assert_eq!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    );
    assert_eq!(metadata.get_installed_size().unwrap(), 52);

    assert_eq!(metadata.get_cookie().unwrap(), "localhost 1681068559");
    assert_eq!(
        metadata.get_source_rpm().unwrap(),
        "rpm-hardlinks-1.0-1.src.rpm"
    );
    assert_eq!(
        metadata.get_file_digest_algorithm().unwrap(),
        DigestAlgorithm::Sha2_256
    );

    assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
    assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));
    assert!(matches!(
        metadata.get_packager(),
        Err(Error::TagNotFound(_))
    ));
    assert!(matches!(metadata.get_vcs(), Err(Error::TagNotFound(_))));

    // 6 files: alpha-1, alpha-2, alpha-3, beta-1, beta-2, standalone
    assert_eq!(metadata.get_file_entries().unwrap().len(), 6);
    assert_eq!(metadata.get_file_paths().unwrap().len(), 6);
    assert!(metadata.get_changelog_entries().unwrap().is_empty());

    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![Dependency::eq("rpm-hardlinks", "1.0-1")]
    );
    assert_eq!(
        metadata.get_requires().unwrap(),
        vec![Dependency::rpmlib("LargeFiles", "4.12.0-1")]
    );
    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    // Verify hardlink metadata via shared inodes
    let inodes = metadata
        .header
        .get_entry_data_as_u32_array(IndexTag::RPMTAG_FILEINODES)
        .unwrap();

    // alpha-1, alpha-2, alpha-3 share an inode
    assert_eq!(inodes[0], inodes[1]);
    assert_eq!(inodes[1], inodes[2]);

    // beta-1, beta-2 share a different inode
    assert_eq!(inodes[3], inodes[4]);
    assert_ne!(inodes[3], inodes[0]);

    // standalone has its own inode
    assert_ne!(inodes[5], inodes[0]);
    assert_ne!(inodes[5], inodes[3]);

    // Signature checksums (v6 package)
    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "83eb72fe3720ae2b4696da421d5cc34ef0acd66543b71746e9a13954c77fe7a4"
    );
    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256)
            .unwrap(),
        "4422ac5a772b85bad8febeeac2850506805f9e7a0c07ea2e2d56d71d3c2b5557"
    );

    // Payload digest
    assert_eq!(
        metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADSHA256)
            .unwrap(),
        vec!["46b58e9fa6f9b7db79738203322df03612f439053140a5aefa9f1b3654db9a20"]
    );

    Ok(())
}

/// Parse v4 and v6 rpm-basic fixtures and verify metadata fields.
#[test]
fn test_basic_package() -> Result<(), Box<dyn std::error::Error>> {
    let v4 = Package::open(common::pkgs::v4::RPM_BASIC)?;
    let v6 = Package::open(common::pkgs::v6::RPM_BASIC)?;

    for package in [&v4, &v6] {
        let metadata = &package.metadata;

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
        assert_eq!(metadata.get_cookie().unwrap(), COOKIE);

        assert_eq!(metadata.get_build_host().unwrap(), "localhost");
        assert_eq!(
            metadata.get_build_time().unwrap(),
            common::FIXTURE_SOURCE_DATE as u64
        );

        assert_eq!(
            metadata.get_payload_compressor().unwrap(),
            CompressionType::None
        );

        // File metadata and content assertions are in payload.rs::test_basic_package_files
        assert_eq!(metadata.get_file_entries().unwrap().len(), 11);
        assert_eq!(metadata.get_file_paths().unwrap().len(), 11);

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

        // Both v4 and v6 have SHA256 header checksum
        assert!(
            metadata
                .signature
                .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
                .is_ok()
        );
    }

    // Signature header checksums - v4 has SHA1, v6 has SHA3_256
    assert_eq!(
        v4.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "54367497f885c1295f6930b415edc151924fb20f789557010151a91c4de62d26"
    );
    assert_eq!(
        v4.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA1)
            .unwrap(),
        "f3655318e4f8fd511ca7f0c674fd27a7f6cf2061"
    );

    assert_eq!(
        v6.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "352ff65e76ef151baf393b15bdcbc8a1f32b42d910bd767e2af7801e46703aef"
    );
    assert_eq!(
        v6.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256)
            .unwrap(),
        "759944f4ffe630aff90f7972710019323ae639db520792f4fe5cc3f89c79c8da"
    );

    // Payload digests differ between v4 and v6
    assert_eq!(
        v4.metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADSHA256)
            .unwrap(),
        vec!["3ef1e3e3a2cd7d82fe48a3daee1f19202bf7582aff85a701b1e47ffbbeaddb63"]
    );
    assert_eq!(
        v6.metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADSHA256)
            .unwrap(),
        vec!["69b3410877d629ad8b59909fc343ab58117b4155c6de3935a42964e589b6ea8f"]
    );

    // v4 and v6 have different rpmlib requires
    assert_eq!(
        v4.metadata.get_requires().unwrap(),
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
        v6.metadata.get_requires().unwrap(),
        vec![
            Dependency::script_pre("/usr/sbin/ego"),
            Dependency::config("rpm-basic", "1:2.3.4-5.el9"),
            Dependency::greater_eq("methylamine", "1.0.0-1"),
            Dependency::less_eq("morality", "2"),
            Dependency::script_post("regret"),
            Dependency::rpmlib("LargeFiles", "4.12.0-1"),
        ]
    );

    Ok(())
}

/// Parse v4 and v6 rpm-empty fixtures and verify metadata for a minimal
/// package with no files, no changelogs, and only auto-generated provides.
#[test]
fn test_empty_package() -> Result<(), Box<dyn std::error::Error>> {
    let v4 = Package::open(common::pkgs::v4::RPM_EMPTY)?;
    let v6 = Package::open(common::pkgs::v6::RPM_EMPTY)?;

    for package in [&v4, &v6] {
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
        assert_eq!(
            metadata.get_build_time().unwrap(),
            common::FIXTURE_SOURCE_DATE as u64
        );

        assert_eq!(
            metadata.get_payload_compressor().unwrap(),
            CompressionType::None
        );
        assert_eq!(metadata.get_installed_size().unwrap(), 0);

        assert_eq!(metadata.get_cookie().unwrap(), COOKIE);
        assert_eq!(metadata.get_source_rpm().unwrap(), "rpm-empty-0-0.src.rpm");
        assert_eq!(
            metadata.get_file_digest_algorithm().unwrap(),
            DigestAlgorithm::Sha2_256
        );

        assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
        assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));
        assert!(matches!(
            metadata.get_packager(),
            Err(Error::TagNotFound(_))
        ));
        assert!(matches!(metadata.get_vcs(), Err(Error::TagNotFound(_))));

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
        assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
        assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
        assert_eq!(metadata.get_supplements().unwrap(), vec![]);
        assert_eq!(metadata.get_suggests().unwrap(), vec![]);
        assert_eq!(metadata.get_enhances().unwrap(), vec![]);
        assert_eq!(metadata.get_recommends().unwrap(), vec![]);

        // Both v4 and v6 have SHA256 header checksum
        assert!(
            metadata
                .signature
                .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
                .is_ok()
        );

        // Both v4 and v6 have the same PAYLOADSHA256
        assert_eq!(
            metadata
                .header
                .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADSHA256)
                .unwrap(),
            vec!["23d0422b4fea28f771e872741bb370790b3cd0538eafb461233e820b84b57a2e"]
        );
    }

    // v4 Signature header checksums
    assert_eq!(
        v4.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "bd638771e0ddee7fb4fd2201e13ef00d10da7b23769fd4d3709e7469203565cd"
    );
    assert_eq!(
        v4.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA1)
            .unwrap(),
        "a372f6650d7b0391a0698562fb3165a7ac8f0492"
    );

    // v6 Signature header checksums
    assert_eq!(
        v6.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "e2853aef4ed2f0b9be391c1222a7fa39e6ba187e81a7d2e963254e10a0e4f21b"
    );
    assert_eq!(
        v6.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256)
            .unwrap(),
        "33666a1f97bf70776f7a6b5f7af9e71f2f7f5dd5adfac4f74d68829490ac87bd"
    );
    assert!(
        v6.metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA1)
            .is_err()
    );

    // v4 has rpmlib requires, v6 does not
    assert_eq!(
        v4.metadata.get_requires().unwrap(),
        vec![
            Dependency::rpmlib("CompressedFileNames", "3.0.4-1"),
            Dependency::rpmlib("FileDigests", "4.6.0-1"),
            Dependency::rpmlib("PayloadFilesHavePrefix", "4.0-1"),
        ]
    );
    assert_eq!(v6.metadata.get_requires().unwrap(), vec![]);

    Ok(())
}

/// Parse v4 and v6 rpm-empty source RPM fixtures and verify metadata.
#[test]
fn test_empty_source_package() -> Result<(), Box<dyn std::error::Error>> {
    let v4 = Package::open(common::pkgs::v4::src::RPM_EMPTY_SRC)?;
    let v6 = Package::open(common::pkgs::v6::src::RPM_EMPTY_SRC)?;

    for package in [&v4, &v6] {
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
        assert_eq!(
            metadata.get_build_time().unwrap(),
            common::FIXTURE_SOURCE_DATE as u64
        );

        assert_eq!(metadata.get_cookie().unwrap(), COOKIE);
        assert_eq!(
            metadata.get_file_digest_algorithm().unwrap(),
            DigestAlgorithm::Sha2_256
        );

        assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
        assert!(matches!(
            metadata.get_payload_compressor().unwrap(),
            CompressionType::None
        ));
        assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));
        assert!(matches!(
            metadata.get_packager(),
            Err(Error::TagNotFound(_))
        ));
        assert!(matches!(metadata.get_vcs(), Err(Error::TagNotFound(_))));
        assert!(matches!(
            metadata.get_source_rpm(),
            Err(Error::TagNotFound(_))
        ));
        assert_eq!(metadata.get_installed_size().unwrap(), 162);

        // File metadata and content assertions are in payload.rs::test_files_empty_source_package
        assert_eq!(metadata.get_file_entries().unwrap().len(), 1);
        assert_eq!(metadata.get_file_paths().unwrap().len(), 1);
        assert!(metadata.get_changelog_entries().unwrap().is_empty());

        assert_eq!(
            metadata.get_provides().unwrap(),
            vec![Dependency::eq("rpm-empty", "0-0")]
        );
        assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
        assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
        assert_eq!(metadata.get_supplements().unwrap(), vec![]);
        assert_eq!(metadata.get_suggests().unwrap(), vec![]);
        assert_eq!(metadata.get_enhances().unwrap(), vec![]);
        assert_eq!(metadata.get_recommends().unwrap(), vec![]);
    }

    // v4 has different rpmlib requires than v6
    assert_eq!(
        v4.metadata.get_requires().unwrap(),
        vec![
            Dependency::rpmlib("CompressedFileNames", "3.0.4-1"),
            Dependency::rpmlib("FileDigests", "4.6.0-1"),
        ]
    );
    assert_eq!(
        v6.metadata.get_requires().unwrap(),
        vec![Dependency::rpmlib("LargeFiles", "4.12.0-1")]
    );

    Ok(())
}

/// Parse the rpm-scriptlets fixture and verify scriptlets, triggers, and file triggers.
#[test]
fn test_scriptlets_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::pkgs::v6::RPM_SCRIPTLETS)?;
    let metadata = &package.metadata;

    assert_eq!(metadata.is_source_package(), false);
    assert_eq!(metadata.get_name().unwrap(), "rpm-scriptlets");
    assert!(metadata.get_epoch().is_err());
    assert_eq!(metadata.get_version().unwrap(), "1.0");
    assert_eq!(metadata.get_release().unwrap(), "1");
    assert_eq!(metadata.get_arch().unwrap(), "noarch");
    assert_eq!(
        metadata.get_description().unwrap(),
        "A package for exercising RPM scriptlets, triggers, and file triggers."
    );
    assert_eq!(
        metadata.get_summary().unwrap(),
        "Test RPM scriptlets and triggers"
    );
    assert_eq!(metadata.get_license().unwrap(), "MIT");
    assert_eq!(metadata.get_group().unwrap(), "Unspecified");

    assert_eq!(metadata.get_build_host().unwrap(), "localhost");
    assert_eq!(
        metadata.get_build_time().unwrap(),
        common::FIXTURE_SOURCE_DATE as u64
    );

    assert_eq!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::None
    );
    assert_eq!(metadata.get_installed_size().unwrap(), 15);

    assert_eq!(metadata.get_cookie().unwrap(), COOKIE);
    assert_eq!(
        metadata.get_source_rpm().unwrap(),
        "rpm-scriptlets-1.0-1.src.rpm"
    );
    assert_eq!(
        metadata.get_file_digest_algorithm().unwrap(),
        DigestAlgorithm::Sha2_256
    );

    assert!(matches!(metadata.get_vendor(), Err(Error::TagNotFound(_))));
    assert!(matches!(metadata.get_url(), Err(Error::TagNotFound(_))));
    assert!(matches!(
        metadata.get_packager(),
        Err(Error::TagNotFound(_))
    ));
    assert!(matches!(metadata.get_vcs(), Err(Error::TagNotFound(_))));

    assert_eq!(metadata.get_file_entries().unwrap().len(), 1);
    assert_eq!(metadata.get_file_paths().unwrap().len(), 1);
    assert!(metadata.get_changelog_entries().unwrap().is_empty());

    // Dependencies
    assert_eq!(
        metadata.get_provides().unwrap(),
        vec![Dependency::eq("rpm-scriptlets", "1.0-1")]
    );
    assert_eq!(metadata.get_conflicts().unwrap(), vec![]);
    assert_eq!(metadata.get_obsoletes().unwrap(), vec![]);
    assert_eq!(metadata.get_supplements().unwrap(), vec![]);
    assert_eq!(metadata.get_suggests().unwrap(), vec![]);
    assert_eq!(metadata.get_enhances().unwrap(), vec![]);
    assert_eq!(metadata.get_recommends().unwrap(), vec![]);

    // Basic scriptlets
    // NOTE: RPM includes comments that follow each scriptlet body up to the
    // next section marker, so the script bodies include trailing comments.
    let sh = Some(vec!["/bin/sh".to_owned()]);

    assert_eq!(
        metadata.get_pre_install_script().unwrap(),
        Scriptlet {
            script: "echo \"pre-install\"\n\n# Explicit interpreter".to_owned(),
            flags: None,
            program: sh.clone(),
        }
    );
    assert_eq!(
        metadata.get_post_install_script().unwrap(),
        Scriptlet {
            script: "echo \"post-install\"".to_owned(),
            flags: None,
            program: sh.clone(),
        }
    );
    assert_eq!(
        metadata.get_pre_uninstall_script().unwrap(),
        Scriptlet {
            script: "echo \"pre-uninstall\"".to_owned(),
            flags: None,
            program: sh.clone(),
        }
    );
    assert_eq!(
        metadata.get_post_uninstall_script().unwrap(),
        Scriptlet {
            script: "echo \"post-uninstall\"\n\n# Transaction-level scriptlets".to_owned(),
            flags: None,
            program: sh.clone(),
        }
    );
    assert_eq!(
        metadata.get_pre_trans_script().unwrap(),
        Scriptlet {
            script: "echo \"pre-transaction\"".to_owned(),
            flags: None,
            program: sh.clone(),
        }
    );
    assert_eq!(
        metadata.get_post_trans_script().unwrap(),
        Scriptlet {
            script: "echo \"post-transaction\"\n\n# Verify scriptlet".to_owned(),
            flags: None,
            program: sh.clone(),
        }
    );
    assert_eq!(
        metadata.get_verify_script().unwrap(),
        Scriptlet {
            script: "echo \"verify\"\n\n# Triggers (against a hypothetical target package)"
                .to_owned(),
            flags: None,
            program: sh.clone(),
        }
    );

    // Package triggers: triggerprein, triggerin (> 5.0), triggerun (<= 6.0), triggerpostun
    assert_eq!(
        metadata.get_triggers().unwrap(),
        vec![
            Trigger {
                script: "echo \"trigger-pre-install on bash\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "bash".to_owned(),
                    flags: DependencyFlags::TRIGGERPREIN,
                    version: "".to_owned(),
                }],
            },
            Trigger {
                script: "echo \"trigger-install on bash > 5.0\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "bash".to_owned(),
                    flags: DependencyFlags::TRIGGERIN | DependencyFlags::GREATER,
                    version: "5.0".to_owned(),
                }],
            },
            Trigger {
                script: "echo \"trigger-uninstall on bash <= 6.0\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "bash".to_owned(),
                    flags: DependencyFlags::TRIGGERUN | DependencyFlags::LE,
                    version: "6.0".to_owned(),
                }],
            },
            Trigger {
                script: "echo \"trigger-post-uninstall on bash\"\n\n# File triggers".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "bash".to_owned(),
                    flags: DependencyFlags::TRIGGERPOSTUN,
                    version: "".to_owned(),
                }],
            },
        ]
    );

    // File triggers (filetriggerin, filetriggerun, filetriggerpostun -- /usr/lib)
    assert_eq!(
        metadata.get_file_triggers().unwrap(),
        vec![
            Trigger {
                script: "echo \"file-trigger-install in /usr/lib\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "/usr/lib".to_owned(),
                    flags: DependencyFlags::TRIGGERIN,
                    version: "".to_owned(),
                }],
            },
            Trigger {
                script: "echo \"file-trigger-uninstall in /usr/lib\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "/usr/lib".to_owned(),
                    flags: DependencyFlags::TRIGGERUN,
                    version: "".to_owned(),
                }],
            },
            Trigger {
                script: "echo \"file-trigger-post-uninstall in /usr/lib\"\n\n# Transaction-level file triggers".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "/usr/lib".to_owned(),
                    flags: DependencyFlags::TRIGGERPOSTUN,
                    version: "".to_owned(),
                }],
            },
        ]
    );

    // Transaction file triggers (transfiletriggerin, etc. -- /usr/bin)
    assert_eq!(
        metadata.get_trans_file_triggers().unwrap(),
        vec![
            Trigger {
                script: "echo \"trans-file-trigger-install in /usr/bin\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "/usr/bin".to_owned(),
                    flags: DependencyFlags::TRIGGERIN,
                    version: "".to_owned(),
                }],
            },
            Trigger {
                script: "echo \"trans-file-trigger-uninstall in /usr/bin\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "/usr/bin".to_owned(),
                    flags: DependencyFlags::TRIGGERUN,
                    version: "".to_owned(),
                }],
            },
            Trigger {
                script: "echo \"trans-file-trigger-post-uninstall in /usr/bin\"".to_owned(),
                program: vec!["/bin/sh".to_owned()],
                conditions: vec![TriggerCondition {
                    name: "/usr/bin".to_owned(),
                    flags: DependencyFlags::TRIGGERPOSTUN,
                    version: "".to_owned(),
                }],
            },
        ]
    );

    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA256)
            .unwrap(),
        "b2a74081a9e61b65cb546fb26d0072c7ab41f55a9f3b163b6c301d517ee8663d"
    );
    assert_eq!(
        metadata
            .signature
            .get_entry_data_as_string(IndexSignatureTag::RPMSIGTAG_SHA3_256)
            .unwrap(),
        "f9200b308ed7e9303efb99f1f9a22f5eff0a67b9a270d626cd051cbf664d3d81"
    );

    // Payload digest
    assert_eq!(
        metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_PAYLOADSHA256)
            .unwrap(),
        vec!["70d9f63275a86467c02e0e97ba8b66b1a6eb1f3f36fbe2c20bb98953d381e91b"]
    );

    Ok(())
}

/// Parse the rpm-rich-deps fixture and verify rich (boolean) dependencies
/// are correctly read across all dependency types.
#[test]
fn test_rich_deps_package() -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(common::pkgs::v6::RPM_RICH_DEPS)?;
    let metadata = &package.metadata;

    assert_eq!(metadata.get_name().unwrap(), "rpm-rich-deps");
    assert_eq!(metadata.get_version().unwrap(), "1.0");
    assert_eq!(metadata.get_release().unwrap(), "1");
    assert_eq!(metadata.get_arch().unwrap(), "noarch");
    assert_eq!(metadata.get_license().unwrap(), "MIT");
    assert_eq!(
        metadata.get_summary().unwrap(),
        "Test RPM rich (boolean) dependencies"
    );

    // Rich deps are stored as regular dependencies with the boolean
    // expression as the name, flags=ANY, and empty version.
    let requires = metadata.get_requires()?;
    let rich_requires: Vec<_> = requires
        .iter()
        .filter(|d| d.name.starts_with('('))
        .collect();
    assert_eq!(rich_requires.len(), 11);

    // Verify all rich requires have flags=ANY and empty version
    for dep in &rich_requires {
        assert_eq!(
            dep.flags,
            DependencyFlags::ANY,
            "rich dep {} should have ANY flags",
            dep.name
        );
        assert_eq!(
            dep.version, "",
            "rich dep {} should have empty version",
            dep.name
        );
    }

    // Verify specific rich requires are present
    let rich_names: Vec<&str> = rich_requires.iter().map(|d| d.name.as_str()).collect();
    assert!(rich_names.contains(&"(pkgA or pkgB)"));
    assert!(rich_names.contains(&"(pkgC and pkgD)"));
    assert!(rich_names.contains(&"(pkgE if pkgF)"));
    assert!(rich_names.contains(&"(pkgG if pkgH else pkgI)"));
    assert!(rich_names.contains(&"(pkgO with pkgP)"));
    assert!(rich_names.contains(&"(pkgQ without pkgR)"));
    // Nested
    assert!(rich_names.contains(&"((pkgS or pkgT) and pkgU)"));
    assert!(rich_names.contains(&"(pkgV or (pkgW and pkgX))"));
    // With version constraints (embedded in the expression, not in the dep version field)
    assert!(rich_names.contains(&"(pkgBB >= 2.0 or pkgCC >= 3.0)"));
    assert!(rich_names.contains(&"(pkgDD >= 1.0 and pkgEE < 5.0)"));
    assert!(rich_names.contains(&"(pkgFF >= 2.0 if pkgGG >= 1.0)"));

    // Verify rpmlib(RichDependencies) is auto-generated
    assert!(
        requires
            .iter()
            .any(|d| d.name == "rpmlib(RichDependencies)")
    );

    // Rich deps in other dependency types
    let recommends = metadata.get_recommends()?;
    let rich_recommends: Vec<&str> = recommends
        .iter()
        .filter(|d| d.name.starts_with('('))
        .map(|d| d.name.as_str())
        .collect();
    assert!(rich_recommends.contains(&"((pkgY and pkgZ) or pkgAA)"));
    assert!(rich_recommends.contains(&"(pkgHH or pkgII)"));

    let suggests = metadata.get_suggests()?;
    assert!(suggests.iter().any(|d| d.name == "(pkgJJ if pkgKK)"));

    let supplements = metadata.get_supplements()?;
    let rich_supplements: Vec<&str> = supplements
        .iter()
        .filter(|d| d.name.starts_with('('))
        .map(|d| d.name.as_str())
        .collect();
    assert!(rich_supplements.contains(&"(pkgJ unless pkgK)"));
    assert!(rich_supplements.contains(&"(pkgLL and pkgMM)"));

    let enhances = metadata.get_enhances()?;
    assert!(enhances.iter().any(|d| d.name == "(pkgNN or pkgOO)"));

    let conflicts = metadata.get_conflicts()?;
    let rich_conflicts: Vec<&str> = conflicts
        .iter()
        .filter(|d| d.name.starts_with('('))
        .map(|d| d.name.as_str())
        .collect();
    assert!(rich_conflicts.contains(&"(pkgL unless pkgM else pkgN)"));
    assert!(rich_conflicts.contains(&"(pkgPP and pkgQQ)"));

    Ok(())
}

#[test]
fn test_entry_is_present() {
    let meta = PackageMetadata::open(common::pkgs::v6::RPM_BASIC).unwrap();
    assert!(meta.header.entry_is_present(IndexTag::RPMTAG_NAME));
    assert!(!meta.header.entry_is_present(IndexTag::RPMTAG_PREFIXES));
    // Raw u32 should also work
    assert!(meta.header.entry_is_present(1000u32)); // RPMTAG_NAME
    assert!(!meta.header.entry_is_present(9999u32));
}

#[test]
fn test_entry_by_typed_tag() {
    let meta = PackageMetadata::open(common::pkgs::v6::RPM_BASIC).unwrap();
    let data = meta.header.entry(IndexTag::RPMTAG_NAME).unwrap();
    match data {
        IndexData::StringTag(ref s) => assert_eq!(s, "rpm-basic"),
        _ => panic!("expected StringTag, got {data}"),
    }
}

#[test]
fn test_entry_by_raw_u32() {
    let meta = PackageMetadata::open(common::pkgs::v6::RPM_BASIC).unwrap();
    let data = meta.header.entry(1000u32).unwrap(); // RPMTAG_NAME
    match data {
        IndexData::StringTag(ref s) => assert_eq!(s, "rpm-basic"),
        _ => panic!("expected StringTag, got {data}"),
    }
}

#[test]
fn test_entry_not_found() {
    let meta = PackageMetadata::open(common::pkgs::v6::RPM_BASIC).unwrap();
    let err = meta.header.entry(9999u32).unwrap_err();
    assert!(matches!(err, Error::TagNotFound(9999)));
}

#[test]
fn test_tag_not_found_display() {
    let meta = PackageMetadata::open(common::pkgs::v6::RPM_BASIC).unwrap();
    let err = meta.header.entry(IndexTag::RPMTAG_PREFIXES).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("RPMTAG_PREFIXES"),
        "expected tag name in error: {msg}"
    );
}

#[test]
fn test_find_file_entry() -> Result<(), Box<dyn std::error::Error>> {
    let pkg = Package::open(common::pkgs::v4::RPM_BASIC)?;

    // Find an existing file
    let entry = pkg
        .metadata
        .find_file_entry(Path::new("/etc/rpm-basic/example_config.toml"))?
        .expect("config file should be found");
    assert_eq!(entry.basename(), "example_config.toml");
    assert_eq!(entry.dirname(), "/etc/rpm-basic/");
    assert_eq!(entry.size(), 31);
    assert!(entry.flags().contains(FileFlags::CONFIG));

    // Nonexistent path returns None
    assert!(
        pkg.metadata
            .find_file_entry(Path::new("/nonexistent/path"))?
            .is_none()
    );

    // Empty package returns None
    let empty = Package::open(common::pkgs::v4::RPM_EMPTY)?;
    assert!(
        empty
            .metadata
            .find_file_entry(Path::new("/anything"))?
            .is_none()
    );

    Ok(())
}
