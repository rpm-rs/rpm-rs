#[cfg(feature = "payload")]
mod builder;
mod compressor;
#[cfg(feature = "payload")]
mod content;
mod filecaps;
mod headers;
mod package;
#[cfg(feature = "payload")]
mod payload;
mod timestamp;
#[cfg(feature = "payload")]
mod util;

pub mod signature;

pub use headers::*;

pub use compressor::*;

pub use package::*;

#[cfg(feature = "payload")]
pub use builder::*;

#[cfg(feature = "payload")]
pub use content::*;

pub use timestamp::*;

#[cfg(feature = "chrono")]
pub use ::chrono;

pub use filecaps::*;

/// These tests cover payload + metadata integration, but they do equality tests on
/// non-public fields / types, so they can't be actual integration tests, even though
/// they otherwise would make more sense as integration tests.
#[cfg(test)]
#[cfg(feature = "payload")]
mod test_payload_integration {
    use crate::*;
    use pretty_assertions::assert_eq;
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    /// SOURCE_DATE_EPOCH used for building fixture packages (from build_packages.sh)
    /// This timestamp is April 9, 2023 19:29:19 UTC
    pub const FIXTURE_SOURCE_DATE: u32 = 1681068559;

    /// Helper to calculate SHA256 digest of content and return as hex string
    fn calculate_sha256(content: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    /// Test that Package::files() correctly extracts file contents from an
    /// uncompressed RPM package.
    #[test]
    fn test_files_v6_uncompressed() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from a
    /// gzip-compressed RPM package.
    #[test]
    #[cfg(feature = "gzip-compression")]
    fn test_files_v6_gzip() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open("tests/assets/RPMS/v6/gzip/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from a
    /// zstd-compressed RPM package.
    #[test]
    #[cfg(feature = "zstd-compression")]
    fn test_files_v6_zstd() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open("tests/assets/RPMS/v6/zstd/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from an
    /// xz-compressed RPM package.
    #[test]
    #[cfg(feature = "xz-compression")]
    fn test_files_v6_xz() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open("tests/assets/RPMS/v6/xz/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
        test_basic_package_files(&package)
    }

    /// Test that Package::files() correctly extracts file contents from a v4 RPM package,
    /// verifying that v4 and v6 formats produce identical results.
    #[test]
    fn test_files_v4_uncompressed() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
        test_basic_package_files(&package)
    }

    /// Shared test logic for verifying file extraction across all compression types.
    #[track_caller]
    fn test_basic_package_files(package: &Package) -> Result<(), Box<dyn std::error::Error>> {
        // Verify all three file APIs return consistent data and get files for content verification
        let files = assert_file_apis_consistent(package)?;

        // Extract package and verify extracted files match files() API results
        let temp_dir = tempfile::tempdir()?;
        let extract_path = temp_dir.path().join("rpm-basic");
        package.extract(&extract_path)?;
        verify_extracted_files(&extract_path, &files)?;

        // Load expected file contents from source files
        let expected_config = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/example_config.toml"
        ));
        let expected_script = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/multiplication_tables.py"
        ));
        let expected_hello = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/module/hello.py"
        ));
        let expected_xml = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/example_data.xml"
        ));
        let expected_init = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/module/__init__.py"
        ));

        // File 0: /etc/rpm-basic/example_config.toml
        assert_eq!(files[0].content, expected_config);
        assert_eq!(
            files[0].metadata,
            FileEntry {
                path: PathBuf::from("/etc/rpm-basic/example_config.toml"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[0].content.len(),
                flags: FileFlags::CONFIG,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[0].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 1: /usr/bin/rpm-basic
        assert_eq!(files[1].content, expected_script);
        assert_eq!(
            files[1].metadata,
            FileEntry {
                path: PathBuf::from("/usr/bin/rpm-basic"),
                mode: FileMode::regular(0o0644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[1].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[1].content),
                    algo: DigestAlgorithm::Sha2_256
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 2: /usr/lib/rpm-basic (directory)
        assert_eq!(
            files[2].metadata,
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic"),
                mode: FileMode::dir(0o0755),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[2].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 3: /usr/lib/rpm-basic/module (directory)
        assert_eq!(
            files[3].metadata,
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic/module"),
                mode: FileMode::dir(0o0755),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[3].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 4: /usr/lib/rpm-basic/module/__init__.py
        assert_eq!(files[4].content, expected_init);
        assert_eq!(
            files[4].metadata,
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic/module/__init__.py"),
                mode: FileMode::regular(0o0644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[4].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[4].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 5: /usr/lib/rpm-basic/module/hello.py
        assert_eq!(files[5].content, expected_hello);
        assert_eq!(
            files[5].metadata,
            FileEntry {
                path: PathBuf::from("/usr/lib/rpm-basic/module/hello.py"),
                mode: FileMode::regular(0o0644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[5].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[5].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 6: /usr/share/doc/rpm-basic (directory)
        assert_eq!(
            files[6].metadata,
            FileEntry {
                path: PathBuf::from("/usr/share/doc/rpm-basic"),
                mode: FileMode::dir(0o755),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[6].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 7: /usr/share/doc/rpm-basic/README
        // README is generated in spec file: echo "No more half measures, Walter." > README
        assert_eq!(files[7].content, b"No more half measures, Walter.\n");
        assert_eq!(
            files[7].metadata,
            FileEntry {
                path: PathBuf::from("/usr/share/doc/rpm-basic/README"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[7].content.len(),
                flags: FileFlags::DOC,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[7].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 8: /usr/share/rpm-basic/example_data.xml
        assert_eq!(files[8].content, expected_xml);
        assert_eq!(
            files[8].metadata,
            FileEntry {
                path: PathBuf::from("/usr/share/rpm-basic/example_data.xml"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[8].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[8].content),
                    algo: DigestAlgorithm::Sha2_256
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 9: /var/log/rpm-basic/basic.log (ghost file - not in payload)
        assert_eq!(
            files[9].metadata,
            FileEntry {
                path: PathBuf::from("/var/log/rpm-basic/basic.log"),
                mode: FileMode::regular(0),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[9].content.len(),
                flags: FileFlags::GHOST,
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        // File 10: /var/tmp/rpm-basic (directory after ghost file)
        assert_eq!(
            files[10].metadata,
            FileEntry {
                path: PathBuf::from("/var/tmp/rpm-basic"),
                mode: FileMode::dir(0o0755),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned()
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[10].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );

        Ok(())
    }

    /// Helper function to verify that extracted files on disk match the files from files() API.
    #[track_caller]
    fn verify_extracted_files(
        extract_path: &std::path::Path,
        files: &[RpmFile],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for file in files {
            let file_path = extract_path.join(
                file.metadata
                    .path
                    .strip_prefix("/")
                    .unwrap_or(&file.metadata.path),
            );

            if file.metadata.flags.contains(FileFlags::GHOST) {
                // Ghost files should NOT be created during extraction
                assert!(
                    !file_path.exists(),
                    "Ghost file {:?} should NOT exist on disk",
                    file.metadata.path
                );
            } else {
                match file.metadata.file_type() {
                    FileType::Dir => {
                        assert!(
                            file_path.exists() && file_path.is_dir(),
                            "Directory {:?} should exist",
                            file.metadata.path
                        );
                    }
                    FileType::Regular => {
                        assert!(
                            file_path.exists() && file_path.is_file(),
                            "Regular file {:?} should exist",
                            file.metadata.path
                        );
                        let disk_content = std::fs::read(&file_path)?;
                        assert_eq!(
                            disk_content, file.content,
                            "Content mismatch for {:?}",
                            file.metadata.path
                        );
                    }
                    FileType::SymbolicLink => {
                        // On Unix, verify symlinks are created properly
                        #[cfg(unix)]
                        {
                            assert!(
                                file_path.exists() || file_path.symlink_metadata().is_ok(),
                                "Symlink {:?} should exist",
                                file.metadata.path
                            );
                            let metadata = file_path.symlink_metadata()?;
                            assert!(
                                metadata.file_type().is_symlink(),
                                "Path {:?} should be a symlink",
                                file.metadata.path
                            );
                        }
                        // On Windows, symlinks are only created if their target exists.
                        // Relative symlinks or symlinks to paths outside the extraction
                        // directory are silently skipped, so we don't verify them.
                    }
                    _ => {
                        // Other file types (device nodes, FIFOs, etc.) are not extracted
                    }
                }
            }
        }
        Ok(())
    }

    /// Helper function to verify that files(), get_file_entries(), and get_file_paths()
    /// all return consistent data in the same order. Returns the files Vec for further assertions.
    #[track_caller]
    fn assert_file_apis_consistent(
        package: &Package,
    ) -> Result<Vec<RpmFile>, Box<dyn std::error::Error>> {
        let files: Vec<RpmFile> = package.files()?.collect::<Result<Vec<_>, _>>()?;
        let metadata_entries = package.metadata.get_file_entries()?;
        let file_paths = package.metadata.get_file_paths()?;

        assert_eq!(
            files.len(),
            metadata_entries.len(),
            "files() should return {} entries (matching get_file_entries()), but got {}",
            metadata_entries.len(),
            files.len()
        );
        assert_eq!(
            file_paths.len(),
            metadata_entries.len(),
            "get_file_paths() should return {} entries (matching get_file_entries()), but got {}",
            metadata_entries.len(),
            file_paths.len()
        );

        // Verify that all three APIs return data in the same order
        for (i, ((file, meta), path)) in files
            .iter()
            .zip(metadata_entries.iter())
            .zip(file_paths.iter())
            .enumerate()
        {
            assert_eq!(
                file.metadata.path(),
                meta.path(),
                "Path mismatch at index {}: files() has {:?} but get_file_entries() has {:?}",
                i,
                file.metadata.path(),
                meta.path()
            );
            assert_eq!(
                file.metadata.path(),
                *path,
                "Path mismatch at index {}: files() has {:?} but get_file_paths() has {:?}",
                i,
                file.metadata.path(),
                path
            );
            assert_eq!(
                file.metadata, *meta,
                "Full metadata mismatch at index {}: files() differs from get_file_entries()",
                i
            );
        }

        Ok(files)
    }

    /// Test file extraction for rpm-file-attrs package, verifying various file
    /// attributes (symlinks, different owners, capabilities, file flags).
    #[test]
    fn test_file_attrs() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open("tests/assets/RPMS/v6/rpm-file-attrs-1.0-1.noarch.rpm")?;

        // Verify all three file APIs return consistent data and get files for content verification
        let files = assert_file_apis_consistent(&package)?;
        assert_eq!(files.len(), 26);

        // Extract package and verify extracted files match files() API results
        let temp_dir = tempfile::tempdir()?;
        let extract_path = temp_dir.path().join("rpm-file-attrs");
        package.extract(&extract_path)?;
        verify_extracted_files(&extract_path, &files)?;

        // File 0: /opt/rpm-file-attrs (directory)
        assert_eq!(
            files[0].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs"),
                mode: FileMode::dir(0o755),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[0].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 1: /opt/rpm-file-attrs/artifact
        assert_eq!(files[1].content, b"artifact\n");
        assert_eq!(
            files[1].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/artifact"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[1].content.len(),
                flags: FileFlags::ARTIFACT,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[1].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 2: /opt/rpm-file-attrs/config
        assert_eq!(files[2].content, b"config\n");
        assert_eq!(
            files[2].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/config"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[2].content.len(),
                flags: FileFlags::CONFIG,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[2].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 3: /opt/rpm-file-attrs/config_noreplace
        assert_eq!(files[3].content, b"config_noreplace\n");
        assert_eq!(
            files[3].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/config_noreplace"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[3].content.len(),
                flags: FileFlags::CONFIG | FileFlags::NOREPLACE,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[3].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 4: /opt/rpm-file-attrs/different-owner-and-group
        assert_eq!(files[4].content, b"different-owner-and-group\n");
        assert_eq!(
            files[4].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/different-owner-and-group"),
                mode: FileMode::regular(0o655),
                ownership: FileOwnership {
                    user: "jane".to_owned(),
                    group: "bob".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[4].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[4].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 5: /opt/rpm-file-attrs/dir (directory)
        assert_eq!(
            files[5].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/dir"),
                mode: FileMode::dir(0o755),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[5].content.len(),
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 6: /opt/rpm-file-attrs/dir/normal
        assert_eq!(files[6].content, b"file-in-a-dir\n");
        assert_eq!(
            files[6].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/dir/normal"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: files[6].content.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[6].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 7: /opt/rpm-file-attrs/doc
        assert_eq!(files[7].content, b"doc\n");
        assert_eq!(
            files[7].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/doc"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 4,
                flags: FileFlags::DOC,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[7].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 8: /opt/rpm-file-attrs/empty_caps
        assert_eq!(files[8].content, b"empty_caps\n");
        assert_eq!(
            files[8].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/empty_caps"),
                mode: FileMode::regular(0o655),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 11,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[8].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("=".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 9: /opt/rpm-file-attrs/empty_caps2
        assert_eq!(files[9].content, b"empty_caps2\n");
        assert_eq!(
            files[9].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/empty_caps2"),
                mode: FileMode::regular(0o655),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 12,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[9].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("=".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 10: /opt/rpm-file-attrs/example-binary
        assert_eq!(files[10].content, b"example-binary\n");
        assert_eq!(
            files[10].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/example-binary"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 15,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[10].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 11: /opt/rpm-file-attrs/example-confidential-file
        assert_eq!(files[11].content, b"example-confidential-file\n");
        assert_eq!(
            files[11].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/example-confidential-file"),
                mode: FileMode::regular(0o600),
                ownership: FileOwnership {
                    user: "jane".to_owned(),
                    group: "jane".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 26,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[11].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 12: /opt/rpm-file-attrs/ghost (ghost file - not in payload)
        assert_eq!(
            files[12].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/ghost"),
                mode: FileMode::regular(0),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 0,
                flags: FileFlags::GHOST,
                digest: None,
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[12].content.len(), 0);

        // File 13: /opt/rpm-file-attrs/license
        assert_eq!(files[13].content, b"license\n");
        assert_eq!(
            files[13].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/license"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 8,
                flags: FileFlags::LICENSE,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[13].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 14: /opt/rpm-file-attrs/missingok
        assert_eq!(files[14].content, b"missingok\n");
        assert_eq!(
            files[14].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/missingok"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 10,
                flags: FileFlags::MISSINGOK,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[14].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 15: /opt/rpm-file-attrs/normal
        assert_eq!(files[15].content, b"normal\n");
        assert_eq!(
            files[15].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/normal"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 7,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[15].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 16: /opt/rpm-file-attrs/readme
        assert_eq!(files[16].content, b"readme\n");
        assert_eq!(
            files[16].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/readme"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 7,
                flags: FileFlags::README,
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[16].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 17: /opt/rpm-file-attrs/symlink (symlink to normal)
        assert_eq!(files[17].content, b"normal");
        assert_eq!(
            files[17].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/symlink"),
                mode: FileMode::symbolic_link(0o777),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 6,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: Some("normal".to_owned()),
                ima_signature: None,
            }
        );
        assert_eq!(files[17].content, b"normal");
        assert_eq!(files[17].content.len(), 6);
        assert_eq!(files[17].metadata.size, 6);

        // File 18: /opt/rpm-file-attrs/symlink_dir (directory)
        assert_eq!(
            files[18].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/symlink_dir"),
                mode: FileMode::dir(0o755),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 0,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[18].content.len(), 0);

        // File 19: /opt/rpm-file-attrs/symlink_dir/dir (symlink to ../dir)
        assert_eq!(files[19].content, b"../dir");
        assert_eq!(
            files[19].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/symlink_dir/dir"),
                mode: FileMode::symbolic_link(0o777),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 6,
                flags: FileFlags::empty(),
                digest: None,
                caps: Some("".to_owned()),
                linkto: Some("../dir".to_owned()),
                ima_signature: None,
            }
        );
        assert_eq!(files[19].content, b"../dir");
        assert_eq!(files[19].content.len(), 6);
        assert_eq!(files[19].metadata.size, 6);

        // File 20: /opt/rpm-file-attrs/verify_all
        assert_eq!(files[20].content, b"verify_all\n");
        assert_eq!(
            files[20].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/verify_all"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 11,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[20].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 21: /opt/rpm-file-attrs/verify_none
        assert_eq!(files[21].content, b"verify_none\n");
        assert_eq!(
            files[21].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/verify_none"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 12,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[21].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 22: /opt/rpm-file-attrs/verify_not
        assert_eq!(files[22].content, b"verify_not\n");
        assert_eq!(
            files[22].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/verify_not"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 11,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[22].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 23: /opt/rpm-file-attrs/verify_some
        assert_eq!(files[23].content, b"verify_some\n");
        assert_eq!(
            files[23].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/verify_some"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 12,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[23].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        // File 24: /opt/rpm-file-attrs/with_caps
        assert_eq!(files[24].content, b"with_caps\n");
        assert_eq!(
            files[24].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-attrs/with_caps"),
                mode: FileMode::regular(0o655),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 10,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[24].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("cap_sys_ptrace,cap_sys_admin=ep".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );

        // File 25: /usr/lib/sysusers.d/rpm-file-attrs.conf
        let expected_sysusers = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/rpm-file-attrs-sysusers.conf"
        ));
        assert_eq!(files[25].content, expected_sysusers);
        assert_eq!(
            files[25].metadata,
            FileEntry {
                path: PathBuf::from("/usr/lib/sysusers.d/rpm-file-attrs.conf"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: expected_sysusers.len(),
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[25].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: Some("".to_owned()),
                linkto: None,
                ima_signature: None,
            }
        );
        Ok(())
    }

    /// Test file extraction for rpm-file-types package, focusing on unusual file
    /// names (spaces, special characters) and binary content (PNG image).
    #[test]
    fn test_file_types() -> Result<(), Box<dyn std::error::Error>> {
        let package = Package::open("tests/assets/RPMS/v6/rpm-file-types-1.0-1.noarch.rpm")?;

        // Verify all three file APIs return consistent data and get files for content verification
        let files = assert_file_apis_consistent(&package)?;
        assert_eq!(files.len(), 3);

        // Extract package and verify extracted files match files() API results
        let temp_dir = tempfile::tempdir()?;
        let extract_path = temp_dir.path().join("rpm-file-types");
        package.extract(&extract_path)?;
        verify_extracted_files(&extract_path, &files)?;

        // Load expected file contents from source files
        let expected_empty = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/empty_file"
        ));
        let expected_spaces = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/file with spaces & special (chars).txt"
        ));
        let expected_png = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/assets/SOURCES/rpm-rs-logo.png"
        ));

        // File 0: /opt/rpm-file-types/empty_file
        assert_eq!(
            files[0].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-types/empty_file"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 0,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[0].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[0].content, expected_empty);
        assert_eq!(files[0].content.len(), 0);
        assert_eq!(files[0].metadata.size, 0);

        // File 1: /opt/rpm-file-types/file with spaces & special (chars).txt
        assert_eq!(
            files[1].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-types/file with spaces & special (chars).txt"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 31,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[1].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[1].content, expected_spaces);
        assert_eq!(files[1].content.len(), expected_spaces.len());
        assert_eq!(files[1].metadata.size, expected_spaces.len());
        assert_eq!(files[1].content.len(), 31);

        // File 2: /opt/rpm-file-types/rpm-rs-logo.png (binary content)
        assert_eq!(
            files[2].metadata,
            FileEntry {
                path: PathBuf::from("/opt/rpm-file-types/rpm-rs-logo.png"),
                mode: FileMode::regular(0o644),
                ownership: FileOwnership {
                    user: "root".to_owned(),
                    group: "root".to_owned(),
                },
                modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                size: 2017,
                flags: FileFlags::empty(),
                digest: Some(FileDigest {
                    digest: calculate_sha256(&files[2].content),
                    algo: DigestAlgorithm::Sha2_256,
                }),
                caps: None,
                linkto: None,
                ima_signature: None,
            }
        );
        assert_eq!(files[2].content, expected_png);
        assert_eq!(files[2].content.len(), expected_png.len());
        assert_eq!(files[2].metadata.size, expected_png.len());
        assert_eq!(files[2].content.len(), 2017);
        // Verify PNG magic bytes
        assert_eq!(&files[2].content[0..8], b"\x89PNG\r\n\x1a\n");

        Ok(())
    }

    /// Test file extraction for rpm-empty package (no files).
    #[test]
    fn test_empty_package() -> Result<(), Box<dyn std::error::Error>> {
        let v4 = Package::open("tests/assets/RPMS/v4/rpm-empty-0-0.x86_64.rpm")?;
        let v6 = Package::open("tests/assets/RPMS/v6/rpm-empty-0-0.x86_64.rpm")?;

        for package in [&v4, &v6] {
            // Verify all three file APIs return consistent data
            let files = assert_file_apis_consistent(package)?;
            assert_eq!(files.len(), 0);
        }

        Ok(())
    }

    /// Test file extraction for rpm-empty source package (contains rpm-empty.spec).
    #[test]
    fn test_empty_source_package() -> Result<(), Box<dyn std::error::Error>> {
        let v4 = Package::open("tests/assets/SRPMS/v4/rpm-empty-0-0.src.rpm")?;
        let v6 = Package::open("tests/assets/SRPMS/v6/rpm-empty-0-0.src.rpm")?;

        for package in [&v4, &v6] {
            // Verify all three file APIs return consistent data and get files for content verification
            let files = assert_file_apis_consistent(package)?;
            assert_eq!(files.len(), 1);

            // File 0: rpm-empty.spec
            assert_eq!(
                files[0].metadata,
                FileEntry {
                    path: PathBuf::from("rpm-empty.spec"),
                    mode: FileMode::regular(0o644),
                    ownership: FileOwnership {
                        user: "root".to_owned(),
                        group: "root".to_owned()
                    },
                    modified_at: Timestamp(FIXTURE_SOURCE_DATE),
                    size: 162,
                    flags: FileFlags::SPECFILE,
                    digest: Some(FileDigest {
                        digest: calculate_sha256(&files[0].content),
                        algo: DigestAlgorithm::Sha2_256,
                    }),
                    caps: None,
                    linkto: None,
                    ima_signature: None,
                }
            );
            assert_eq!(files[0].metadata.size, 162);
            assert_eq!(files[0].content.len(), 162);

            // Verify spec file content contains expected fields
            let spec_content = std::str::from_utf8(&files[0].content)?;
            assert!(spec_content.contains("Name:           rpm-empty"));
            assert!(spec_content.contains("Version:        0"));
            assert!(spec_content.contains("License:        LGPL"));
        }

        Ok(())
    }
}
