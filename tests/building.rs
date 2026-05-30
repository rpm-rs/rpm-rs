use std::path::{Path, PathBuf};

use rpm::*;

mod common;

mod validation {
    use super::*;

    /// Verify that pre_build_validation performs validation on the package name
    #[test]
    fn test_builder_rejects_invalid_name() {
        // But not in name
        let result = PackageBuilder::new("foo\t", "1.0.0", "MIT", "x86_64", "test").build();
        assert!(result.is_err(), "should reject special chars (tab) in name");

        let result = PackageBuilder::new("foo\n", "1.0.0", "MIT", "x86_64", "test").build();
        assert!(
            result.is_err(),
            "should reject special chars (newline) in name"
        );
    }

    /// Verify that pre_build_validation rejects control chars in various builder metadata fields.
    #[test]
    fn test_builder_rejects_control_chars_in_metadata() {
        // Tab and newline are allowed in description
        PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
            .description("line1\nline2\ttabbed")
            .build()
            .expect("tabs and newlines should be allowed in description");

        // Control character in summary
        let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test\x1b[0m").build();
        assert!(
            result.is_err(),
            "should reject control chars (ANSI escape) in summary"
        );

        // Control character in dependency name
        let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
            .requires(rpm::Dependency::any("bad\x00dep"))
            .build();
        assert!(
            result.is_err(),
            "should reject control chars in dependency name"
        );
    }

    /// Verify that pre_build_validation rejects control chars in file-level metadata.
    #[test]
    fn test_builder_rejects_control_chars_in_file_metadata() {
        let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

        // Control character in file owner
        let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
            .with_file(
                &cargo_file,
                FileOptions::new("/etc/test.toml").user("bad\x01user"),
            )
            .unwrap()
            .build();
        assert!(result.is_err(), "should reject control chars in file user");
    }

    /// Verify that pre_build_validation rejects control chars in changelog metadata.
    #[test]
    fn test_builder_rejects_control_chars_in_changelogs() {
        // Control character in changelog author
        let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
            .add_changelog_entry("author\x07 <a@b.c>", "entry", 1_600_000_000)
            .build();
        assert!(
            result.is_err(),
            "should reject control chars in changelog name"
        );

        // Control character in changelog entry
        let result = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test")
            .add_changelog_entry("author <a@b.c>", "entry \x07", 1_600_000_000)
            .build();
        assert!(
            result.is_err(),
            "should reject control chars in changelog body"
        );
    }

    /// Verify that calling build() twice returns an error.
    #[test]
    fn test_builder_rejects_double_build() {
        let mut b = PackageBuilder::new("foo", "1.0.0", "MIT", "x86_64", "test");
        b.build().expect("first build should succeed");
        let err = b.build();
        assert!(
            matches!(err, Err(rpm::Error::BuilderReuse)),
            "second build should return BuilderReuse error"
        );
    }

    /// Verify that each `with_*` method rejects mismatched `FileOptions` variants.
    #[test]
    fn test_file_options_validation() {
        let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

        // with_dir_entry rejects non-Dir mode
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err = b.with_dir_entry(FileOptions::new("/var/log/foo"));
        assert!(
            err.is_err(),
            "with_dir_entry should reject regular file options"
        );

        // with_symlink rejects non-SymbolicLink mode
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err = b.with_symlink(FileOptions::new("/usr/bin/link"));
        assert!(
            err.is_err(),
            "with_symlink should reject regular file options"
        );

        // with_symlink rejects empty target
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err =
            b.with_symlink(FileOptions::new("/usr/bin/link").mode(FileMode::symbolic_link(0o777)));
        assert!(
            err.is_err(),
            "with_symlink should reject empty symlink target"
        );

        // with_ghost rejects non-ghost options
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err = b.with_ghost(FileOptions::new("/var/log/foo"));
        assert!(err.is_err(), "with_ghost should reject non-ghost options");

        // with_file rejects Dir mode
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err = b.with_file(
            cargo_file.to_str().unwrap(),
            FileOptions::dir("/var/log/foo"),
        );
        assert!(err.is_err(), "with_file should reject directory options");

        // with_file rejects ghost flag
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err = b.with_file(
            cargo_file.to_str().unwrap(),
            FileOptions::ghost("/var/log/foo"),
        );
        assert!(err.is_err(), "with_file should reject ghost options");

        // with_file_contents rejects Dir mode
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err = b.with_file_contents("content", FileOptions::dir("/var/log/foo"));
        assert!(
            err.is_err(),
            "with_file_contents should reject directory options"
        );

        // with_file_contents rejects ghost flag
        let mut b = PackageBuilder::new("t", "1.0.0", "MIT", "x86_64", "t");
        let err = b.with_file_contents("content", FileOptions::ghost("/var/log/foo"));
        assert!(
            err.is_err(),
            "with_file_contents should reject ghost options"
        );
    }

    /// Adding the same path explicitly twice should produce an error.
    #[test]
    fn test_duplicate_explicit_add_still_errors() {
        let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

        let mut builder = PackageBuilder::new("test-dup", "1.0.0", "MIT", "x86_64", "test");
        builder
            .with_file(&cargo_file, FileOptions::new("/etc/test.toml"))
            .unwrap();
        let result = builder.with_file(&cargo_file, FileOptions::new("/etc/test.toml"));

        assert!(result.is_err(), "duplicate explicit add should error");
    }
}

mod write_to {
    use super::*;

    /// Test write_to() with a directory path - should auto-generate filename
    #[test]
    fn test_write_to_directory() -> Result<(), Box<dyn std::error::Error>> {
        let pkg = PackageBuilder::new("test-write", "1.2.3", "MIT", "x86_64", "test package")
            .release("4.fc40")
            .build()?;

        let temp_dir = tempfile::tempdir()?;
        let output_path = pkg.write_to(temp_dir.path())?;

        // Should create a file with the NVRA name
        assert_eq!(
            output_path.file_name().unwrap().to_str().unwrap(),
            "test-write-1.2.3-4.fc40.x86_64.rpm"
        );
        assert!(output_path.exists());

        // Verify we can read it back
        let parsed = Package::open(&output_path)?;
        assert_eq!(parsed.metadata.get_name()?, "test-write");
        assert_eq!(parsed.metadata.get_version()?, "1.2.3");

        Ok(())
    }

    /// Test write_to() with a file path - should use the provided path with .rpm extension
    #[test]
    fn test_write_to_file() -> Result<(), Box<dyn std::error::Error>> {
        let pkg = PackageBuilder::new("test-write", "1.0.0", "MIT", "noarch", "test").build()?;

        let temp_dir = tempfile::tempdir()?;
        let custom_path = temp_dir.path().join("custom-name");
        let output_path = pkg.write_to(&custom_path)?;

        // Should add .rpm extension
        assert_eq!(
            output_path.file_name().unwrap().to_str().unwrap(),
            "custom-name.rpm"
        );
        assert!(output_path.exists());

        // Verify we can read it back
        let parsed = Package::open(&output_path)?;
        assert_eq!(parsed.metadata.get_name()?, "test-write");

        Ok(())
    }

    /// Test write_to() with a path that already has .rpm extension
    #[test]
    fn test_write_to_file_with_extension() -> Result<(), Box<dyn std::error::Error>> {
        let pkg = PackageBuilder::new("test-write", "1.0.0", "MIT", "noarch", "test").build()?;

        let temp_dir = tempfile::tempdir()?;
        let custom_path = temp_dir.path().join("my-package.rpm");
        let output_path = pkg.write_to(&custom_path)?;

        // Should keep the .rpm extension
        assert_eq!(
            output_path.file_name().unwrap().to_str().unwrap(),
            "my-package.rpm"
        );
        assert!(output_path.exists());

        Ok(())
    }
}

/// Test that auto-generated provides and requires match RPM's behavior:
/// - NAME = EVR provide (always)
/// - NAME(ISA) = EVR provide (only for non-noarch)
/// - config(NAME) = EVR provide/require (only when %config files exist)
/// - EVR format includes epoch when set
#[test]
fn test_auto_provides_and_requires() -> Result<(), Box<dyn std::error::Error>> {
    let sources_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES");
    let config_file = sources_dir.join("example_config.toml");

    // 1. x86_64 package with no config files
    let pkg = PackageBuilder::new("testpkg", "1.0", "MIT", "x86_64", "test")
        .release("2.fc40")
        .build()?;
    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;

    let provides = parsed.metadata.get_provides()?;
    assert!(provides.contains(&Dependency::eq("testpkg", "1.0-2.fc40")));
    assert!(provides.contains(&Dependency::eq("testpkg(x86-64)", "1.0-2.fc40")));
    assert!(!provides.iter().any(|d| d.name.starts_with("config(")));

    let requires = parsed.metadata.get_requires()?;
    assert!(!requires.iter().any(|d| d.name.starts_with("config(")));

    // 2. noarch package - should NOT have NAME(ISA) provide
    let pkg = PackageBuilder::new("testpkg", "1.0", "MIT", "noarch", "test")
        .release("1")
        .build()?;
    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;

    let provides = parsed.metadata.get_provides()?;
    assert!(provides.contains(&Dependency::eq("testpkg", "1.0-1")));
    assert_eq!(provides.len(), 1, "noarch should only have NAME provide");

    // 3. Package with epoch - EVR should include epoch
    let pkg = PackageBuilder::new("testpkg", "2.0", "MIT", "x86_64", "test")
        .epoch(3)
        .release("1")
        .build()?;
    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;

    let provides = parsed.metadata.get_provides()?;
    assert!(provides.contains(&Dependency::eq("testpkg", "3:2.0-1")));
    assert!(provides.contains(&Dependency::eq("testpkg(x86-64)", "3:2.0-1")));

    // 4. Package with config file - should auto-generate config() deps
    let pkg = PackageBuilder::new("testpkg", "1.0", "MIT", "noarch", "test")
        .release("1")
        .with_file(&config_file, FileOptions::new("/etc/testpkg.conf").config())?
        .build()?;
    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;

    let provides = parsed.metadata.get_provides()?;
    assert!(provides.contains(&Dependency::config("testpkg", "1.0-1")));

    let requires = parsed.metadata.get_requires()?;
    assert!(requires.contains(&Dependency::config("testpkg", "1.0-1")));

    // 5. Package with epoch 0 explicitly set - should include "0:" prefix
    let pkg = PackageBuilder::new("testpkg", "1.0", "MIT", "noarch", "test")
        .epoch(0)
        .release("1")
        .build()?;
    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;

    let provides = parsed.metadata.get_provides()?;
    assert!(provides.contains(&Dependency::eq("testpkg", "0:1.0-1")));

    Ok(())
}

/// Round-trip a package using all `with_*` entry types and verify their metadata is preserved.
#[test]
fn test_build_with_new_file_api() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-new-api", "1.0.0", "MIT", "x86_64", "test package")
        // Regular file with the new permissions() method
        .with_file(
            cargo_file.to_str().unwrap(),
            FileOptions::new("/etc/test/config.toml")
                .permissions(0o644)
                .config(),
        )?
        // Symlink via dedicated constructor and method
        .with_symlink(FileOptions::symlink(
            "/usr/bin/test_link",
            "/usr/bin/test_target",
        ))?
        // Explicit directory entry
        .with_dir_entry(
            FileOptions::dir("/var/log/testapp")
                .permissions(0o750)
                .user("testuser"),
        )?
        // Ghost file
        .with_ghost(FileOptions::ghost("/var/log/testapp/app.log").permissions(0o644))?
        // Ghost directory
        .with_ghost(FileOptions::ghost_dir("/var/run/testapp"))?
        .build()?;

    // Write and re-read the package
    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let metadata = &parsed.metadata;

    let file_paths = metadata.get_file_paths()?;
    let file_entries = metadata.get_file_entries()?;

    // Verify all entries are present
    assert!(file_paths.contains(&PathBuf::from("/etc/test/config.toml")));
    assert!(file_paths.contains(&PathBuf::from("/usr/bin/test_link")));
    assert!(file_paths.contains(&PathBuf::from("/var/log/testapp")));
    assert!(file_paths.contains(&PathBuf::from("/var/log/testapp/app.log")));
    assert!(file_paths.contains(&PathBuf::from("/var/run/testapp")));

    // Verify file entry metadata
    for entry in &file_entries {
        match entry.path().to_str().unwrap() {
            "/etc/test/config.toml" => {
                assert!(entry.flags().contains(FileFlags::CONFIG));
                assert_eq!(entry.file_type(), FileType::Regular);
                assert_eq!(entry.permissions(), 0o644);
            }
            "/usr/bin/test_link" => {
                assert_eq!(entry.file_type(), FileType::SymbolicLink);
                assert_eq!(entry.linkto().as_deref(), Some("/usr/bin/test_target"));
            }
            "/var/log/testapp" => {
                assert_eq!(entry.file_type(), FileType::Dir);
                assert_eq!(entry.permissions(), 0o750);
            }
            "/var/log/testapp/app.log" => {
                assert!(entry.flags().contains(FileFlags::GHOST));
                assert_eq!(entry.file_type(), FileType::Regular);
            }
            "/var/run/testapp" => {
                assert!(entry.flags().contains(FileFlags::GHOST));
                assert_eq!(entry.file_type(), FileType::Dir);
            }
            _ => {}
        }
    }

    Ok(())
}

/// Verify that `with_dir` recursively adds directory entries and files.
#[test]
fn test_with_dir_basic() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .using_config(BuildConfig::default().source_date(1_600_000_000))
        .with_dir(&source_dir, "/usr/lib/mymodule", |o| o)?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;
    let paths: Vec<_> = entries.iter().map(|e| e.path()).collect();

    // Should have directory entry + 2 files
    assert_eq!(
        paths,
        vec![
            Path::new("/usr/lib/mymodule"),
            Path::new("/usr/lib/mymodule/__init__.py"),
            Path::new("/usr/lib/mymodule/hello.py"),
        ]
    );

    // Directory entry
    assert_eq!(entries[0].file_type(), FileType::Dir);
    assert_eq!(entries[0].size(), 0);

    // Files should be regular
    assert_eq!(entries[1].file_type(), FileType::Regular);
    assert_eq!(entries[2].file_type(), FileType::Regular);

    Ok(())
}

/// An explicit `with_file` added before `with_dir` should take priority over the bulk add.
#[test]
fn test_with_dir_explicit_override_before_bulk() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");
    let init_file = source_dir.join("__init__.py");

    // Add __init__.py explicitly with config flag, then bulk-add the directory.
    // The explicit entry should win (bulk skips existing).
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .using_config(BuildConfig::default().source_date(1_600_000_000))
        .with_file(
            &init_file,
            FileOptions::new("/usr/lib/mymodule/__init__.py").config(),
        )?
        .with_dir(&source_dir, "/usr/lib/mymodule", |o| o)?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let init_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/lib/mymodule/__init__.py"))
        .expect("__init__.py should be present");

    // The explicitly-added CONFIG flag should be preserved (not overwritten by bulk)
    assert!(init_entry.flags().contains(FileFlags::CONFIG));

    Ok(())
}

/// An explicit `with_file` added after `with_dir` should replace the bulk-added entry.
#[test]
fn test_with_dir_explicit_override_after_bulk() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");
    let init_file = source_dir.join("__init__.py");

    // Bulk-add first, then override __init__.py explicitly.
    // The explicit entry should replace the bulk-added one.
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .using_config(BuildConfig::default().source_date(1_600_000_000))
        .with_dir(&source_dir, "/usr/lib/mymodule", |o| o)?
        .with_file(
            &init_file,
            FileOptions::new("/usr/lib/mymodule/__init__.py").config(),
        )?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let init_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/lib/mymodule/__init__.py"))
        .expect("__init__.py should be present");

    // The explicit CONFIG flag should be present (replaced the bulk entry)
    assert!(init_entry.flags().contains(FileFlags::CONFIG));

    Ok(())
}

/// When two `with_dir` calls cover the same path, the first bulk add wins.
#[test]
fn test_with_dir_overlapping_bulk_first_wins() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    // Two bulk adds of the same directory — first one wins
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .using_config(BuildConfig::default().source_date(1_600_000_000))
        .with_dir(&source_dir, "/usr/lib/mymodule", |o| o.config())?
        .with_dir(&source_dir, "/usr/lib/mymodule", |o| o.doc())?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let init_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/lib/mymodule/__init__.py"))
        .expect("__init__.py should be present");

    // First bulk add used config(), second used doc(). First should win.
    assert!(init_entry.flags().contains(FileFlags::CONFIG));
    assert!(!init_entry.flags().contains(FileFlags::DOC));

    Ok(())
}

/// File-only flags like CONFIG applied via the `customize` callback should be stripped from directory entries.
#[test]
fn test_with_dir_strips_flags_from_dirs() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    // Customize callback adds CONFIG — should be stripped from the directory entry
    // but preserved on the file entries
    let pkg = PackageBuilder::new("test-dir", "1.0.0", "MIT", "x86_64", "test")
        .using_config(BuildConfig::default().source_date(1_600_000_000))
        .with_dir(&source_dir, "/usr/lib/mymodule", |o| o.config())?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let dir_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/lib/mymodule"))
        .expect("directory entry should be present");
    assert_eq!(dir_entry.file_type(), FileType::Dir);
    assert!(
        !dir_entry.flags().contains(FileFlags::CONFIG),
        "CONFIG should be stripped from directory entries"
    );

    let file_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/lib/mymodule/hello.py"))
        .expect("hello.py should be present");
    assert!(
        file_entry.flags().contains(FileFlags::CONFIG),
        "CONFIG should be preserved on file entries"
    );

    Ok(())
}

/// Default file attrs should apply permissions, user, and group to files when not explicitly set.
#[test]
fn test_default_file_attrs() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(Some(0o755), Some("myuser".into()), Some("mygroup".into()))
        .with_file(&cargo_file, FileOptions::new("/usr/bin/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    assert_eq!(entry.permissions(), 0o755);
    assert_eq!(entry.user(), "myuser");
    assert_eq!(entry.group(), "mygroup");

    Ok(())
}

/// Default dir attrs should apply permissions, user, and group to directories when not explicitly set.
#[test]
fn test_default_dir_attrs() -> Result<(), Box<dyn std::error::Error>> {
    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_dir_attrs(Some(0o700), Some("diruser".into()), Some("dirgroup".into()))
        .with_dir_entry(FileOptions::dir("/var/log/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/var/log/myapp"))
        .expect("dir should be present");

    assert_eq!(entry.permissions(), 0o700);
    assert_eq!(entry.user(), "diruser");
    assert_eq!(entry.group(), "dirgroup");

    Ok(())
}

/// File defaults and dir defaults should apply independently to the correct entry types.
#[test]
fn test_default_attrs_file_vs_dir() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(
            Some(0o644),
            Some("fileuser".into()),
            Some("filegroup".into()),
        )
        .default_dir_attrs(Some(0o755), Some("diruser".into()), Some("dirgroup".into()))
        .with_file(&cargo_file, FileOptions::new("/etc/myapp.conf"))?
        .with_dir_entry(FileOptions::dir("/var/log/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let file_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/etc/myapp.conf"))
        .expect("file should be present");
    assert_eq!(file_entry.permissions(), 0o644);
    assert_eq!(file_entry.user(), "fileuser");
    assert_eq!(file_entry.group(), "filegroup");

    let dir_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/var/log/myapp"))
        .expect("dir should be present");
    assert_eq!(dir_entry.permissions(), 0o755);
    assert_eq!(dir_entry.user(), "diruser");
    assert_eq!(dir_entry.group(), "dirgroup");

    Ok(())
}

/// Explicit FileOptions should override default attrs.
#[test]
fn test_default_attrs_explicit_override() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(
            Some(0o755),
            Some("defaultuser".into()),
            Some("defaultgroup".into()),
        )
        .with_file(
            &cargo_file,
            FileOptions::new("/usr/bin/myapp")
                .permissions(0o700)
                .user("explicituser")
                .group("explicitgroup"),
        )?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    assert_eq!(entry.permissions(), 0o700);
    assert_eq!(entry.user(), "explicituser");
    assert_eq!(entry.group(), "explicitgroup");

    Ok(())
}

/// Calling default_file_attrs multiple times should accumulate — later calls override earlier ones.
#[test]
fn test_default_attrs_called_twice() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(Some(0o644), Some("user1".into()), Some("group1".into()))
        .default_file_attrs(Some(0o755), None, None)
        .with_file(&cargo_file, FileOptions::new("/usr/bin/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    // Second call overrode permissions; user/group were None so first call's values persist
    assert_eq!(entry.permissions(), 0o755);
    assert_eq!(entry.user(), "user1");
    assert_eq!(entry.group(), "group1");

    Ok(())
}

/// None fields in default attrs should leave the default (root) unchanged.
#[test]
fn test_default_attrs_none_fields() -> Result<(), Box<dyn std::error::Error>> {
    let cargo_file = Path::new(common::CARGO_MANIFEST_DIR).join("Cargo.toml");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .default_file_attrs(None, Some("myuser".into()), None)
        .with_file(&cargo_file, FileOptions::new("/usr/bin/myapp"))?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/bin/myapp"))
        .expect("file should be present");

    assert_eq!(entry.user(), "myuser");
    assert_eq!(entry.group(), "root");

    Ok(())
}

/// Default attrs should apply to files added via `with_dir`.
#[test]
fn test_default_attrs_with_dir() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES/module");

    let pkg = PackageBuilder::new("test-defaults", "1.0.0", "MIT", "x86_64", "test")
        .using_config(BuildConfig::default().source_date(1_600_000_000))
        .default_file_attrs(Some(0o644), Some("fileuser".into()), None)
        .default_dir_attrs(Some(0o755), Some("diruser".into()), None)
        .with_dir(&source_dir, "/usr/lib/mymodule", |o| o)?
        .build()?;

    let mut buf = Vec::new();
    pkg.write(&mut buf)?;
    let parsed = Package::parse(&mut buf.as_slice())?;
    let entries = parsed.metadata.get_file_entries()?;

    let dir_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/lib/mymodule"))
        .expect("dir should be present");
    assert_eq!(dir_entry.permissions(), 0o755);
    assert_eq!(dir_entry.user(), "diruser");

    let file_entry = entries
        .iter()
        .find(|e| e.path() == Path::new("/usr/lib/mymodule/hello.py"))
        .expect("file should be present");
    assert_eq!(file_entry.permissions(), 0o644);
    assert_eq!(file_entry.user(), "fileuser");

    Ok(())
}

#[test]
fn test_epoch_handling() -> Result<(), Box<dyn std::error::Error>> {
    use rpm::*;

    // Test 1: No epoch set (default) - should NOT have EPOCH tag
    let pkg1 = PackageBuilder::new("test", "1.0", "MIT", "noarch", "test").build()?;
    let mut buf1 = Vec::new();
    pkg1.write(&mut buf1)?;
    let parsed1 = Package::parse(&mut buf1.as_slice())?;
    assert!(
        !parsed1
            .metadata
            .header
            .entry_is_present(IndexTag::RPMTAG_EPOCH),
        "Package without epoch() should not have EPOCH tag"
    );

    // Test 2: Explicit epoch 0 - should HAVE EPOCH tag with value 0
    let pkg2 = PackageBuilder::new("test", "1.0", "MIT", "noarch", "test")
        .epoch(0)
        .build()?;
    let mut buf2 = Vec::new();
    pkg2.write(&mut buf2)?;
    let parsed2 = Package::parse(&mut buf2.as_slice())?;
    assert!(
        parsed2
            .metadata
            .header
            .entry_is_present(IndexTag::RPMTAG_EPOCH),
        "Package with epoch(0) should have EPOCH tag"
    );
    assert_eq!(parsed2.metadata.get_epoch()?, 0);

    // Test 3: Explicit epoch 1 - should HAVE EPOCH tag with value 1
    let pkg3 = PackageBuilder::new("test", "1.0", "MIT", "noarch", "test")
        .epoch(1)
        .build()?;
    let mut buf3 = Vec::new();
    pkg3.write(&mut buf3)?;
    let parsed3 = Package::parse(&mut buf3.as_slice())?;
    assert!(
        parsed3
            .metadata
            .header
            .entry_is_present(IndexTag::RPMTAG_EPOCH),
        "Package with epoch(1) should have EPOCH tag"
    );
    assert_eq!(parsed3.metadata.get_epoch()?, 1);

    Ok(())
}
