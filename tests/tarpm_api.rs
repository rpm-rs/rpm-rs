use std::io::Cursor;

use rpm::{
    BuildConfig, CompressionType, DigestAlgorithm, FileOptions, Header, HeaderEditor, HeaderEntry,
    IndexData, IndexSignatureTag, IndexTag, Lead, Package, PackageBuilder, PayloadBuilder,
    RpmFormat, Timestamp,
};
use sha2::Digest;

#[test]
fn raw_headers_round_trip_all_index_data_variants() -> Result<(), Box<dyn std::error::Error>> {
    let expected = vec![
        HeaderEntry::new(20000, IndexData::Null),
        HeaderEntry::new(20001, IndexData::Char(vec![1, 2, 3])),
        HeaderEntry::new(20002, IndexData::Int8(vec![4, 5])),
        HeaderEntry::new(20003, IndexData::Int16(vec![6, 7])),
        HeaderEntry::new(20004, IndexData::Int32(vec![8, 9])),
        HeaderEntry::new(20005, IndexData::Int64(vec![10, 11])),
        HeaderEntry::new(20006, IndexData::StringTag("string".to_string())),
        HeaderEntry::new(20007, IndexData::Bin(vec![12, 13])),
        HeaderEntry::new(
            20008,
            IndexData::StringArray(vec!["one".to_string(), "two".to_string()]),
        ),
        HeaderEntry::new(20009, IndexData::I18NString(vec!["translated".to_string()])),
    ];
    let header = Header::from_entries(expected.clone(), IndexTag::RPMTAG_HEADERIMMUTABLE);
    let package = Package::assemble(
        Lead::new("raw-header-test"),
        header,
        Vec::new(),
        RpmFormat::V6,
        None,
    )?;
    let mut encoded = Vec::new();
    package.write(&mut encoded)?;
    let parsed = Package::parse(&mut Cursor::new(encoded))?;
    let mut actual = parsed
        .metadata
        .header
        .get_all_entries()?
        .into_iter()
        .filter(|(tag, _)| *tag != rpm::constants::HEADER_IMMUTABLE)
        .map(|(tag, data)| HeaderEntry::new(tag, data))
        .collect::<Vec<_>>();
    actual.sort_by_key(|entry| entry.tag);
    let mut expected = expected;
    expected.sort_by_key(|entry| entry.tag);
    assert_eq!(actual, expected);

    let region = parsed
        .metadata
        .header
        .get_all_entries()?
        .into_iter()
        .find(|(tag, _)| *tag == rpm::constants::HEADER_IMMUTABLE);
    assert!(matches!(region, Some((_, IndexData::Bin(bytes))) if !bytes.is_empty()));
    Ok(())
}

#[test]
fn package_assembly_refreshes_digests_and_drops_signatures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm"
    );
    let mut package = Package::open(fixture)?;
    assert!(!package.raw_signatures()?.is_empty());
    let entries = package
        .metadata
        .header
        .get_all_entries()?
        .into_iter()
        .filter(|(tag, _)| *tag != rpm::constants::HEADER_IMMUTABLE)
        .map(|(tag, data)| HeaderEntry::new(tag, data))
        .collect::<Vec<_>>();
    package = Package::assemble(
        package.metadata.lead,
        Header::from_entries(entries, IndexTag::RPMTAG_HEADERIMMUTABLE),
        package.payload,
        RpmFormat::V6,
        None,
    )?;
    assert!(package.raw_signatures()?.is_empty());
    assert!(package.check_digests()?.header_sha256.is_verified());
    Ok(())
}

#[test]
fn file_options_can_override_mtime() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = rpm::PackageBuilder::new("mtime", "1", "MIT", "noarch", "mtime");
    builder.with_file_contents(
        b"content".to_vec(),
        rpm::FileOptions::new("./mtime").modified_at(Timestamp(42)),
    )?;
    let package = builder.build()?;
    let entry = package.metadata.get_file_entries()?.remove(0);
    assert_eq!(entry.modified_at(), Timestamp(42));
    Ok(())
}

#[test]
fn payload_result_exposes_derived_metadata_and_hardlinks() -> Result<(), Box<dyn std::error::Error>>
{
    let mut builder = rpm::PackageBuilder::new("payload", "1", "MIT", "noarch", "payload");
    builder.with_file_contents(
        b"same".to_vec(),
        rpm::FileOptions::new("./a").hardlink("set"),
    )?;
    builder.with_file_contents(
        b"same".to_vec(),
        rpm::FileOptions::new("./b").hardlink("set"),
    )?;
    let result = builder.build_payload()?;
    assert!(!result.compressed_payload.is_empty());
    assert!(!result.file_header_entries().is_empty());
    assert!(!result.payload_header_entries().is_empty());
    assert_eq!(
        result.hardlinks(),
        vec![vec!["/a".to_string(), "/b".to_string()]]
    );
    assert!(result.archive_size > 0);
    Ok(())
}

#[test]
fn header_editor_preserves_unknown_tags_and_regenerates_region()
-> Result<(), Box<dyn std::error::Error>> {
    let original = Header::from_entries(
        [
            HeaderEntry::new(
                IndexTag::RPMTAG_NAME as u32,
                IndexData::StringTag("old".into()),
            ),
            HeaderEntry::new(65000, IndexData::Bin(vec![0, 255, 1])),
        ],
        IndexTag::RPMTAG_HEADERIMMUTABLE,
    );
    let mut editor = HeaderEditor::from_header(&original, IndexTag::RPMTAG_HEADERIMMUTABLE)?;
    editor.upsert(
        IndexTag::RPMTAG_NAME as u32,
        IndexData::StringTag("new".into()),
    );
    editor.upsert(65001, IndexData::Int32(vec![7]));
    let rebuilt = editor.build();
    let package = Package::assemble(Lead::new("new"), rebuilt, Vec::new(), RpmFormat::V4, None)?;
    let mut bytes = Vec::new();
    package.write(&mut bytes)?;
    let parsed = Package::parse(&mut Cursor::new(bytes))?;
    let entries = parsed.metadata.header.get_all_entries()?;
    assert_eq!(
        entries
            .iter()
            .filter(|(tag, _)| *tag == rpm::constants::HEADER_IMMUTABLE)
            .count(),
        1
    );
    assert_eq!(
        parsed.metadata.header.entry(65000u32)?,
        IndexData::Bin(vec![0, 255, 1])
    );
    assert_eq!(
        parsed.metadata.header.entry(65001u32)?,
        IndexData::Int32(vec![7])
    );
    assert_eq!(parsed.metadata.get_name()?, "new");
    Ok(())
}

#[test]
fn standalone_payload_builder_handles_hardlinks_ghosts_symlinks_and_mtime()
-> Result<(), Box<dyn std::error::Error>> {
    let mut builder = PayloadBuilder::new();
    builder.using_config(
        BuildConfig::v6()
            .compression(CompressionType::None)
            .file_digest_algorithm(DigestAlgorithm::Sha2_512),
    );
    builder.with_file_contents(
        b"shared".to_vec(),
        FileOptions::new("/a")
            .hardlink("set")
            .modified_at(Timestamp(12)),
    )?;
    builder.with_file_contents(
        b"shared".to_vec(),
        FileOptions::new("/b")
            .hardlink("set")
            .modified_at(Timestamp(12)),
    )?;
    builder.with_dir_entry(FileOptions::dir("/dir").modified_at(Timestamp(13)))?;
    builder.with_ghost(FileOptions::ghost("/ghost"))?;
    builder.with_symlink(FileOptions::symlink("/link", "/a"))?;
    let result = builder.build()?;
    assert_eq!(
        result
            .files()
            .iter()
            .map(|file| file.path.as_str())
            .collect::<Vec<_>>(),
        vec!["/a", "/b", "/dir", "/ghost", "/link"]
    );
    assert_eq!(result.files()[0].size, 6);
    assert_eq!(result.files()[0].payload_size, 0);
    assert_eq!(result.files()[1].payload_size, 6);
    assert_eq!(
        result.files()[0].digest,
        hex::encode(sha2::Sha512::digest(b"shared"))
    );
    assert_eq!(result.files()[0].digest, result.files()[1].digest);
    assert_eq!(result.files()[0].modified_at, Timestamp(12));
    assert_eq!(result.files()[3].payload_size, 0);
    assert_eq!(
        result.hardlinks(),
        vec![vec!["/a".to_string(), "/b".to_string()]]
    );
    assert!(
        result
            .payload_header_entries()
            .iter()
            .any(|entry| entry.tag == IndexTag::RPMTAG_RPMFORMAT as u32)
    );
    Ok(())
}

#[test]
fn standalone_and_package_builders_share_payload_results() -> Result<(), Box<dyn std::error::Error>>
{
    for format in [RpmFormat::V4, RpmFormat::V6] {
        let config = BuildConfig::from(format)
            .compression(CompressionType::None)
            .source_date(42);
        let mut standalone = PayloadBuilder::new();
        standalone.using_config(config);
        standalone.with_file_contents(b"content".to_vec(), FileOptions::new("/file"))?;
        let result = standalone.build()?;

        let mut ordinary = PackageBuilder::new("same", "1", "MIT", "noarch", "same");
        ordinary.using_config(config);
        ordinary.with_file_contents(b"content".to_vec(), FileOptions::new("/file"))?;
        let package = ordinary.build()?;
        assert_eq!(result.compressed_payload, package.payload);
        for entry in result.rebuild_header_entries() {
            assert_eq!(
                package.metadata.header.entry(entry.tag)?,
                entry.data,
                "tag {}",
                entry.tag
            );
        }
    }
    Ok(())
}

#[test]
fn raw_rebuild_replaces_stale_derived_tags_but_preserves_editable_ones()
-> Result<(), Box<dyn std::error::Error>> {
    let mut builder = PayloadBuilder::new();
    builder.using_config(BuildConfig::v4().compression(CompressionType::None));
    builder.with_file_contents(b"changed".to_vec(), FileOptions::new("/file"))?;
    let result = builder.build()?;
    let mut editor = HeaderEditor::new(IndexTag::RPMTAG_HEADERIMMUTABLE);
    editor.upsert(65000, IndexData::StringTag("custom".into()));
    editor.upsert(
        IndexTag::RPMTAG_PAYLOADCOMPRESSOR as u32,
        IndexData::StringTag("gzip".into()),
    );
    editor.upsert(
        IndexTag::RPMTAG_FILELANGS as u32,
        IndexData::StringArray(vec!["fr".into()]),
    );
    editor.upsert(
        IndexTag::RPMTAG_FILEDIGESTS as u32,
        IndexData::StringArray(vec!["stale".into()]),
    );
    result.apply_to_header(&mut editor);
    let header = editor.build();
    assert!(!header.entry_is_present(IndexTag::RPMTAG_PAYLOADCOMPRESSOR));
    assert_eq!(
        header.entry(65000u32)?,
        IndexData::StringTag("custom".into())
    );
    assert_eq!(
        header.entry(IndexTag::RPMTAG_FILELANGS)?,
        IndexData::StringArray(vec!["fr".into()])
    );
    assert_ne!(
        header.entry(IndexTag::RPMTAG_FILEDIGESTS)?,
        IndexData::StringArray(vec!["stale".into()])
    );
    Ok(())
}

#[test]
fn assembled_package_has_no_cryptographic_file_or_verity_signatures()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm"
    );
    let original = Package::open(fixture)?;
    let rebuilt = Package::assemble(
        original.metadata.lead,
        original.metadata.header,
        original.payload,
        RpmFormat::V6,
        Some(128),
    )?;
    assert!(rebuilt.raw_signatures()?.is_empty());
    for tag in [
        IndexSignatureTag::RPMSIGTAG_FILESIGNATURES,
        IndexSignatureTag::RPMSIGTAG_VERITYSIGNATURES,
        IndexSignatureTag::RPMSIGTAG_VERITYSIGNATUREALGO,
    ] {
        assert!(!rebuilt.metadata.signature.entry_is_present(tag));
    }
    assert!(rebuilt.check_digests()?.header_sha256.is_verified());
    Ok(())
}

#[test]
fn context_specific_tag_names_do_not_confuse_overlapping_numbers() {
    let main = rpm::constants::main_tag_name(1008);
    let signature = rpm::constants::signature_tag_name(1008);
    assert_ne!(main, signature);
    assert_eq!(rpm::constants::parse_main_tag_name(&main), Some(1008));
    assert_eq!(
        rpm::constants::parse_signature_tag_name(&signature),
        Some(1008)
    );
    assert_eq!(rpm::constants::main_tag_name(65000), "#65000");
    assert_eq!(rpm::constants::parse_main_tag_name("#65000"), Some(65000));
}

#[test]
fn unsupported_file_digest_algorithm_fails_explicitly() {
    let mut builder = PayloadBuilder::new();
    builder.using_config(BuildConfig::v4().file_digest_algorithm(DigestAlgorithm::Md5));
    builder
        .with_file_contents(b"bytes".to_vec(), FileOptions::new("/file"))
        .unwrap();
    assert!(matches!(
        builder.build(),
        Err(rpm::Error::InvalidFileOptions {
            method: "BuildConfig::file_digest_algorithm",
            ..
        })
    ));
}

#[test]
fn standalone_payload_respects_gzip_and_sha3_file_digest() -> Result<(), Box<dyn std::error::Error>>
{
    let mut builder = PayloadBuilder::new();
    builder.using_config(
        BuildConfig::v4()
            .compression(CompressionType::Gzip)
            .file_digest_algorithm(DigestAlgorithm::Sha3_256),
    );
    builder.with_file_contents(b"bytes".to_vec(), FileOptions::new("/file"))?;
    let result = builder.build()?;
    assert!(result.compressed_payload.starts_with(&[0x1f, 0x8b]));
    assert_eq!(
        result.files()[0].digest,
        hex::encode(sha3::Sha3_256::digest(b"bytes"))
    );
    assert_eq!(
        result
            .file_header_entries()
            .iter()
            .find(|entry| entry.tag == IndexTag::RPMTAG_FILEDIGESTALGO as u32)
            .unwrap()
            .data,
        IndexData::Int32(vec![DigestAlgorithm::Sha3_256 as u32])
    );
    Ok(())
}

#[test]
fn v4_assembly_refreshes_size_digest_and_reserved_space() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm"
    );
    let original = Package::open(fixture)?;
    let rebuilt = Package::assemble(
        original.metadata.lead,
        original.metadata.header,
        original.payload,
        RpmFormat::V4,
        Some(96),
    )?;
    assert!(rebuilt.check_digests()?.header_sha256.is_verified());
    assert!(
        rebuilt
            .metadata
            .signature
            .entry_is_present(IndexSignatureTag::RPMSIGTAG_SIZE)
    );
    assert_eq!(
        rebuilt
            .metadata
            .signature
            .entry(IndexSignatureTag::RPMSIGTAG_RESERVEDSPACE)?,
        IndexData::Bin(vec![0; 96])
    );
    Ok(())
}
