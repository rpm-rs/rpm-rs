use std::io::Cursor;

use rpm::{Header, HeaderEntry, IndexData, IndexTag, Lead, Package, RpmFormat, Timestamp};

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
    package.replace_header(Header::from_entries(
        entries,
        IndexTag::RPMTAG_HEADERIMMUTABLE,
    ))?;
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
    assert!(!result.file_metadata.is_empty());
    assert!(!result.payload_digests.is_empty());
    assert_eq!(
        result.hardlinks,
        vec![vec!["/a".to_string(), "/b".to_string()]]
    );
    assert!(result.archive_size > 0);
    Ok(())
}
