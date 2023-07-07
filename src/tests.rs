use std::io;

use hex_literal::hex;

use super::*;

fn rpm_389_ds_file_path() -> std::path::PathBuf {
    cargo_manifest_dir().join("test_assets/389-ds-base-devel-1.3.8.4-15.el7.x86_64.rpm")
}

fn cargo_manifest_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn test_rpm_builder() -> Result<(), Box<dyn std::error::Error>> {
    let mut buff = io::Cursor::new(Vec::<u8>::new());

    let mut pkg = RPMBuilder::new("test", "1.0.0", "MIT", "x86_64", "some awesome package")
        .compression(CompressionType::Gzip)
        .with_file(
            "Cargo.toml",
            RPMFileOptions::new("/etc/awesome/config.toml").is_config(),
        )?
        // file mode is inherited from source file
        .with_file("Cargo.toml", RPMFileOptions::new("/usr/bin/awesome"))?
        .with_file(
            "Cargo.toml",
            // you can set a custom mode and custom user too
            RPMFileOptions::new("/etc/awesome/second.toml")
                .mode(0o100744)
                .user("hugo"),
        )?
        .pre_install_script("echo preinst")
        .add_changelog_entry("me", "was awesome, eh?", 1_681_411_811)
        .add_changelog_entry("you", "yeah, it was", 850_984_797)
        .requires(Dependency::any("wget"))
        .vendor("dummy vendor")
        .url("dummy url")
        .vcs("dummy vcs")
        .build()?;

    pkg.write(&mut buff)?;

    // check that generated packages has source rpm tag
    // to be more compatibly recognized as RPM binary packages
    pkg.metadata.get_source_rpm()?;

    pkg.verify_digests()?;

    Ok(())
}

#[test]
fn test_rpm_header() -> Result<(), Box<dyn std::error::Error>> {
    let rpm_file_path = rpm_389_ds_file_path();
    let mut package = RPMPackage::open(rpm_file_path)?;

    let metadata = &package.metadata;
    assert_eq!(metadata.signature.index_entries.len(), 7);
    assert_eq!(metadata.signature.index_entries[0].num_items, 16);
    assert_eq!(metadata.signature.index_header.data_section_size, 1156);

    assert_eq!(package.metadata.get_name().unwrap(), "389-ds-base-devel");
    assert!(package.metadata.get_epoch().is_err());
    assert_eq!(package.metadata.get_version().unwrap(), "1.3.8.4");
    assert_eq!(package.metadata.get_release().unwrap(), "15.el7");
    assert_eq!(package.metadata.get_arch().unwrap(), "x86_64");

    assert_eq!(
        package.metadata.get_url().unwrap(),
        "https://www.port389.org/"
    );

    // TODO: vcs
    // assert_eq!(
    //     package.metadata.get_vcs().unwrap(),
    //     "git://pkgs.fedoraproject.org/389-ds-base.git"
    // );

    assert_eq!(
        package.metadata.get_packager().unwrap(),
        "CentOS BuildSystem <http://bugs.centos.org>"
    );
    assert_eq!(package.metadata.get_license().unwrap(), "GPLv3+");
    assert_eq!(package.metadata.get_vendor().unwrap(), "CentOS");

    // TODO: internationalized strings
    // assert_eq!(
    //     package.metadata.get_summary().unwrap(),
    //     "Development libraries for 389 Directory Server"
    // );
    // assert_eq!(
    //     package.metadata.get_description().unwrap(),
    //     "Development Libraries and headers for the 389 Directory Server base package."
    // );
    // assert_eq!(
    //     package.metadata.get_group().unwrap(),
    //     "Development/Libraries"
    // );
    assert_eq!(
        package.metadata.get_source_rpm().unwrap(),
        "389-ds-base-1.3.8.4-15.el7.src.rpm"
    );
    assert_eq!(
        package.metadata.get_build_host().unwrap(),
        "x86-01.bsys.centos.org"
    );
    assert_eq!(package.metadata.get_build_time().unwrap(), 1540945151);
    assert_eq!(package.metadata.get_installed_size().unwrap(), 503853);
    assert_eq!(
        package.metadata.get_payload_compressor().unwrap(),
        CompressionType::Xz
    );

    assert!(!package.metadata.is_source_package());

    let expected_data = vec![
        (
            16,
            IndexData::Bin(hex!("0000003e00000007ffffff9000000010").to_vec()),
            IndexSignatureTag::HEADER_SIGNATURES,
        ),
        (
            536,
            IndexData::Bin(
                hex!(
                    "8902150305005be98c5b24c6a8a7f4a80eb50108a84c0ffd1a9de30f7ebb74e3"
                    "62effd4d1c11a168220dff4a721118e4b0466b1182c6d4d6db53641b32334195"
                    "f30ca6c250ee81816a0805fa3b2666635cfa4b2502e7ad3f4f827aa34dad0da0"
                    "196377d2183054c71423220b0dd8ba1b6c94b30fb382186233514eaafa848a4b"
                    "cd8272f1409438c7bc48294f3298d9af351a0bf0877439d6e786449d5c7ade63"
                    "1a16b2291d469e61adff916f51658ab9370e65b6772fb7746a9c8af04b2d87bf"
                    "61ff70dc29ec9a0c7f12f655ea22b5f01a0da5e8c67f1b9c551b355cac722686"
                    "8930d52d08930f9e1afd8c7edbca574fd942d7f674cdf668efe324669229da96"
                    "878ea2882378eec3fc71fdb6366badd754554da0a3407051c276de9fa3e57f80"
                    "72a9c37f3e37d77a9998c4c64b5193bcd0f29309737f6e7ab46b7b79e0455539"
                    "fc61a7dea5ff80313914f6b6076cd7a410a087554de5a526c1990e5819aec3bf"
                    "e81648e08596511872b80f009f26deec1232ecd03cde310bd6bf4ac5665ccdb0"
                    "293c6dc61856d717b44debdcbbe44f1af5723a96444df314b17975a46acc9d27"
                    "47a912a707a830aef2debc3387b58c053f454e644a866dc3f4fe059181952fad"
                    "81da1b39f8f0b846f03882a6f235344d9e179a97afbd9b193188d83a502e9150"
                    "45059288b207109a6c44a2720fca6817991a62cd66230f90a414a66c7d06c44b"
                    "be814772ebd4a23d637386ef0e2b78d44f482eb0558c8e5d"
                )
                .to_vec(),
            ),
            IndexSignatureTag::RPMSIGTAG_RSA,
        ),
        (
            1,
            IndexData::StringTag("6178620331c1fe63c5dd3da7c118058e366e37d8".to_string()),
            IndexSignatureTag::RPMSIGTAG_SHA1,
        ),
        (
            1,
            IndexData::Int32(vec![275_904]),
            IndexSignatureTag::RPMSIGTAG_SIZE,
        ),
        (
            536,
            IndexData::Bin(
                hex!(
                    "8902150305005be98c5b24c6a8a7f4a80eb5010854e71000c4bbc55be7e380bd"
                    "e90ac6326a424ab0a9f595f1a9314a22fcf8dccf89d830198355f0b5a10cd36b"
                    "69218f05e5175c29998484c6f2a7cfe9d499422039f5d9966ac30113fa46ee6d"
                    "cb01f7c934268e9eba5d89b9d921150651a6ad70c53ad8a88494be29c19b5338"
                    "26908b7dd2a07ccca27760fab97f9077c7b9ad7eaba0dba329ec72a070d1ed9a"
                    "8c306bdfc58b0fc814cae12b95146a702123491470e684e1f1d06fc07dcdb7df"
                    "d4c6d3d0175db3f4afd3eaaaed2f7202fbd446752ac33850d7b25b616425078c"
                    "9b01f86febbb5db0028130eb4b01e1ff9f24a7e3de71519692d06018c360d5ae"
                    "d7402657f3db6a8197641024057d54958d365f23d7171a83caf0e61d2722dcb6"
                    "040de825e6c4e02617420336fef8c7c2dba2b7993aece2d4933d530d2696846e"
                    "4bfab3ca988a65a8627dbf1f80bfa3a6e7030e15b77337db35356fce71d03c15"
                    "766d26e5f6ae50c828a5b3dfd324b93ffdcc0260e4fd10710abedf1923a171e6"
                    "993cefd541207a9a8c24e87483ddabea8738ca8e3d601420c702eda1dcd5cf22"
                    "1414939c6895bf6edd283efca0fb37df9c7cef37117aa32871d5caa31709a992"
                    "c91a2b5dac0eee10c497ad184e1ab72ad21cb69d8b2291619f6ee0069cc2218f"
                    "2495801917155cba279fa4c819d1fb64f7365e6b36ba25273d31749e53f723e2"
                    "000c869cab3ff5446eaad8038b2e8cca14fe1dad6b5e608d"
                )
                .to_vec(),
            ),
            IndexSignatureTag::RPMSIGTAG_PGP,
        ),
        (
            16,
            IndexData::Bin(hex!("db6df49b40196e845eed42e216622867").to_vec()),
            IndexSignatureTag::RPMSIGTAG_MD5,
        ),
        (
            1,
            IndexData::Int32(vec![510_164]),
            IndexSignatureTag::RPMSIGTAG_PAYLOADSIZE,
        ),
    ];

    for (i, (len, data, tag)) in expected_data.iter().enumerate() {
        let actual_entry = &metadata.signature.index_entries[i];
        assert_eq!(*len as u32, actual_entry.num_items);
        assert_eq!(*data, actual_entry.data);
        assert_eq!(*tag as u32, actual_entry.tag);
    }

    assert_eq!(
        metadata.get_package_segment_offsets(),
        RPMPackageSegmentOffsets {
            lead: 0,
            signature_header: 96,
            header: 1384,
            payload: 148172
        }
    );
    assert_eq!(
        metadata.get_payload_compressor().unwrap(),
        CompressionType::Xz
    );

    let expected_file_checksums = vec![
        "",
        "3e4e2501e2a70343a661b0b85b82e27b2090a7e595dc3b5c91e732244ffc3272",
        "d36ab638ed0635afcb1582387d676b2e461c5a88ac05a6e2aada8b40b4175bc1",
        "9667aa81021c9f4d48690ef6fbb3e7d623bdae94e2da414abd044dc38e52f037",
        "1e8235e08aac746155c209c1e641e73bf7a4c34d9971aaa9f864226bd5de9d99",
        "53a1e216749208c0bdfc9e8ec70f4bb9459ad1ff224571a7a432e472d2202986",
        "2807bb4e77579c81dc7e283d60612a6ecc3ce56000691cac744a4bca73cea241",
        "",
        "",
        "",
        "",
        "",
        "a839e2870b7a212ca9dc6f92007907bc42de1984eac6c278a519d4115071f322",
        "3ca364e71a110cd0f2317fbaf99bc8552b8374dbeaf0a989695990f940d88bea",
        "eead9f55f0774559d37b20fbc5448f978e1a80d27f488768cbbb278a932e7e9f",
        "",
        "495b7c1e22dcc0f37d78076a1fcad786b69ac78f1e806466d798fd8fc4a5d10d",
        "8ceb4b9ee5adedde47b31e975c1d90c73ad27b6b165a1dcd80c7c545eb65b903",
        "a73b7d3598e98f46aeb0559e641d3e6ac83c0fc34e1e5fa98cb9d4a6050bacd9",
        "97a6a0413ce3664e192dff12a29bc3f690c24e8a0d48d986478c56cdfe370c3b",
        "d110052464fd35c5dc227b3f071606ec40c12ba773fec9ec88ad01430bd4a27b",
        "5c3adbdea58a8bb7663c65216dda7d1f38a17b067f718df46ece04ecb503f689",
        "005dc9d5aa85b10c3200535af8b0ed2123770e3a79d48be5067e81cc553d55bd",
        "aa7ea2def38dfc965b27ae20467006aca779e02ad366d50824c4615a7d43af27",
        "5ee25b47a83b1431f6ecb1d0a292a8e9a2917c1de9e87129c86cdda743be3f55",
        "413aae4fb264aad9d35db94eb28b5f70a7183101692943e81bc90d6718418d8e",
        "66004b2e338ce29e59d6a26467e251f092ae0a0f33b67dbba67d2ea9f3ec89f6",
        "3db4ad3317bff658a04a1bdbc01fab83cd348f76a1d44585b892fdb0223f2b77",
        "ccac76a229e6739ab318d9ede59f6b980d3200fc50669409d3b1e8a0ff1fa029",
        "5a3378c84c68e2a407add0f850c64d701af2aedcca67dd2489e86cb1e08dbb6b",
        "da188ece6801b97c98031b854d4000e348e969edea239cb1bcbfae7a194e3520",
        "28a93db2fe665e8b08494fe5adf3d8dc00c2f96a4994a09eb70cf982d912fa09",
        "ba92ea5c90389b38a3c003a5e4a7b09e57473cbd2fb3645c2c0012808023fd0b",
        "502dd15afe5609a113108cad047a810b7a97cc8819e830f1d5b00cb5bf65a295",
        "4445b3e6550a3d7da96a246e6138d3f349160420085ce14222d3f686eb29915c",
        "649f748bffe197539db9237d56da8a3e408731488550617596359cd32731ec06",
        "4bd801d053bf456c3dd2c94f9721d1bb0c44d2c119e233b8ad4c5189bd39b256",
        "d444bb47f4a83ebd0e6b669f73bb2d6d3dde804b70a0bbd2be66693d88ce8e16",
        "087be3693057db21a0b1d38844bb5efa8112f67f3572063546215f25f9fe8d9e",
        "2c639c8768e323f2ad4ea96f1667989cb97d49947e9bcebcd449163d9c9bb85c",
    ];

    let checksums = metadata.get_file_checksums()?;

    assert_eq!(expected_file_checksums, checksums);

    let mut buf = Vec::new();

    package.metadata.lead.write(&mut buf)?;
    assert_eq!(96, buf.len());

    let lead = Lead::parse(&buf)?;
    assert_eq!(package.metadata.lead, lead);

    buf = Vec::new();
    package.metadata.signature.write_signature(&mut buf)?;
    let signature = Header::parse_signature(&mut buf.as_slice())?;

    assert_eq!(
        package.metadata.signature.index_header,
        signature.index_header
    );

    for i in 0..signature.index_entries.len() {
        assert_eq!(
            signature.index_entries[i],
            package.metadata.signature.index_entries[i]
        );
    }
    assert_eq!(
        package.metadata.signature.index_entries,
        signature.index_entries
    );

    buf = Vec::new();
    package.metadata.header.write(&mut buf)?;
    let header = Header::parse(&mut buf.as_slice())?;
    assert_eq!(package.metadata.header, header);

    buf = Vec::new();
    package.write(&mut buf)?;
    let second_pkg = RPMPackage::parse(io::Cursor::new(buf))?;
    // assert_eq!(package.content.len(), second_pkg.content.len());
    assert_eq!(package.metadata, second_pkg.metadata);

    package.verify_digests()?;

    Ok(())
}
