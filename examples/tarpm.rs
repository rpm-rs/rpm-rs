//! Extract and rebuild RPMs in the JSON-oriented format used by tarpm.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use base64::prelude::*;
use clap::{CommandFactory, Parser};
use rpm::{
    BuildConfig, CompressionType, FileOptions, FileType, Header, HeaderEntry, IndexData, IndexTag,
    Lead, Package, PackageBuilder, RpmFormat, Tag, Timestamp, constants,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

#[derive(Parser, Debug)]
#[command(about = "Extract and rebuild RPMs using tarpm-compatible JSON")]
struct Args {
    #[arg(short = 't', conflicts_with_all = ["extract", "create"])]
    list: bool,
    #[arg(short = 'x', conflicts_with_all = ["list", "create"])]
    extract: bool,
    #[arg(short = 'c', conflicts_with_all = ["list", "extract"])]
    create: bool,
    #[arg(short = 'f')]
    filename: Option<PathBuf>,
    #[arg(short = 'O')]
    output: Option<PathBuf>,
    #[arg(short = 'v', long)]
    verbose: bool,
    path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JsonTag {
    tag: String,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HeaderDocument {
    #[serde(default)]
    tags: Vec<JsonTag>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dependencies: Option<std::collections::BTreeMap<String, Vec<DependencyDocument>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    changelog: Option<Vec<ChangelogDocument>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    files: Vec<FileDocument>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DependencyDocument {
    name: String,
    comparison: String,
    version: String,
    sense_flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChangelogDocument {
    timestamp: u64,
    name: String,
    text: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileDocument {
    path: String,
    size: u64,
    mode: String,
    mtime: u64,
    user: String,
    group: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linkto: Option<String>,
    flags: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeadDocument {
    magic: String,
    major: u8,
    minor: u8,
    package_type: u16,
    arch: u16,
    name: String,
    os: u16,
    signature_type: u16,
    reserved: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    if args.list {
        list(&args)?;
    } else if args.extract {
        extract(&args)?;
    } else if args.create {
        create(&args)?;
    } else {
        Args::command().print_help()?;
        println!();
    }
    Ok(())
}

fn rpm_path(args: &Args) -> Result<&Path, Box<dyn std::error::Error>> {
    args.filename
        .as_deref()
        .or(args.path.as_deref())
        .ok_or_else(|| "an RPM filename is required".into())
}

fn list(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(rpm_path(args)?)?;
    if package.metadata.is_source_package() {
        return Err("source RPM payloads are not supported by this example".into());
    }
    for path in package.metadata.get_file_paths()? {
        if args.verbose
            && let Some(entry) = package.metadata.find_file_entry(&path)?
        {
            println!("{:06o} {}", entry.mode().raw_mode(), path.display());
            continue;
        }
        println!("{}", path.display());
    }
    Ok(())
}

fn extract(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let package = Package::open(rpm_path(args)?)?;
    if package.metadata.is_source_package() {
        return Err("source RPM payloads are not supported by this example".into());
    }
    let root = args.output.clone().unwrap_or_else(|| {
        PathBuf::from(
            package
                .canonical_filename()
                .unwrap_or_else(|_| "rpm-extracted.rpm".to_string())
                .trim_end_matches(".rpm"),
        )
    });
    fs::create_dir_all(&root)?;
    let payload = root.join("payload");
    package.extract(&payload)?;

    write_json(
        &root.join("lead.json"),
        &lead_document(&package.metadata.lead),
    )?;
    write_json(
        &root.join("signature.json"),
        &header_document(&package.metadata.signature)?,
    )?;
    let mut header = header_document(&package.metadata.header)?;
    header.files = package
        .metadata
        .get_file_entries()?
        .into_iter()
        .map(file_document)
        .collect();
    header.dependencies = Some(dependency_documents(&package.metadata)?);
    header.changelog = Some(
        package
            .metadata
            .get_changelog_entries()?
            .into_iter()
            .map(|entry| ChangelogDocument {
                timestamp: entry.timestamp,
                name: entry.name,
                text: entry.description.lines().map(str::to_string).collect(),
            })
            .collect(),
    );
    write_json(&root.join("header.json"), &header)?;
    Ok(())
}

fn create(args: &Args) -> Result<(), Box<dyn std::error::Error>> {
    let root = args
        .path
        .as_deref()
        .ok_or("an extracted directory is required")?;
    let output = args
        .filename
        .as_deref()
        .or(args.output.as_deref())
        .ok_or("an output RPM filename is required")?;
    let document: HeaderDocument = serde_json::from_slice(&fs::read(root.join("header.json"))?)?;
    let mut source_entries = document
        .tags
        .iter()
        .map(|tag| json_tag_to_entry(tag, root))
        .collect::<Result<Vec<_>, _>>()?;
    apply_dependency_documents(&mut source_entries, document.dependencies.as_ref())?;
    apply_changelog_documents(&mut source_entries, document.changelog.as_ref())?;
    let get = |name: &str| -> Option<String> {
        let number = constants::parse_tag_name(name)?;
        source_entries.iter().find_map(|entry| {
            (entry.tag == number).then(|| match &entry.data {
                IndexData::StringTag(value) => value.clone(),
                _ => String::new(),
            })
        })
    };
    if source_entries
        .iter()
        .any(|entry| entry.tag == IndexTag::RPMTAG_SOURCEPACKAGE as u32)
    {
        return Err("source RPMs are not supported by this example".into());
    }
    let name = get("RPMTAG_NAME").ok_or("header.json has no RPMTAG_NAME")?;
    let version = get("RPMTAG_VERSION").ok_or("header.json has no RPMTAG_VERSION")?;
    let license = get("RPMTAG_LICENSE").unwrap_or_else(|| "NOASSERTION".to_string());
    let arch = get("RPMTAG_ARCH").unwrap_or_else(|| "noarch".to_string());
    let summary = get("RPMTAG_SUMMARY").unwrap_or_else(|| name.clone());
    let format = if source_entries.iter().any(|entry| {
        entry.tag == IndexTag::RPMTAG_RPMFORMAT as u32
            && matches!(&entry.data, IndexData::Int32(values) if values.first() == Some(&6))
    }) {
        RpmFormat::V6
    } else {
        RpmFormat::V4
    };
    let compression_name = get("RPMTAG_PAYLOADCOMPRESSOR").unwrap_or_else(|| "none".to_string());
    let compression = if compression_name == "none" {
        CompressionType::None
    } else {
        compression_name.parse::<CompressionType>()?
    };
    let mut builder = PackageBuilder::new(&name, &version, &license, &arch, &summary);
    builder.using_config(BuildConfig::from(format).compression(compression));
    if let Some(release) = get("RPMTAG_RELEASE") {
        builder.release(release);
    }
    if let Some(description) = get("RPMTAG_DESCRIPTION") {
        builder.description(description);
    }
    let source_header_entries = source_entries
        .iter()
        .filter(|entry| {
            entry.tag != constants::HEADER_IMMUTABLE && entry.tag != constants::HEADER_REGIONS
        })
        .cloned()
        .collect::<Vec<_>>();
    let source_package = Package::assemble(
        Lead::new(&name),
        Header::from_entries(source_header_entries, IndexTag::RPMTAG_HEADERIMMUTABLE),
        Vec::new(),
        format,
        None,
    )?;
    let mut file_overrides = std::collections::BTreeMap::new();
    for entry in source_package.metadata.get_file_entries()? {
        file_overrides.insert(
            entry
                .path()
                .to_string_lossy()
                .trim_start_matches('/')
                .to_string(),
            FileOverride {
                mode: entry.mode(),
                modified_at: entry.modified_at(),
                user: entry.user().to_string(),
                group: entry.group().to_string(),
                linkto: entry.linkto().map(str::to_string),
                flags: entry.flags(),
            },
        );
    }
    if !document.files.is_empty() {
        file_overrides.clear();
        for file in &document.files {
            let mode = u16::from_str_radix(file.mode.trim_start_matches("0o"), 8)?;
            file_overrides.insert(
                file.path.trim_start_matches('/').to_string(),
                FileOverride {
                    mode: mode.into(),
                    modified_at: Timestamp(file.mtime.try_into()?),
                    user: file.user.clone(),
                    group: file.group.clone(),
                    linkto: file.linkto.clone(),
                    flags: rpm::FileFlags::from_bits_retain(file.flags),
                },
            );
        }
    }
    add_payload_tree(
        &mut builder,
        &root.join("payload"),
        &root.join("payload"),
        &file_overrides,
    )?;
    for (path, metadata) in &file_overrides {
        if metadata.flags.contains(rpm::FileFlags::GHOST) {
            let destination = format!("./{path}");
            let options = if metadata.mode.file_type() == FileType::Dir {
                FileOptions::ghost_dir(&destination)
            } else {
                FileOptions::ghost(&destination)
            }
            .mode(metadata.mode)
            .user(&metadata.user)
            .group(&metadata.group)
            .modified_at(metadata.modified_at);
            builder.with_ghost(options)?;
        }
    }
    let built = builder.build_payload()?;

    let derived = |tag: u32| {
        [
            IndexTag::RPMTAG_SIZE as u32,
            IndexTag::RPMTAG_LONGSIZE as u32,
            IndexTag::RPMTAG_ARCHIVESIZE as u32,
            IndexTag::RPMTAG_LONGARCHIVESIZE as u32,
            IndexTag::RPMTAG_FILEDIGESTALGO as u32,
            IndexTag::RPMTAG_RPMFORMAT as u32,
            IndexTag::RPMTAG_FILESIZES as u32,
            IndexTag::RPMTAG_LONGFILESIZES as u32,
            IndexTag::RPMTAG_FILEMODES as u32,
            IndexTag::RPMTAG_FILERDEVS as u32,
            IndexTag::RPMTAG_FILEMTIMES as u32,
            IndexTag::RPMTAG_FILEDIGESTS as u32,
            IndexTag::RPMTAG_FILELINKTOS as u32,
            IndexTag::RPMTAG_FILEFLAGS as u32,
            IndexTag::RPMTAG_FILEUSERNAME as u32,
            IndexTag::RPMTAG_FILEGROUPNAME as u32,
            IndexTag::RPMTAG_FILEDEVICES as u32,
            IndexTag::RPMTAG_FILEINODES as u32,
            IndexTag::RPMTAG_DIRINDEXES as u32,
            IndexTag::RPMTAG_FILELANGS as u32,
            IndexTag::RPMTAG_FILEVERIFYFLAGS as u32,
            IndexTag::RPMTAG_BASENAMES as u32,
            IndexTag::RPMTAG_DIRNAMES as u32,
            IndexTag::RPMTAG_FILECAPS as u32,
            IndexTag::RPMTAG_PAYLOADSHA256 as u32,
            IndexTag::RPMTAG_PAYLOADSHA256ALT as u32,
            IndexTag::RPMTAG_PAYLOAD_SHA3_256 as u32,
            IndexTag::RPMTAG_PAYLOAD_SHA3_256_ALT as u32,
            IndexTag::RPMTAG_PAYLOAD_SHA512 as u32,
            IndexTag::RPMTAG_PAYLOAD_SHA512_ALT as u32,
            IndexTag::RPMTAG_PAYLOADSIZE as u32,
            IndexTag::RPMTAG_PAYLOADSIZEALT as u32,
            IndexTag::RPMTAG_PAYLOADCOMPRESSOR as u32,
            IndexTag::RPMTAG_PAYLOADFLAGS as u32,
        ]
        .contains(&tag)
    };
    let mut entries: Vec<HeaderEntry> = source_entries
        .into_iter()
        .filter(|entry| entry.tag != constants::HEADER_IMMUTABLE && !derived(entry.tag))
        .collect();
    for (tag, data) in built.header.get_all_entries()? {
        if derived(tag) {
            entries.push(HeaderEntry::new(tag, data));
        }
    }
    let package = Package::assemble(
        Lead::new(&name),
        Header::from_entries(entries, IndexTag::RPMTAG_HEADERIMMUTABLE),
        built.compressed_payload,
        format,
        Some(rpm::SignatureHeaderBuilder::DEFAULT_RESERVED_SPACE),
    )?;
    package.write_file(output)?;
    Ok(())
}

struct FileOverride {
    mode: rpm::FileMode,
    modified_at: Timestamp,
    user: String,
    group: String,
    linkto: Option<String>,
    flags: rpm::FileFlags,
}

fn add_payload_tree(
    builder: &mut PackageBuilder,
    root: &Path,
    path: &Path,
    overrides: &std::collections::BTreeMap<String, FileOverride>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut children = fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(|entry| entry.file_name());
    for child in children {
        let child_path = child.path();
        let relative = child_path.strip_prefix(root)?.to_string_lossy();
        let destination = format!("./{}", relative.replace(std::path::MAIN_SEPARATOR, "/"));
        let metadata = fs::symlink_metadata(&child_path)?;
        let default_modified_at = metadata
            .modified()
            .ok()
            .and_then(|time| time.try_into().ok())
            .unwrap_or(Timestamp(0));
        let override_data = overrides.get(relative.as_ref());
        let modified_at = override_data
            .map(|data| data.modified_at)
            .unwrap_or(default_modified_at);
        let user = override_data.map(|data| data.user.as_str());
        let group = override_data.map(|data| data.group.as_str());
        if metadata.file_type().is_dir() {
            let mut options = FileOptions::dir(&destination)
                .modified_at(modified_at)
                .mode(
                    override_data
                        .map(|data| data.mode)
                        .unwrap_or_else(|| rpm::FileMode::dir(0o755)),
                );
            if let Some(user) = user {
                options = options.user(user);
            }
            if let Some(group) = group {
                options = options.group(group);
            }
            builder.with_dir_entry(options)?;
            add_payload_tree(builder, root, &child_path, overrides)?;
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&child_path)?;
            let target = override_data
                .and_then(|data| data.linkto.as_deref())
                .unwrap_or(target.to_string_lossy().as_ref())
                .to_string();
            let mut options = FileOptions::symlink(&destination, target).modified_at(modified_at);
            if let Some(data) = override_data {
                options = options.mode(data.mode);
            }
            if let Some(user) = user {
                options = options.user(user);
            }
            if let Some(group) = group {
                options = options.group(group);
            }
            builder.with_symlink(options)?;
        } else if metadata.file_type().is_file() {
            let mut options = FileOptions::new(&destination).modified_at(modified_at);
            if let Some(data) = override_data {
                options = options.mode(data.mode);
            }
            if let Some(user) = user {
                options = options.user(user);
            }
            if let Some(group) = group {
                options = options.group(group);
            }
            builder.with_file(&child_path, options)?;
        } else {
            return Err(format!("unsupported payload entry: {}", child_path.display()).into());
        }
    }
    Ok(())
}

fn lead_document(lead: &Lead) -> LeadDocument {
    LeadDocument {
        magic: BASE64_STANDARD.encode(lead.magic()),
        major: lead.major(),
        minor: lead.minor(),
        package_type: lead.package_type(),
        arch: lead.arch(),
        name: lead.name(),
        os: lead.os(),
        signature_type: lead.signature_type(),
        reserved: BASE64_STANDARD.encode(lead.reserved()),
    }
}

fn header_document<T: Tag>(header: &Header<T>) -> Result<HeaderDocument, rpm::Error> {
    let tags = header
        .get_all_entries()?
        .into_iter()
        .filter(|(tag, _)| *tag != constants::HEADER_IMMUTABLE && *tag != constants::HEADER_REGIONS)
        .map(|(tag, data)| data_to_json_tag(tag, data))
        .collect();
    Ok(HeaderDocument {
        tags,
        ..Default::default()
    })
}

fn data_to_json_tag(tag: u32, data: IndexData) -> JsonTag {
    let (kind, value) = match data {
        IndexData::Null => ("null", None),
        IndexData::Char(value) => ("char", Some(json!(value))),
        IndexData::Int8(value) => ("int8", Some(json!(value))),
        IndexData::Int16(value) => ("int16", Some(json!(value))),
        IndexData::Int32(value) => ("int32", Some(json!(value))),
        IndexData::Int64(value) => ("int64", Some(json!(value))),
        IndexData::StringTag(value) => ("string", Some(json!(value))),
        IndexData::Bin(value) => ("bin", Some(json!(BASE64_STANDARD.encode(value)))),
        IndexData::StringArray(value) => ("string_array", Some(json!(value))),
        IndexData::I18NString(value) => ("i18n_string", Some(json!(value))),
    };
    JsonTag {
        tag: constants::tag_name(tag),
        kind: kind.to_string(),
        value,
        file: None,
    }
}

fn file_document(entry: rpm::FileEntry<'_>) -> FileDocument {
    FileDocument {
        path: entry.path().to_string_lossy().into_owned(),
        size: entry.size() as u64,
        mode: format!("{:o}", entry.mode().raw_mode()),
        mtime: entry.modified_at().0 as u64,
        user: entry.user().to_string(),
        group: entry.group().to_string(),
        digest: entry.digest().map(|digest| digest.as_hex().to_string()),
        linkto: entry.linkto().map(str::to_string),
        flags: entry.flags().bits(),
    }
}

fn dependency_documents(
    metadata: &rpm::PackageMetadata,
) -> Result<std::collections::BTreeMap<String, Vec<DependencyDocument>>, rpm::Error> {
    let mut result = std::collections::BTreeMap::new();
    for (name, dependencies) in [
        ("provides", metadata.get_provides()),
        ("requires", metadata.get_requires()),
        ("conflicts", metadata.get_conflicts()),
        ("obsoletes", metadata.get_obsoletes()),
        ("recommends", metadata.get_recommends()),
        ("suggests", metadata.get_suggests()),
        ("supplements", metadata.get_supplements()),
        ("enhances", metadata.get_enhances()),
    ] {
        result.insert(
            name.to_string(),
            dependencies?
                .into_iter()
                .map(|dependency| {
                    let flags = dependency.flags.bits();
                    let comparison = match flags & 0x0e {
                        0x0a => "<=",
                        0x0c => ">=",
                        0x08 => "=",
                        0x04 => ">",
                        0x02 => "<",
                        _ => "",
                    };
                    DependencyDocument {
                        name: dependency.name,
                        comparison: comparison.to_string(),
                        version: dependency.version,
                        sense_flags: flags,
                    }
                })
                .collect(),
        );
    }
    Ok(result)
}

fn apply_dependency_documents(
    entries: &mut Vec<HeaderEntry>,
    documents: Option<&std::collections::BTreeMap<String, Vec<DependencyDocument>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(documents) = documents else {
        return Ok(());
    };
    let categories = [
        (
            "provides",
            IndexTag::RPMTAG_PROVIDENAME,
            IndexTag::RPMTAG_PROVIDEVERSION,
            IndexTag::RPMTAG_PROVIDEFLAGS,
        ),
        (
            "requires",
            IndexTag::RPMTAG_REQUIRENAME,
            IndexTag::RPMTAG_REQUIREVERSION,
            IndexTag::RPMTAG_REQUIREFLAGS,
        ),
        (
            "conflicts",
            IndexTag::RPMTAG_CONFLICTNAME,
            IndexTag::RPMTAG_CONFLICTVERSION,
            IndexTag::RPMTAG_CONFLICTFLAGS,
        ),
        (
            "obsoletes",
            IndexTag::RPMTAG_OBSOLETENAME,
            IndexTag::RPMTAG_OBSOLETEVERSION,
            IndexTag::RPMTAG_OBSOLETEFLAGS,
        ),
        (
            "recommends",
            IndexTag::RPMTAG_RECOMMENDNAME,
            IndexTag::RPMTAG_RECOMMENDVERSION,
            IndexTag::RPMTAG_RECOMMENDFLAGS,
        ),
        (
            "suggests",
            IndexTag::RPMTAG_SUGGESTNAME,
            IndexTag::RPMTAG_SUGGESTVERSION,
            IndexTag::RPMTAG_SUGGESTFLAGS,
        ),
        (
            "supplements",
            IndexTag::RPMTAG_SUPPLEMENTNAME,
            IndexTag::RPMTAG_SUPPLEMENTVERSION,
            IndexTag::RPMTAG_SUPPLEMENTFLAGS,
        ),
        (
            "enhances",
            IndexTag::RPMTAG_ENHANCENAME,
            IndexTag::RPMTAG_ENHANCEVERSION,
            IndexTag::RPMTAG_ENHANCEFLAGS,
        ),
    ];
    for (name, name_tag, version_tag, flags_tag) in categories {
        let Some(dependencies) = documents.get(name) else {
            continue;
        };
        entries.retain(|entry| {
            ![name_tag as u32, version_tag as u32, flags_tag as u32].contains(&entry.tag)
        });
        entries.extend([
            HeaderEntry::new(
                name_tag as u32,
                IndexData::StringArray(dependencies.iter().map(|d| d.name.clone()).collect()),
            ),
            HeaderEntry::new(
                version_tag as u32,
                IndexData::StringArray(dependencies.iter().map(|d| d.version.clone()).collect()),
            ),
            HeaderEntry::new(
                flags_tag as u32,
                IndexData::Int32(dependencies.iter().map(|d| d.sense_flags).collect()),
            ),
        ]);
    }
    Ok(())
}

fn apply_changelog_documents(
    entries: &mut Vec<HeaderEntry>,
    documents: Option<&Vec<ChangelogDocument>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(documents) = documents else {
        return Ok(());
    };
    let tags = [
        IndexTag::RPMTAG_CHANGELOGNAME as u32,
        IndexTag::RPMTAG_CHANGELOGTIME as u32,
        IndexTag::RPMTAG_CHANGELOGTEXT as u32,
    ];
    entries.retain(|entry| !tags.contains(&entry.tag));
    entries.extend([
        HeaderEntry::new(
            IndexTag::RPMTAG_CHANGELOGNAME as u32,
            IndexData::StringArray(documents.iter().map(|d| d.name.clone()).collect()),
        ),
        HeaderEntry::new(
            IndexTag::RPMTAG_CHANGELOGTIME as u32,
            IndexData::Int32(
                documents
                    .iter()
                    .map(|d| u32::try_from(d.timestamp))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
        ),
        HeaderEntry::new(
            IndexTag::RPMTAG_CHANGELOGTEXT as u32,
            IndexData::StringArray(documents.iter().map(|d| d.text.join("\n")).collect()),
        ),
    ]);
    Ok(())
}

fn json_tag_to_entry(
    tag: &JsonTag,
    root: &Path,
) -> Result<HeaderEntry, Box<dyn std::error::Error>> {
    let number = constants::parse_tag_name(&tag.tag)
        .ok_or_else(|| format!("unknown tag name: {}", tag.tag))?;
    let value = if let Some(file) = &tag.file {
        Value::String(fs::read_to_string(root.join(file))?)
    } else {
        tag.value.clone().unwrap_or(Value::Null)
    };
    let data = match tag.kind.as_str() {
        "null" => IndexData::Null,
        "char" => IndexData::Char(bytes(&value)?),
        "int8" => IndexData::Int8(bytes(&value)?),
        "int16" => IndexData::Int16(numbers(&value)?.into_iter().map(|n| n as u16).collect()),
        "int32" => IndexData::Int32(numbers(&value)?.into_iter().map(|n| n as u32).collect()),
        "int64" => IndexData::Int64(numbers(&value)?),
        "string" => IndexData::StringTag(
            value
                .as_str()
                .ok_or("string tag is not a string")?
                .to_string(),
        ),
        "bin" | "binary" => IndexData::Bin(
            BASE64_STANDARD.decode(value.as_str().ok_or("binary tag is not base64")?)?,
        ),
        "string_array" | "i18n_string" => {
            let values = value
                .as_array()
                .ok_or("string array tag is not an array")?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or("string array member is not a string")
                })
                .collect::<Result<Vec<_>, _>>()?;
            if tag.kind == "i18n_string" {
                IndexData::I18NString(values)
            } else {
                IndexData::StringArray(values)
            }
        }
        other => return Err(format!("unsupported RPM tag type: {other}").into()),
    };
    Ok(HeaderEntry::new(number, data))
}

fn bytes(value: &Value) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(value
        .as_array()
        .ok_or("byte tag is not an array")?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|number| u8::try_from(number).ok())
                .ok_or("byte value is out of range")
        })
        .collect::<Result<Vec<_>, _>>()?)
}

fn numbers(value: &Value) -> Result<Vec<u64>, Box<dyn std::error::Error>> {
    Ok(value
        .as_array()
        .ok_or("numeric tag is not an array")?
        .iter()
        .map(|value| value.as_u64().ok_or("numeric value is not an integer"))
        .collect::<Result<Vec<_>, _>>()?)
}

fn write_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value).map_err(io::Error::other)?;
    file.write_all(b"\n")
}
