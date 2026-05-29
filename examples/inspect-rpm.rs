use clap::Parser;
use rpm::PackageMetadata;
use std::path::PathBuf;

/// Inspect an RPM package and print a detailed summary.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the RPM file
    rpm: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let meta = PackageMetadata::open(&args.rpm)?;

    let nevra = meta.get_nevra()?;
    println!("Name        : {}", nevra.name());
    println!("Epoch       : {}", nevra.epoch());
    println!("Version     : {}", nevra.version());
    println!("Release     : {}", nevra.release());
    println!("Architecture: {}", nevra.arch());

    if let Ok(summary) = meta.get_summary() {
        println!("Summary     : {summary}");
    }
    if let Ok(description) = meta.get_description() {
        println!("Description : {description}");
    }
    if let Ok(license) = meta.get_license() {
        println!("License     : {license}");
    }
    if let Ok(url) = meta.get_url() {
        println!("URL         : {url}");
    }
    if let Ok(vendor) = meta.get_vendor() {
        println!("Vendor      : {vendor}");
    }
    if let Ok(packager) = meta.get_packager() {
        println!("Packager    : {packager}");
    }
    if let Ok(build_host) = meta.get_build_host() {
        println!("Build Host  : {build_host}");
    }
    if let Ok(build_time) = meta.get_build_time() {
        println!("Build Time  : {build_time}");
    }
    if let Ok(source_rpm) = meta.get_source_rpm() {
        println!("Source RPM  : {source_rpm}");
    }
    if let Ok(size) = meta.get_installed_size() {
        println!("Size        : {size}");
    }

    for (label, deps) in [
        ("Provides", meta.get_provides()),
        ("Requires", meta.get_requires()),
        ("Conflicts", meta.get_conflicts()),
        ("Obsoletes", meta.get_obsoletes()),
        ("Recommends", meta.get_recommends()),
        ("Suggests", meta.get_suggests()),
    ] {
        if let Ok(deps) = deps {
            if !deps.is_empty() {
                println!("{label}:");
                for dep in &deps {
                    println!("  {dep}");
                }
            }
        }
    }

    if let Ok(entries) = meta.get_file_entries() {
        if !entries.is_empty() {
            println!("Files ({}):", entries.len());
            for entry in &entries {
                println!("  {}", entry.path().display());
            }
        }
    }

    Ok(())
}
