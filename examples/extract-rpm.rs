use clap::Parser;
use rpm::Package;
use std::path::PathBuf;

/// Extract an RPM's payload to a directory.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the RPM file
    rpm: PathBuf,

    /// Destination directory (defaults to current directory)
    #[arg(short, long, default_value = ".")]
    dest: PathBuf,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let pkg = Package::open(&args.rpm)?;

    let nevra = pkg.metadata.get_nevra()?;
    println!("Extracting {nevra} to {}/", args.dest.display());

    for file in pkg.files()? {
        let file = file?;
        println!("  {}", file.metadata.path().display());
    }

    pkg.extract(&args.dest)?;

    Ok(())
}
