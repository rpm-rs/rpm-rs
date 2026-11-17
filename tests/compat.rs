use std::path::Path;

use rpm::*;

mod common;

#[cfg(target_os = "linux")]
mod pgp {
    use super::*;
    use rpm::signature::pgp::Signer;

    /// Signature algorithms that a distro's RPM may or may not support.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Algorithm {
        Rsa,
        Ecdsa,
        Eddsa,
        Mldsa,
    }

    /// RPM format versions.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum RpmFormat {
        V4,
        V6,
    }

    /// A container image and the RPM signature capabilities it supports.
    struct Distro {
        image: &'static str,
        algorithms: &'static [Algorithm],
        formats: &'static [RpmFormat],
    }

    impl Distro {
        /// Returns true if this distro supports the given algorithm and format combination.
        fn supports(&self, alg: Algorithm, fmt: RpmFormat) -> bool {
            self.algorithms.contains(&alg) && self.formats.contains(&fmt)
        }
    }

    // NOTE: If a distro gains support for an algorithm or format, update the relevant entry.
    const DISTROS: &[Distro] = &[
        Distro {
            image: "quay.io/almalinuxorg/8-base",
            algorithms: &[Algorithm::Rsa],
            formats: &[RpmFormat::V4],
        },
        Distro {
            image: "quay.io/centos/centos:stream9",
            algorithms: &[Algorithm::Rsa, Algorithm::Eddsa],
            formats: &[RpmFormat::V4],
        },
        Distro {
            image: "quay.io/centos/centos:stream10",
            algorithms: &[Algorithm::Rsa, Algorithm::Ecdsa, Algorithm::Eddsa],
            formats: &[RpmFormat::V4, RpmFormat::V6],
        },
        Distro {
            image: "quay.io/fedora/fedora:latest",
            algorithms: &[Algorithm::Rsa, Algorithm::Ecdsa, Algorithm::Eddsa],
            formats: &[RpmFormat::V4, RpmFormat::V6],
        }, // TODO: add ML-DSA to matrix once support exists
    ];

    /// A package to install and optionally verify inside a container.
    /// The label is used for log output. The container path defaults to `/out/{label}.rpm`
    /// but can be overridden with `asset_path`.
    struct TestPackage {
        /// Identifies this package in logs. Also determines path unless `asset_path` is set.
        label: &'static str,
        /// If set, only run on distros supporting this algorithm/format.
        required: Option<(Algorithm, RpmFormat)>,
        /// Whether `rpm --checksig` must verify an OpenPGP signature.
        verify_signature: bool,
        /// Override the default `/out/{label}.rpm` container path.
        /// If set, this should be a host-side path under `tests/assets/`; it will be
        /// converted to its container-side equivalent (`/assets/...`) automatically.
        asset_path: Option<&'static str>,
    }

    /// Install and checksig multiple packages on each distro in a single container run.
    /// Each package gets a labeled section in the output so failures are easy to locate.
    /// Packages whose `required` algorithm/format aren't supported by a distro are skipped.
    #[track_caller]
    fn run_compat_tests(
        test_name: &str,
        packages: &[TestPackage],
    ) -> Result<(), Box<dyn std::error::Error>> {
        for distro in DISTROS {
            let mut cmd = String::new();

            for pkg in packages {
                let skip = matches!(
                    pkg.required,
                    Some((alg, fmt)) if !distro.supports(alg, fmt)
                );
                if skip {
                    continue;
                }

                let default_path;
                let container_path;
                let path = match &pkg.asset_path {
                    Some(p) => {
                        // Convert host-side asset path to container-side path.
                        // Host paths contain ".../tests/assets/..." which maps to "/assets/..." in the container.
                        let marker = "/tests/assets/";
                        let idx = p
                            .find(marker)
                            .expect("asset_path must contain /tests/assets/");
                        container_path = format!("/assets/{}", &p[idx + marker.len()..]);
                        &container_path
                    }
                    None => {
                        default_path = format!("/out/{}.rpm", pkg.label);
                        &default_path
                    }
                };
                let install_cmd = if pkg.asset_path.is_some() {
                    format!("rpm -ivh --nodeps --force {path}")
                } else {
                    format!("dnf ${{REPOS}} install -y {path}")
                };
                let signature_option = if pkg.verify_signature {
                    ""
                } else {
                    "--nosignature "
                };
                cmd.push_str(&format!(
                    r#"
echo ">>>>>>>>>> {label} <<<<<<<<<<"
{install_cmd}
rpm -vv --checksig {signature_option}{path} 2>&1
echo ">>>>>>>>>> {label}: OK <<<<<<<<<<"
"#,
                    label = pkg.label,
                ));
            }

            if !cmd.is_empty() {
                podman_container_launcher(test_name, &cmd, distro.image, vec![])?;
            }
        }
        Ok(())
    }

    /// Build a [`PackageBuilder`] pre-populated with files, symlinks, directories, ghosts,
    /// scripts, changelog entries, and dependencies for use in integration tests.
    fn build_full_rpm(name: &str) -> Result<PackageBuilder, Box<dyn std::error::Error>> {
        let sources = Path::new(common::CARGO_MANIFEST_DIR).join("tests/assets/SOURCES");
        let script = sources.join("multiplication_tables.py");
        let config_file = sources.join("example_config.toml");
        let module_dir = sources.join("module");

        let mut bldr = PackageBuilder::new(name, "1.0.0", "MIT", "x86_64", "some package");
        bldr.default_file_attrs(Some(0o644), Some("root".into()), Some("root".into()))
            .default_dir_attrs(Some(0o755), Some("root".into()), Some("root".into()))
            .with_file(script.to_str().unwrap(), FileOptions::new("/usr/bin/foo"))?
            .with_file(
                config_file.to_str().unwrap(),
                FileOptions::new("/etc/foobar/config.toml")
                    .permissions(0o644)
                    .config()
                    .noreplace(),
            )?
            .with_file(
                config_file.to_str().unwrap(),
                FileOptions::new("/etc/foobar/other.toml").user("hugo"),
            )?
            .with_file_contents(
                "u hugo - \"Hugo user\"",
                FileOptions::new("/usr/lib/sysusers.d/hugo.conf"),
            )?
            .with_symlink(FileOptions::symlink("/usr/bin/bar", "/usr/bin/foo"))?
            .with_dir_entry(FileOptions::dir("/var/log/foobar").permissions(0o750))?
            .with_ghost(FileOptions::ghost("/var/log/foobar/app.log"))?
            .with_ghost(FileOptions::ghost_dir("/var/run/foobar"))?
            .with_dir(module_dir.to_str().unwrap(), "/usr/lib/foobar", |o| o)?
            .epoch(1)
            .pre_install_script("echo preinst")
            .add_changelog_entry(
                "me",
                "was awesome, eh?",
                chrono::DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").unwrap(),
            )
            .add_changelog_entry(
                "you",
                "yeah, it was",
                chrono::DateTime::parse_from_rfc3339("1996-12-19T16:39:57-08:00").unwrap(),
            )
            .requires(Dependency::any("rpm-sign"))
            .provides(Dependency::eq("foobar-tools", "1.0.0"))
            .provides(Dependency::any("foobar-lib"))
            .vendor("dummy vendor")
            .url("dummy url")
            .vcs("dummy vcs");

        Ok(bldr)
    }

    /// Verify pre-built fixture packages against both rpm-rs and distro rpm --checksig,
    /// only running each package on distros that support its algorithm and format.
    #[test]
    fn smoke_test_fixtures() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();

        // Then, verify with each distro's rpm --checksig
        run_compat_tests(
            "smoke_test_fixtures",
            &[
                // v4 signed
                TestPackage {
                    label: "fixture_v4_rsa",
                    required: Some((Algorithm::Rsa, RpmFormat::V4)),
                    verify_signature: true,
                    asset_path: Some(common::pkgs::v4::RPM_BASIC_RSA_SIGNED),
                },
                TestPackage {
                    label: "fixture_v4_ecdsa",
                    required: Some((Algorithm::Ecdsa, RpmFormat::V4)),
                    verify_signature: true,
                    asset_path: Some(common::pkgs::v4::RPM_BASIC_ECDSA_SIGNED),
                },
                TestPackage {
                    label: "fixture_v4_eddsa",
                    required: Some((Algorithm::Eddsa, RpmFormat::V4)),
                    verify_signature: true,
                    asset_path: Some(common::pkgs::v4::RPM_BASIC_EDDSA_SIGNED),
                },
                // v6 signed
                TestPackage {
                    label: "fixture_v6_rsa",
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: Some(common::pkgs::v6::RPM_BASIC_RSA_SIGNED),
                },
                TestPackage {
                    label: "fixture_v6_eddsa",
                    required: Some((Algorithm::Eddsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: Some(common::pkgs::v6::RPM_BASIC_EDDSA_SIGNED),
                },
                TestPackage {
                    label: "fixture_v6_mldsa",
                    required: Some((Algorithm::Mldsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: Some(common::pkgs::v6::RPM_BASIC_MLDSA_SIGNED),
                },
                TestPackage {
                    label: "fixture_v6_multi_signed",
                    required: Some((Algorithm::Eddsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: Some(common::pkgs::v6::RPM_BASIC_MULTI_SIGNED),
                },
            ],
        )?;

        Ok(())
    }

    const EMPTY_V4_UNSIGNED: &str = "empty_v4_unsigned";
    const EMPTY_V6_UNSIGNED: &str = "empty_v6_unsigned";
    const EMPTY_V4_SIGNED_RSA: &str = "empty_v4_signed_rsa";
    const EMPTY_V6_SIGNED_RSA: &str = "empty_v6_signed_rsa";
    const EMPTY_V6_SIGNED_EDDSA: &str = "empty_v6_signed_eddsa";
    const FULL_V4_UNSIGNED: &str = "full_v4_unsigned";
    const FULL_V6_UNSIGNED: &str = "full_v6_unsigned";
    const FULL_V4_SIGNED_RSA: &str = "full_v4_signed_rsa";
    const FULL_V6_SIGNED_RSA: &str = "full_v6_signed_rsa";
    const FULL_V6_SIGNED_EDDSA: &str = "full_v6_signed_eddsa";
    const FULL_V6_MULTI_SIGNED: &str = "full_v6_multi_signed";
    const FULL_V4_ZSTD: &str = "full_v4_zstd";
    const FULL_V6_GZIP: &str = "full_v6_gzip";
    const FULL_V6_ZSTD: &str = "full_v6_zstd";
    const FULL_V6_XZ: &str = "full_v6_xz";
    const FULL_V6_UNCOMPRESSED: &str = "full_v6_uncompressed";

    /// Returns the output path for a built test RPM given its label.
    fn rpm_path(label: &str) -> std::path::PathBuf {
        Path::new(common::CARGO_OUT_DIR).join(format!("{label}.rpm"))
    }

    /// Build RPMs using rpm-rs (empty and full, unsigned and signed, v4 and v6),
    /// install them, and verify signatures across all supported distros.
    #[test]
    fn test_rpm_compat() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();

        let v4_rsa_signer = Signer::from_asc_file(common::keys::v4::RSA_4K_PRIVATE)?;
        let v6_rsa_signer = Signer::from_asc_file(common::keys::v6::RSA_4K_PRIVATE)?;
        let v6_eddsa_signer = Signer::from_asc_file(common::keys::v6::ED25519_PRIVATE)?;
        // TODO: let v6_mldsa_signer = Signer::from_asc_file(common::keys::v6::MLDSA65_ED25519_PRIVATE)?;

        // Empty unsigned
        PackageBuilder::new(EMPTY_V4_UNSIGNED, "1.0.0", "MIT", "x86_64", "empty package")
            .using_config(BuildConfig::v4())
            .build()?
            .write_file(rpm_path(EMPTY_V4_UNSIGNED))?;

        PackageBuilder::new(EMPTY_V6_UNSIGNED, "1.0.0", "MIT", "x86_64", "empty package")
            .using_config(BuildConfig::v6())
            .build()?
            .write_file(rpm_path(EMPTY_V6_UNSIGNED))?;

        // Empty signed (v4 RSA only, v6 with multiple algorithms)
        PackageBuilder::new(
            EMPTY_V4_SIGNED_RSA,
            "1.0.0",
            "MIT",
            "x86_64",
            "empty package",
        )
        .using_config(BuildConfig::v4())
        .build_and_sign(&v4_rsa_signer)?
        .write_file(rpm_path(EMPTY_V4_SIGNED_RSA))?;

        PackageBuilder::new(
            EMPTY_V6_SIGNED_RSA,
            "1.0.0",
            "MIT",
            "x86_64",
            "empty package",
        )
        .using_config(BuildConfig::v6())
        .build_and_sign(&v6_rsa_signer)?
        .write_file(rpm_path(EMPTY_V6_SIGNED_RSA))?;

        PackageBuilder::new(
            EMPTY_V6_SIGNED_EDDSA,
            "1.0.0",
            "MIT",
            "x86_64",
            "empty package",
        )
        .using_config(BuildConfig::v6())
        .build_and_sign(&v6_eddsa_signer)?
        .write_file(rpm_path(EMPTY_V6_SIGNED_EDDSA))?;

        // Full unsigned
        build_full_rpm(FULL_V4_UNSIGNED)?
            .using_config(BuildConfig::v4().compression(CompressionType::Gzip))
            .build()?
            .write_file(rpm_path(FULL_V4_UNSIGNED))?;

        build_full_rpm(FULL_V6_UNSIGNED)?
            .using_config(BuildConfig::v6().compression(CompressionType::Gzip))
            .build()?
            .write_file(rpm_path(FULL_V6_UNSIGNED))?;

        // Full signed (v4 RSA only, v6 with multiple algorithms)
        build_full_rpm(FULL_V4_SIGNED_RSA)?
            .using_config(BuildConfig::v4().compression(CompressionType::Gzip))
            .build_and_sign(&v4_rsa_signer)?
            .write_file(rpm_path(FULL_V4_SIGNED_RSA))?;

        build_full_rpm(FULL_V6_SIGNED_RSA)?
            .using_config(BuildConfig::v6().compression(CompressionType::Gzip))
            .build_and_sign(&v6_rsa_signer)?
            .write_file(rpm_path(FULL_V6_SIGNED_RSA))?;

        build_full_rpm(FULL_V6_SIGNED_EDDSA)?
            .using_config(BuildConfig::v6().compression(CompressionType::Gzip))
            .build_and_sign(&v6_eddsa_signer)?
            .write_file(rpm_path(FULL_V6_SIGNED_EDDSA))?;

        // Multi-signed (sign with both RSA and EdDSA)
        let mut multi_pkg = build_full_rpm(FULL_V6_MULTI_SIGNED)?
            .using_config(BuildConfig::v6().compression(CompressionType::Gzip))
            .build_and_sign(&v6_rsa_signer)?;
        multi_pkg.sign(&v6_eddsa_signer)?;
        multi_pkg.write_file(rpm_path(FULL_V6_MULTI_SIGNED))?;

        // Compression variants
        build_full_rpm(FULL_V4_ZSTD)?
            .using_config(BuildConfig::v4().compression(CompressionType::Zstd))
            .build()?
            .write_file(rpm_path(FULL_V4_ZSTD))?;

        build_full_rpm(FULL_V6_GZIP)?
            .using_config(BuildConfig::v6().compression(CompressionType::Gzip))
            .build()?
            .write_file(rpm_path(FULL_V6_GZIP))?;

        build_full_rpm(FULL_V6_ZSTD)?
            .using_config(BuildConfig::v6().compression(CompressionType::Zstd))
            .build()?
            .write_file(rpm_path(FULL_V6_ZSTD))?;

        build_full_rpm(FULL_V6_XZ)?
            .using_config(BuildConfig::v6().compression(CompressionType::Xz))
            .build()?
            .write_file(rpm_path(FULL_V6_XZ))?;

        build_full_rpm(FULL_V6_UNCOMPRESSED)?
            .using_config(BuildConfig::v6().compression(CompressionType::None))
            .build()?
            .write_file(rpm_path(FULL_V6_UNCOMPRESSED))?;

        run_compat_tests(
            "install_rpms",
            &[
                // Empty unsigned
                TestPackage {
                    label: EMPTY_V4_UNSIGNED,
                    required: None,
                    verify_signature: false,
                    asset_path: None,
                },
                TestPackage {
                    label: EMPTY_V6_UNSIGNED,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: false,
                    asset_path: None,
                },
                // Empty signed
                TestPackage {
                    label: EMPTY_V4_SIGNED_RSA,
                    required: Some((Algorithm::Rsa, RpmFormat::V4)),
                    verify_signature: true,
                    asset_path: None,
                },
                TestPackage {
                    label: EMPTY_V6_SIGNED_RSA,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: None,
                },
                TestPackage {
                    label: EMPTY_V6_SIGNED_EDDSA,
                    required: Some((Algorithm::Eddsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: None,
                },
                // Full unsigned
                TestPackage {
                    label: FULL_V4_UNSIGNED,
                    required: None,
                    verify_signature: false,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_UNSIGNED,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: false,
                    asset_path: None,
                },
                // Full signed
                TestPackage {
                    label: FULL_V4_SIGNED_RSA,
                    required: Some((Algorithm::Rsa, RpmFormat::V4)),
                    verify_signature: true,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_SIGNED_RSA,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_SIGNED_EDDSA,
                    required: Some((Algorithm::Eddsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_MULTI_SIGNED,
                    required: Some((Algorithm::Eddsa, RpmFormat::V6)),
                    verify_signature: true,
                    asset_path: None,
                },
                // Compression variants
                TestPackage {
                    label: FULL_V4_ZSTD,
                    required: None,
                    verify_signature: false,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_GZIP,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: false,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_ZSTD,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: false,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_XZ,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: false,
                    asset_path: None,
                },
                TestPackage {
                    label: FULL_V6_UNCOMPRESSED,
                    required: Some((Algorithm::Rsa, RpmFormat::V6)),
                    verify_signature: false,
                    asset_path: None,
                },
            ],
        )?;

        Ok(())
    }
}

/// Run a shell command inside a podman container with the test assets and output directories mounted.
///
/// Installs signing tooling, imports test keys, then executes `cmd`. The `label` is printed
/// in a banner to identify which test and image are running in the logs.
fn podman_container_launcher(
    label: &str,
    cmd: &str,
    image: &str,
    mut mappings: Vec<String>,
) -> std::io::Result<()> {
    // partially following: https://access.redhat.com/articles/3359321
    let setup = r#"
set -e

# Common defaults for package management
REPOS="--disablerepo=* --enablerepo=fedora"
PACKAGES="rpm-sign gpg sequoia-sq"

# Mirrorlist no longer supported on centos, disable
if grep -Eq "ID=.*(centos|almalinux)" /etc/os-release; then
    mirrorlist_repos=$(grep -l mirrorlist.centos.org /etc/yum.repos.d/* || true)
    if [ -n "$mirrorlist_repos" ]; then
        sed -i s/mirror.centos.org/vault.centos.org/g $mirrorlist_repos
        sed -i s/^#.*baseurl=http/baseurl=http/g $mirrorlist_repos
        sed -i s/^mirrorlist=http/#mirrorlist=http/g $mirrorlist_repos
    fi

    REPOS="--disablerepo=* --enablerepo=base* --enablerepo=appstream*"
    PACKAGES="rpm-sign gpg"
    # sequoia-sq is only available on centos stream 10+
    if grep -q 'VERSION_ID="10' /etc/os-release; then
        PACKAGES="$PACKAGES sequoia-sq"
    fi
fi

echo "\### install tooling for signing"

dnf install ${REPOS} -y ${PACKAGES}

pushd assets/
sh import_keys.sh
popd

gpg --keyid-format long --list-secret-keys
gpg --keyid-format long --list-public-keys

set -x

echo "\### Prelude over, executing user-provided command"
"#;

    let script = format!("{setup}\n{cmd}\n");

    // Write script to a uniquely-named temp file and mount it into the container
    let script_dir = Path::new(common::CARGO_OUT_DIR).join("test-scripts");
    let _ = std::fs::create_dir(&script_dir);
    let cache_name = image.replace(['/', ':'], "_");
    let script_path = script_dir.join(format!("{label}_{cache_name}.sh"));
    std::fs::write(&script_path, &script)?;

    let out = format!("{}:/out", common::CARGO_OUT_DIR);
    let assets = format!("{}/tests/assets:/assets:ro", common::CARGO_MANIFEST_DIR);
    let script_mount = format!("{}:/run.sh:ro", script_path.display());
    mappings.extend(vec![out, assets, script_mount]);

    let mut args = mappings.iter().fold(
        vec!["run", "--rm", "--security-opt", "label=disable"],
        |mut acc, mapping| {
            acc.extend(vec!["-v", mapping]);
            acc
        },
    );
    args.extend(vec![image, "sh", "/run.sh"]);

    println!("\n========== {label} [{image}] ==========");

    let output = std::process::Command::new("podman")
        .args(dbg!(args))
        .output()?;

    // Print via println!/eprintln! so the test harness captures it
    // and only displays on failure (or with --nocapture).
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stdout.is_empty() {
        println!("{stdout}");
    }
    if !stderr.is_empty() {
        eprintln!("{stderr}");
    }

    assert!(
        output.status.success(),
        "Container exited with status: {}",
        output.status
    );

    println!("Container execution ended.");
    Ok(())
}
