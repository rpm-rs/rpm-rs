# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

## Misc

- CI now includes an ARM64 runner for Linux, and uploads ARM64 (Aarch64) packages to PyPI.

## 0.24.0

## Added

- `PackageMetadata::get_evr()`

## Removed

- Removed the `Nevra` and `Evr` structs for EVR/NEVRA parsing & sorting. These have been moved to a separate `rpm-version` crate.

## 0.23.5

### Added

- Added `PackageMetadata.verify_signature()` and `PackageMetadata.check_signatures()` to the Python API.
- Added `PackageMetadata.header_bytes()`, `PackageMetadata.check_digests()`, and `PackageMetadata.verify_digests()` to the Python API.
- Added `PackageMetadata.verify_script()`, `PackageMetadata.triggers()`, `PackageMetadata.file_triggers()`, and `PackageMetadata.trans_file_triggers()` to the Python API.
- Added `PackageBuilder` trigger methods: `trigger_in()`, `trigger_un()`, `trigger_postun()`, `trigger_prein()`, `file_trigger_in()`, `file_trigger_un()`, `file_trigger_postun()`, `trans_file_trigger_in()`, `trans_file_trigger_un()`, `trans_file_trigger_postun()`.
- Added `Trigger` and `TriggerCondition` types to the Python API.
- Added `DigestReport.has_header_digest()` and `DigestReport.has_payload_digest()` to the Python API.

## 0.23.4

### Added

- Added `signatures()` to `PackageMetadata`, mirroring the Rust API.

## 0.23.3

### Changed

- Python API accepts "path-like objects" (str, bytes, pathlib.Path) instead of just strings.

## 0.23.2

### Added

- Added `SignatureVersion` enum to the Python bindings with `V4` and `V6` variants.
- Added `SignatureInfo.version` property to the Python bindings, returning a `SignatureVersion` value. Raises `ValueError` for unrecognized versions.

## 0.23.1

### Changed

- Made the Python bindings "abi3" compatible, such that the built packages do not need to be rebuilt for each version of Python.

## 0.23.0

### Added

- Added a new Python API - this package lives on PyPI at https://pypi.org/project/rpm-rs/
- `Header::entry()` for fetching the an arbitrary tag or u32 (interpreted as a tag) from the header
- Many new examples

### Fixed

- Fixed incorrect file digests when the underlying writer performs short writes (e.g. sockets, pipes, or slow I/O).
- Fixed silent data loss in header index serialization under short writes.

### Changed

- Made an optional `payload` feature so that users who only need metadata parsing functions (no building, no file access or extraction) can avoid compression library dependencies.

### Breaking Changes

- `Package.content` renamed to `Package.payload`
- Made `FileEntry.linkto` an `Option<String>` instead of a bare `String`, to be more similar to other fields such as `digest`.
- Renamed `DigestReport.sha1_header` (etc.) to `DigestReport.header_sha1` (etc.) to match the payload digests.

## 0.22.0

This should (hopefully) be the last majorly API-changing release. The changes should be minor until 1.0.

### Breaking Changes

- `PackageBuilder` is now pass-by-reference instead of pass-by-value, which significantly helps ergonomics in some cases (by avoiding the need to re-assign variables constantly when calling methods on `PackageBuilder` in loops).

## 0.21.0

### Added

- `Package::resign_in_place()` for re-signing an on-disk RPM package without reading or rewriting the payload, consuming the signature header's "reserved space" so that the new header fits in exactly the same byte range, allowing an in-place overwrite. Returns `Error::InsufficientReservedSpace` if the new signature is too large to fit.
- `Package::clear_signatures_in_place()` for removing all signatures from an on-disk RPM package without reading or rewriting the payload. The space previously occupied by signatures is converted to reserved space, preserving the ability to later add signatures in-place.
- Remote signing support: `PackageMetadata::header_bytes()` extracts the signable header bytes, `Package::apply_signature()` applies a pre-computed OpenPGP signature to an in-memory package, and `Package::apply_signature_in_place()` applies one to an on-disk package without reading the payload. This enables workflows where signing happens on a remote system.
- `BasicKeySigner` (renamed from `HsmSigner`) — adapter that bridges any `pgp::SigningKey` implementation to the rpm-rs `Signing` trait. `HsmSigner` remains as a deprecated type alias.
- `Package::check_digests()` returns a `DigestReport` with per-digest verification status (`Verified`, `NotPresent`, or `Mismatch`) for all supported digest types (MD5, SHA-1, SHA-256, SHA3-256 header digests and SHA-256, SHA-512, SHA3-256 payload digests).
- `Package::check_signatures()` returns a `SignatureReport` containing the `DigestReport` plus per-signature results (`SignatureCheckResult`) with full `SignatureInfo` metadata (fingerprint, algorithm, etc.) and any verification error.
- `DigestStatus`, `DigestReport`, `SignatureCheckResult`, and `SignatureReport` types for structured verification results.
- `PackageMetadata::signatures()`, `check_digests()`, `verify_digests()`, `verify_signature()`, and `check_signatures()` have been added to allow verifying header digests and signatures without reading the package payload. Payload digest fields are set to `DigestStatus::NotChecked`.
- `Package::raw_signatures()` and `PackageMetadata::raw_signatures()` have been added to allow access to the signatures without needing the `signature-pgp` feature enabled - users can process the raw signature bytes with their own selection of PGP library.
- `Package::canonical_filename()` returns the standard RPM filename (`NVRA.rpm`, e.g. `foo-1.0.0-1.x86_64.rpm`) without writing the package to disk.
- `BuildConfig::reserved_space()` to configure the amount of reserved space in the signature header for in-place re-signing. Defaults to `Some(4128)`. Set to `None` to omit reserved space for smaller packages.

### Changed

- Verify subkey binding signatures and self-signatures when loading OpenPGP keys. Previously, key flags (e.g. signing capability) were read from binding signatures without verifying them against the primary key, allowing a tampered key to present unauthorized subkeys.
- Signature verification now rejects signatures from keys that lack the signing capability flag, returning `Error::KeyLacksSigningCapability`. Keys with no key flags subpacket are treated as general-purpose per RFC 9580.

### Deprecated

- `HsmSigner` has been renamed to `BasicKeySigner`. The old name remains as a deprecated type alias.

### Removed

- Removed verification of the MD5 header+payload digest (`RPMSIGTAG_MD5`) and the associated dependency on `md5`. MD5 is well and truly obsolete cryptography these days.
- Removed verification of legacy "RPM v3"-style signatures.
This ought to be the last major API-changing release for a long time (maybe ever). `PackageBuilder` is now pass-by-reference instead of pass-by-value, which significantly helps ergonomics in some cases (by avoiding the need to re-assign variables constantly when calling methods on `PackageBuilder` in loops).

### Breaking Changes

- `PackageBuilder` methods now take `&mut self` and return `&mut Self` instead of consuming `self` and returning `Self`. This is an ergonomic improvement in most cases, as it makes it much easier to use builder methods in loops (e.g. when adding files or dependencies from a collection). Code that stores a `PackageBuilder` after chaining methods from a temporary will need to use a `let mut` binding instead.

## 0.20.0

Huge release! Testing has been improved dramatically, as has conformance / similarity against what RPM produces. There are also many breaking changes to be aware of, but they are worthwhile.

### Added

- `PackageBuilder::default_file_attrs()` and `PackageBuilder::default_dir_attrs()` for setting default ownership and permissions, similar to `%defattr` in RPM spec files.
- `Package::signatures()` for fetching RPM header signatures from the package. Does not include legacy header + payload signatures.
- The ability to mark files as `%missingok`
- Support for singing and verifying packages that use OpenPGP v6 signatures.
- Support for signing packages using select subkeys rather than the primary key of the provided key material.
- Signatures now include the `SignersUserID` subpacket when the key material contains a user ID.
- `PackageBuilder::with_dir_entry()` as a shortcut to adding a directory entry on the RPM (doesn't add contents).
- `PackageBuilder::with_dir()` adds a directory and recursively adds all files found in that directory to the RPM. Adding a file individually (e.g. to set different permissions / options on it) will still work - files added individually will take precedence over files added using `with_dir()`.
- `PackageBuilder::order_with_requires()` for specifying ordering hints during package installation/upgrade without adding actual dependencies (similar to `OrderWithRequires` in spec files).
- `BuildConfig::source_date()` for setting a fixed timestamp for reproducible builds.
- `Signer::load_from_asc_file()` and `Verifier::load_from_asc_file()` helpers, to streamline building `Signer` and `Verifier`.
- `Signer` and `Verifier` now support loading keyring files containing multiple OpenPGP certificates.
- `Verifier::with_key()` allows selecting a specific certificate by fingerprint from a loaded keyring.
- ML-DSA package signatures can now be created and verified. Note that the IETF standard on OpenPGP support for post-quantum cryptography is not yet final, so producing packages with such signatures is not yet recommended - nonetheless, PQC-signed RPMs are "in the wild" already.
- `Verifier` can now load multiple keys independently - see "Breaking Changes".
- `Package::write_to()` writes a package to a file or directory. If given a directory, auto-generates the filename from package NEVRA.
- `PackageMetadata::get_verify_script()` getter for the `%verifyscript` scriptlet.
- `PackageMetadata::get_triggers()`, `get_file_triggers()`, and `get_trans_file_triggers()` getters for reading trigger entries from parsed packages.
- `Trigger` and `TriggerCondition` public types for representing parsed trigger data.
- `Dependency::script_verify()` constructor for `%verify` scriptlet interpreter dependencies.
- `PackageBuilder::verify_script()` for setting the `%verifyscript` scriptlet.
- `PackageBuilder` trigger methods: `trigger_in()`, `trigger_un()`, `trigger_postun()`, `trigger_prein()`, `file_trigger_in()`, `file_trigger_un()`, `file_trigger_postun()`, `trans_file_trigger_in()`, `trans_file_trigger_un()`, `trans_file_trigger_postun()`.

### Fixed

- Added validation to reject control characters in inputs to `PackageBuilder`.
- Added validation to match RPM's treatment of characters allowed or disallowed in package names.
- Improved handling of file paths (normalization) to prevent duplicates and behave more like the original `rpm`.
- Improved how file digests are created in built packages to behave more like the original `rpm`.
- `PackageBuilder::with_file_contents()` was not respecting `source_date`.
- A number of issues / discrepancies in package payload writing.
- A number of issues / discrepancies in the treatment of ghost files.
- `FileVerifyFlags::default()` now correctly sets all 32 bits (0xffffffff) to match RPM's behavior, including reserved bits.
- Package dependency lists are now sorted alphabetically by name to match RPM's ordering.
- v6 packages now correctly include `RPMTAG_SOURCENEVR` and exclude the v4-only `RPMTAG_PAYLOADSHA256ALGO` tag.
- Auto-generated provides now match RPM's behavior.
  - `NAME(ISA)` provides/requires now use ISA format (`x86-64` instead of `x86_64`)
  - `NAME(ISA)` provides/requires are omitted for `noarch`, version uses full EVR format (`[epoch:]version-release`)
  - `config(NAME)` provides/requires are auto-generated when the package contains `%config` files.
- Built packages now include reserved space in the signature header like `rpm` does.
- `Package::verify_signatures()` will now succeed if any signature validation succeeds (if the package has more than one) against `Verifier`.
- `Package::sign()` and `Package::sign_with_timestamps()` now append to `RPMSIGTAG_OPENPGPSIGNATURES` instead of replacing the signature header.
- `Package::sign()`, `Package::sign_with_timestamps()`, and `Package::clear_signatures()` now preserve file IMA signatures.
- `PackageBuilder::verify_script()` was accepted by `PackageBuilder` but never added into the built package.
- `Scriptlet` "prog" tags are now written as a String type for a single provided argument, matching RPM - previously they were always written as STRING_ARRAY.
- Reading scriptlet "prog" tags now handles both STRING and STRING_ARRAY types, matching RPM which writes STRING for single-argument interpreters (the common case).

### Changed

- Bump `pgp` to `0.19.0`
- The `signature-pgp` feature now depends on `getrandom` in addition to `pgp` and `chrono`.
- `Signer::load_from_asc` now auto-selects the first subkey with the signing capability flag, rather than always using the primary key. This is the correct behavior for v6 keys where the primary key is certification-only.
- Packages that declare `RPMTAG_ENCODING = "utf-8"` will be validated that their strings are valid UTF-8 (lazily, on field access).
- Improved performance and memory overhead of package header parsing.
  - As a low-level detail, the data field on `IndexEntry` will no longer be eagerly filled with data from the package header. Only in cases where the data needs to be transformed before being presented will this happen, otherwise data is lazily parsed from the `store` section of the header.

### Breaking Changes

- `Signer` is no longer generic over a key type. Code using `Signer<SecretKey>` should use `Signer` instead or else use `HsmSigner<SecretKey>` which exposes a similar API to the original `Signer<SecretKey>` for users who were using custom `SecretKey` implementations with hardware security modules.
- `Signer::new()` now takes a `SecretKey` directly (no change in practice, but the type signature changed).
- `Signer` fields are no longer public; use the provided constructor methods instead.
- Renamed `Verifier::load_from_asc`, `load_from_asc_file`, `load_from_asc_bytes` to `from_asc`, `from_asc_file`, `from_asc_bytes`. The `load_from_*` names now refer to new methods that take `&mut self` and append key material to an existing `Verifier`.
- Renamed `Signer::load_from_asc`, `load_from_asc_file`, `load_from_asc_bytes` to `from_asc`, `from_asc_file`, `from_asc_bytes`.
- Removed `AlgorithmType` enum and the `algorithm()` method from the `Signing` and `Verifying` traits. This type was unused — the signature tag routing is determined from the signature packet itself.
- Refactored the `FileOptions` functions. Use `FileOptions::new()`, `FileOptions::dir()`, `FileOptions::symlink()`, `FileOptions::ghost()` for a regular file, directory, symbolic link, or "ghost" file, respectively.
- Renamed file attribute methods on `FileOptionsBuilder` to drop the `is_` prefix:
  `is_config()` → `config()`, `is_license()` → `license()`, `is_readme()` → `readme()` (deprecated).
  `is_config_noreplace()` is replaced by chaining `config().noreplace()`.
  `missingok()` is now a standalone method (it is an independent RPM attribute, not
  just a sub-attribute of `%config`). New methods: `doc()`, `artifact()`, `noreplace()`.
- Removed `Package::signature_key_ids()` - `Package::signatures()` is a more useful API.
- Moved `source_date()` from `PackageBuilder` to `BuildConfig`.

## 0.19.0

### Changed

- Peak memory should be reduced when building packages as files are now read lazily when being added to the package archive.
- Reduce memory by read file content to writer straight from the archive instead of reading each file entirely into memory before writing them when extract package.
- Bump `pgp` to `0.18.0`

### Breaking Changes

- Bump MSRV to 1.88

## 0.18.4

### Added

- Built "v6" packages will set the `RPMFORMAT` tag
- Built "v6" packages will set the `PAYLOADSIZE` and `PAYLOADSIZEALT` tags

### Fixed

- The "v6" `BuildConfig` options were incorrectly failing to use v6 defaults

## 0.18.3

### Fixed

- Packages built with the RPMv4 configuration now populate payload length tags in the signature header. Newly built RPMs will have this set automatically.
  - If editing a pre-built RPM (e.g., for signing) the tag will be preserved if already present.
  - RPMv4 requires the presence of this tag.

### Changed

- Bump `pgp` to `0.17.0`

## 0.18.2

### Changed

- Made the fields of `FileDigest` public

## 0.18.1

### Fixed

- Only set verbatim permissions on unix allowing the crate to build on Windows again.

## 0.18.0

### Added

- Added support for multiple signatures on a package as supported by upstream RPM.
- RPMs that internally use the stripped-cpio format for the archive (v6 RPMs, or older ones with a file
  larger than 4gb) are now supported.
- Added support for Sha3 checksums in headers and payloads - includes the addition of these checksums to
  newly-built packages.
- Added support for Sha512 checksums for payload verification, including addition to new packages.
- Can now use `PackageBuilder::using_config()` to provide a configuration that may be common across many
  package builds.
- `PackageMetadata::get_nevra()`, which is useful for sorting the packages or generating NEVRA strings.

### Fixed

- RPM packages that use large files (>4gb) now correctly declare rpmlib() dependency and use the correct
  archive format.
- RPM "NEVRA" parsing was incorrect in cases where the package name included hyphen ('-') characters.

### Changed

- Internally vendored and modified Jonathan Creekmore's `cpio` dependency, as RPM doesn't use vanilla CPIO.
  See [#108](https://github.com/rpm-rs/rpm/issues/108) or the notes in `src/payload.rs`.
- Switched the `flate2` and `bzip2` dependencies to use native Rust implementations of the underlying compression.
- Added `PackageBuilder::with_file_contents()` for inserting binary content directly into packages instead of requiring on-disk files.
- Bump `pgp` to `0.16.0`
- Bump `bzip2` to `0.6.0`

### Breaking Changes

- Moved `PackageBuilder::compression()` functionality to the new build config via `BuildConfig::compression()`.

## 0.17.0

### Added

- Added support for ecdsa signatures
- Added `Package::files()` for iterating over the files of an RPM package (metadata & contents).
- Added `Package::extract()` for extracting the archive contents of an RPM package to a directory on disk.
- Added `Package::clear_signatures()` for removing signatures from an existing package.

### Changed

- Replaced unmaintained `xz2` dependency with the maintained `liblzma` fork

### Fixed

- Resolved an issue where package signatures produced by this library were not able to be verified on older
  versions of RPM such as the one used on EL8.

### Breaking Changes

- Minimum supported Rust version updated to 1.85 (Edition 2024)

## 0.16.0

### Added

- Added `zstdmt` feature which sets zstd compression to use all available cores.
- Added feature flags for every compression algorithm to support disabling unused ones.
- Added support for signing with a key held in an HSM

### Changed

- Bump `pgp` to 0.14.0

### Breaking Changes

- Changed default compression scheme from Gzip to Zstd.
- Removed bzip2 from the compression options enabled by default.
- Minimum supported Rust version updated to 1.75

## 0.15.1

### Changed

- The `Header::parse_header` function gained a speed up related to parsing of the binary headers.

## 0.15.0

### Breaking Changes

- `FileVerifyFlags` member names changed to strip the `VERIFY_` prefix.
- Minimum supported Rust version updated to 1.74

### Added

- `FileOptions::verify()`
- Added `Evr` and `Nevra` structs and `rpm_evr_compare` function for comparing RPM versions.

### Changed

- As RHEL 7 (thus, CentOS 7 and other derivatives) goes out-of-support on June 30, 2024, support for legacy
  features used by distros of that era are being phased out.
  - "RPM v3" signatures (signatures covering both header and payload) will no longer be added when building
    or signing an RPM with rpm-rs.
  - Legacy checksum types ("sha1" and "md5") will not be added when building an RPM with rpm-rs.
  - As a result of these changes, packages built by rpm-rs will still work on EL7-era distros, but rpm on those
    platforms won't be as capable of verifying them.

### Deprecated

- In a (near) future version of rpm-rs, support for EL7-era distros may be removed entirely.

## 0.14.0

### Breaking Changes

- Minimum supported Rust version updated to 1.71
- `Dependency::rpmlib()` now inserts the `rpmlib()` portion automatically, only the feature name itself should
  be provided in the string passed as the name argument.
- `FileOptions::is_no_replace()` is now `FileOptions::is_config_noreplace()` to reflect the fact that the noreplace
  flag is only applicable to config files, and have more similar usage relative to `%config(noreplace)`

### Added

- `Dependency::script_pre()`, `Dependency::script_post()`, `Dependency::script_preun()`, `Dependency::script_postun()`
- `Dependency::config()`, `Dependency::user()`, `Dependency::group()`
- `PackageBuilder::verify_script()`
- `PackageBuilder::group()` and `PackageBuilder::packager()`
- Added support for the automatic user/group creation feature in rpm 4.19

### Changed

- Improved documentation
- `PackageMetadata::write` is now public

### Fixed

- Using file capabilities now adds the appropriate rpmlib() dependency

## 0.13.1

### Added

- Support bzip2 compression type (`CompressionType::Bzip2`).
- Added `pre_trans_script`, `post_trans_script`, `pre_untrans_script`, and `post_untrans_script` methods to `PackageBuilder`. This corresponds with the `%pretrans`, `%postrans`, `%preuntrans`, and `%postuntrans` scriptlets.
- Added new `Scriptlet` type which enabled configuring scriptlet flags and interpreter settings
  - Example Usage:

  ```rs
  package_builder
    .pre_install_script(
      Scriptlet::new("echo hello world")
        .flags(ScriptletFlags::EXPAND)
        .prog(vec!["/bin/blah/bash", "-c"])
    )
  ```

- Added `get_*_script` methods to `PackageMetadata` for finding scriptlets
  - Example Usage:

  ```rs
  package.metadata.get_pre_install_script()?;
  ```

### Changed

- `Error` now implements `Send + Sync` (therefore, `Result<Package, Error>` now implements `Send + Sync`).
- Add mod `rpm::filecaps` instead of capctl crate - this fixes Windows builds

## 0.13.0

### Breaking Changes

- Bumped MSRV to 1.67

### Removed

- Removed `Package::get_file_checksums` and `Package::get_file_ima_signatures` functions, the same information is now retrievable using `Package::get_file_entries`.

### Added

- Support for symbolic link in file mode.
- Make file type const `REGULAR_FILE_TYPE` `DIR_FILE_TYPE` `SYMBOLIC_LINK_FILE_TYPE` public, because `FileMode::file_type` is public, sometimes we need this const to determine file type.
- Method `PackageBuilder::new` now takes a `summary` as last parameter, instead
  of a `description`. A new method `PackageBuilder::description` can be used to
  set a detailed description for a package; if not set, the description defaults
  to the `summary`.
- Add method `with_key_passphrase` to `signature::pgp::Signer`, to provide the
  passphrase when the PGP secret key is passphrase-protected.
- Add method `is_no_replace` to `FileOptionsBuilder`, used to set the
  `%config(noreplace)` flag on a file.
- Added the `FileEntry.linkto` field that is a target of a symbolic link.
- Function `Package::get_file_entries` returns an empty vector for an RPM package without any files.
- `FileEntry` structs returned by (`Package::get_file_entries`) now include IMA signature information as well as digests for file entries.

## 0.12.1

### Added

- Support for setting file capabilities via the RPMTAGS_FILECAPS header.
- `PackageMetadata::get_file_entries` method can get capability headers for each file.

## 0.12.0

### Breaking Changes

- Removed `RPM` prefix from type names, e.g. `RPMPackage` is renamed to `Package`,
  `RPMBuilder` is renamed to `PackageBuilder`, etc. Many other type names are adjusted
  likewise.
- The `PackageBuilder::build_time` method is removed. Package build time is now
  included by default and can be clamped using the `PackageBuilder::source_date` method.
- Several of the signer and verifier trait APIs were changed

Note: The pace of breaking changes ought to slow down significantly from this point forwards.
Most of the substantial changes which needed to be made have now been made. Thank you for your
patience.

### Added

- `PackageBuilder::source_date` method for clamping modification time of files,
  build time of the package, and signature timestamp. This functionality is required for
  reproducible generation of packages.
- `Package::sign_with_timestamp` method for signing a package while using a specific
  timestamp. This is needed to reproducibly sign packages.
- `PackageMetadata::signature_key_id` method for getting the signing key ID (superset
  of the fingerprint) of the key used to sign a package as a hex-encoded string.
  Key fingerprints can be easily extracted from this value.
- The "rpmversion" tag is now populated so that packages know which library (and version)
  they were built with.
- Support for signing and verification with EdDSA signatures

### Changed

- Build time metadata is now included in the built package by default
- The algorithm type is no longer baked into the Signing and Verifying APIs as it is unnecessary.

### Fixed

- CentOS 7 support by using long sizes only for packages bigger than 4 GiB.
- Avoid a longstanding bug in `rpm --rebuilddb` by adding a package build time by default.
- Packages generated by `RPMBuilder` have the RPMTAG_SOURCERPM to be more compatibly recognized as RPM binary packages.

## 0.11.0

### Breaking Changes

- `CompressionType::None` is now returned instead of an error when calling `get_compression()` on
  a package with an uncompressed payload.
- Moved many constants to the bitflag-like types `DependencyFlags`, `FileVerifyFlags` and `FileFlags`
- Changed the `FileEntry.category` field to `FileEntry.flags` and changed its type from an
  enum to a bitflag-like type.
- Renamed `FileDigestAlgorithm` to `DigestAlgorithm`, renamed `UnsupportedFileDigestAlgorithm`
  to `UnsupportedDigestAlgorithm`

### Added

- The compression level to be used during package building is now configurable by passing
  `CompressionWithLevel` to `RPMBuilder::compression`. Compatibility with passing
  `CompressionType` is retained - the default value will be used in that case.
- The default compression for building a package, if the compression is not overridden using
  the above method, is now `Gzip` rather than `None`. This is chosen to keep package
  sizes reasonable while maintaining maximum compatibility and minimizing computational cost.
- Exposed `RPMPackageMetadata::parse()` and `RPMPackageMetadata::open()` so that it is
  possible to read only package metadata without loading the payload into memory. This saves
  time and memory over reading the entire file.
- Exposed the fields on the `Dependency` and `RPMFileEntry` structs.

### Removed

- Removed async support. This crate is poorly suited for use in an async runtime as IO is intermixed
  with computationally expensive compression/decompression, digest and signature verification which
  is likely to take on the order of seconds in some cases. This is "computational blocking". As an
  alternative, if you need to perform actions with this crate within an async runtime, use the
  `spawn_blocking` function on your executor of choice e.g.
  <https://docs.rs/tokio/latest/tokio/index.html#cpu-bound-tasks-and-blocking-code>

### Changed

- `flate2` crate is now used in place of `libflate`. `flate2` is faster in both compression
  and decompression and has better ratios, and includes features which `libflate` does not
  such as configurable compression levels.

### Fixed

- Made parsing more robust in the face of unknown or unexpected tags. This will prevent new
  packages from causing the program to crash if rpm-rs does not yet have a constant defined.
  Also, RPMs in the wild are "messy" and it is sadly commonplace for tags to present in the
  wrong header.

## 0.10.0

### Added

- Added a `RPMPackage::open()` helper for working with files
- Set RPMTAG_ENCODING to "utf-8" on all built RPMs
- Added `$pkg.metadata.get_changelog_entries()`
- Added the following functions to `RPMBuilder` to support weak dependencies: `recommends()`,
  `suggests()`, `enhances()` and `supplements()`
- Added the following additional functions to `RPMBuilder`: `cookie()`, `build_host()`
- Added the following functions to `$pkg.metadata` for retrieval of various kinds of RPM
  dependencies: `get_provides()`, `get_requires()`, `get_obsoletes()`, `get_conflicts()`,
  `get_recommends()`, `get_suggests()`, `get_enhances()`, `get_supplements()`
- Added the following functions to `$pkg.metadata` for retrieval of metadata: `get_group()`,
  `get_description()`, `get_summary()`
- Added the following functions to `$pkg.metadata.header` to enable the reading of arbitrary
  tags in the header: `get_entry_data_as_binary()`, `get_entry_data_as_string()`,
  `get_entry_data_as_u16_array()`, `get_entry_data_as_u32()`, `get_entry_data_as_u32_array()`,
  `get_entry_data_as_u64()`, `get_entry_data_as_u64_array()`, `get_entry_data_as_string_array()`,
  `get_entry_data_as_i18n_string()`
- Added `verify_signature()` and `verify_digests()` to `RPMPackage` to enable checking the integrity
  and provenance of packages.
- Added `get_package_segment_boundaries()` to `RPMPackage` to enable reading the raw bytes of the
  different components (header, payload, etc.) from an on-disk package.
- Added `CompressionType`.
- Added support for `xz` compression type
- Write a sha256 header digest to the signature header as the more modern equivalent of the sha1
  header digest

### Fixed

- Added `rpmlib()` dependencies to built packages as appropriate
- Fixed an issue where `get_file_paths()` and `get_file_entries()` would fail if the package
  did not have any files associated.
- Ensured that digests are always added to built RPMs. Previously they would not be included unless
  the "signature-meta" (or "signature-pgp") features were enabled.
- Added `PAYLOADDIGEST`, `PAYLOADDIGESTALT`, and `PAYLOADDIGESTALGO` tags to built packages.
- To facilitate reproducible builds, stop writing `build_time` to the package by default.
  Users can configure it with `RPMBuilder::build_time()`.
- Improved support for packages >4gb
- Always write tags in sorted order

### Breaking Changes

- Bump MSRV to 1.65.0
- Removed async support from default features
- Removed `Lead` from the public API. `Lead` is long-deprecated and shouldn't be relied on.
  Restricted the data we write to `Lead` to the bare minimum required for compatibility.
- Removed `$pkg.metadata.get_payload_format()`. It is still possible to fetch manually, but
  practically speaking it is not meaningful. rpmbuild has written a misleading value here for
  10 years.
- Added support for parsing `CompressionType` string in `RPMPackageMetadata`.
- Changed signature for `RPMBuilder::compression`.

## 0.9.0

### Breaking Changes

- Bump MSRV to 1.60.0
- Changed a couple of APIs to use unsigned integers instead of signed integers where appropriate
- Moved pre-defined helpers for common package metadata (such as name, version, file lists, etc.)
  from `$pkg.metadata.header` to `$pkg.metadata`
- Removed the `$pkg.metadata.get_file_ima_signature_length()` function

### Added

- Forked from `rpm-rs` at version 0.8.1
- Relicensed as MIT + Apache 2.0 after obtaining consent from all contributors
- Added additional helper methods for retrieving commonly used metadata
- Add vendor, url and vcs metadata optional fields to RPMBuilder

### Fixed

- Updated dependencies to latest versions
- Fix up most issues when compiling with --no-default-features.
- Fixed an issue with improper package signing

[Unreleased]: https://github.com/rpm-rs/rpm-rs/compare/vTODO...HEAD
