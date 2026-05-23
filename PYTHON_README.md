[![PyPI](https://img.shields.io/pypi/v/rpm-rs.svg)](https://pypi.org/project/rpm-rs/)

## RPM-RS (Python)

Python bindings for [rpm-rs](https://github.com/rpm-rs/rpm) — a pure Rust library for working with RPM files.

This is **not** a replacement for the original `rpm` library / tools, and is **not** an official effort by Red Hat or the rpm-software-management developers.

### Goals

- Easy to use API
- Independence from Spec files. Purely programmatic interface for Packaging.
- Pure Rust core to make it easy to use in larger projects, independent from libraries provided by the host OS
- Compatibility from Enterprise Linux 8 (RHEL, Alma, Rocky, CentOS Stream) to Fedora

### Non Goals

RPM has a lot of features. We do not want to re-implement all of them.

- This library is for working with RPM packages on their own - installing RPMs and manipulating the system rpmdb is not supported
- This library does not build software like rpmbuild - it is meant for finished artifacts that need to be packaged as RPM
- Obsolete cryptography (md5, DSA) not supported
- Legacy RPMv3 signatures not supported (e.g. `SIGPGP`, `SIGGPG`)

### Major Features

- [x] RPM Creation
- [x] RPM Signing and Signature Verification
- [x] RPM signing using an external signing service or Hardware Signing Module (HSM)
- [x] High-level APIs for parsing RPM files, reading RPM metadata, and extracting payloads

### Installing

```
pip install rpm-rs
```

### Examples

-------------------

### Read package and access metadata

#### Check basic metadata

```python
from rpm_rs import Package

pkg = Package.open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")

name = pkg.metadata.name
version = pkg.metadata.version
release = pkg.metadata.release
arch = pkg.metadata.arch

print(f"{name}-{version}-{release}.{arch}")

for entry in pkg.metadata.changelog_entries():
    print(f"{entry.name}\n{entry.description}\n")

# `PackageMetadata` provides direct access to Package metadata without reading the payload
# as `Package` does. If you don't need the payload, it is more convenient and efficient to use.

from rpm_rs import PackageMetadata
metadata = PackageMetadata.open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")

assert metadata.name == pkg.metadata.name
assert metadata.version = pkg.metadata.version

for entry in metadata.changelog_entries():
    print(f"{entry.name}\n{entry.description}\n")
```

#### Query dependencies

```python
from rpm_rs import Package

pkg = Package.open("tests/assets/RPMS/v6/rpm-rich-deps-1.0-1.noarch.rpm")

for dep in pkg.metadata.requires():
    print(dep)
    # e.g. "glibc >= 2.17", "bash", "rpm-libs = 4.14.3-1.el8"

# Other dependency types: provides(), conflicts(), obsoletes(),
# recommends(), suggests(), enhances(), supplements()
```

#### Inspect package signatures

```python
from rpm_rs import Package

pkg = Package.open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")

for sig in pkg.signatures():
    print(f"Algorithm: {sig.algorithm}")
    print(f"Hash algorithm: {sig.hash_algorithm}")
    if sig.fingerprint:
        print(f"Fingerprint: {sig.fingerprint}")
    if sig.key_id:
        print(f"Key ID: {sig.key_id}")
    if sig.version == SignatureVersion.V6:
        print("This is a v6 signature")

# Raw OpenPGP signature packets are also available
for raw_sig in pkg.raw_signatures():
    print(f"Signature packet: {len(raw_sig)} bytes")
```

#### List and read file contents

```python
from rpm_rs import Package

pkg = Package.open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")

# List file metadata without reading the payload
for entry in pkg.metadata.file_entries():
    print(f"{entry.path} ({entry.size} bytes, {oct(entry.mode.permissions)})")

# Read file contents (decompresses the payload)
for f in pkg.files():
    print(f"{f.metadata.path}: {len(f.content)} bytes")
```

#### Extract package contents to disk

Extract all files, directories, and symlinks from the package payload into a target directory —
files are written relative to the target directory (not installed to their absolute paths).

```python
from rpm_rs import Package

# The directory must not already exist and its parent must exist.
pkg = Package.open("tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")
pkg.extract("./extracted-pkg")
# Creates ./extracted-pkg/ with the package's file tree inside it
```

### Verify signatures

#### Verify using a keyring with multiple certificates

```python
from rpm_rs import Package, Verifier

# Keyring files containing multiple OpenPGP certificates are supported.
# The verifier will try each certificate until it finds one that matches.
verifier = Verifier.from_file("./tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.asc")

pkg = Package.open("./tests/assets/RPMS/v4/signed/rpm-basic-with-rsa4096-2.3.4-5.el9.noarch.rpm")
pkg.verify_signature(verifier)

# You can also narrow down to a specific certificate by fingerprint:
verifier = Verifier.from_file("./tests/assets/signing_keys/v4/rpm-testkey-v4-keyring.asc")
verifier = verifier.with_key("d996aedc0d64d1e621b95ad2e964f9fb30d073b5")
```

#### Check individual signatures and digests

```python
from rpm_rs import Package, Verifier

pkg = Package.open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")
verifier = Verifier.from_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc")

report = pkg.check_signatures(verifier)

# Check overall pass/fail
assert report.is_ok()

# Or inspect individual digest results
if report.digests.header_sha256.is_verified():
    print("SHA-256 header digest: OK")

status = report.digests.header_sha3_256
if status.is_verified():
    print("SHA3-256 header digest: OK")
elif status.is_not_present():
    print("SHA3-256 header digest: not present")
elif status.is_mismatch():
    print(f"SHA3-256 header digest: MISMATCH (expected {status.expected}, got {status.actual})")

# Inspect each signature with its metadata
for sig in report.signatures:
    key_ref = sig.info.fingerprint or sig.info.key_id or "unknown"
    if sig.is_verified():
        print(f"Signature {key_ref}: OK")
    else:
        print(f"Signature {key_ref}: FAILED: {sig.error}")
```

### Sign packages

#### Sign an existing package and verify package signature

```python
from rpm_rs import Package, Signer, Verifier

signer = Signer.from_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.secret")
verifier = Verifier.from_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-rsa4k.asc")

pkg = Package.open("./tests/assets/RPMS/v6/signed/rpm-basic-with-rsa4k-2.3.4-5.el9.noarch.rpm")
pkg.sign(signer)
pkg.write_to("./tmp/with_signature.rpm")

pkg = Package.open("./tmp/with_signature.rpm")
pkg.verify_signature(verifier)
```

#### Sign with a specific subkey

```python
from rpm_rs import Signer, Package

subkey_fingerprint = "715619ae2365d909eb991ff97a509cd76a0bac92f0e17c1c2525812852cedfc5"

signer = Signer.from_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret")
signer = signer.with_signing_key(subkey_fingerprint)

pkg = Package.open("./tests/assets/RPMS/v6/rpm-basic-2.3.4-5.el9.noarch.rpm")
pkg.sign(signer)
```

### Remote / HSM signing

For signing with keys that are not directly accessible as local key files
(e.g. HSMs, remote signing services, or cloud KMS), you can split the
signing workflow into extract / sign / apply steps:

```python
from rpm_rs import Package, PackageMetadata, Signer

# Step 1: Extract the header bytes to be signed.
# Only reads the metadata, not the payload.
metadata = PackageMetadata.open("pkg.rpm")
header_bytes = metadata.to_bytes()

# Step 2: Sign the header bytes (this would normally happen on a remote system).
signer = Signer.from_file("signing_key.secret")
signature = signer.sign(header_bytes)

# Step 3: Apply the signature.
# For in-memory packages:
pkg = Package.open("pkg.rpm")
pkg.apply_signature(signature)

# Or apply directly to an on-disk package without loading the payload:
Package.apply_signature_in_place("pkg.rpm", signature)
```

#### In-place signing and clearing of signatures

For large packages, it is often desirable to sign or clear signatures without reading
or rewriting the payload. These methods modify only the signature header on disk, using
the reserved space to keep the file size unchanged:

```python
from rpm_rs import Package, Signer

# Re-sign a package on disk (reads only the metadata, not the payload)
signer = Signer.from_file("signing_key.secret")
Package.resign_in_place("pkg.rpm", signer)

# Remove all signatures, converting their space to reserved space
# so that signatures can be added back later
Package.clear_signatures_in_place("pkg.rpm")

# Re-sign the cleared package — the reserved space from clearing is reused
Package.resign_in_place("pkg.rpm", signer)
```

### Build a new package

```python
from rpm_rs import (
    BuildConfig,
    CompressionType,
    FileOptions,
    Package,
    PackageBuilder,
    Signer,
)

# For reproducible builds, set source_date to the timestamp of the last commit in your VCS
config = BuildConfig(compression=CompressionType.Gzip, source_date=1_600_000_000)
signer = Signer.from_file("./tests/assets/signing_keys/v6/rpm-testkey-v6-ed25519.secret")

builder = PackageBuilder("test", "1.0.0", "MIT", "x86_64", "some awesome package")
builder.using_config(config)

# set default ownership and permissions for files and directories, similar to %defattr
# in an RPM spec file. Pass None for any field to leave it unchanged (like `-` in %defattr).
builder.default_file_attrs(permissions=0o644, user="myuser", group="mygroup")
builder.default_dir_attrs(permissions=0o755, user="myuser", group="mygroup")

# add a file with no special options
# by default, files will be owned by the "root" user and group, and inherit their permissions
# from the on-disk file.
builder.with_file(
    "./tests/assets/SOURCES/multiplication_tables.py",
    FileOptions.new("/usr/bin/awesome"),
)

# you can set permissions, capabilities and other metadata (user, group, etc.) manually
builder.with_file(
    "./tests/assets/SOURCES/example_config.toml",
    FileOptions.new(
        "/etc/awesome/second.toml",
        permissions=0o644,
        caps="cap_sys_admin,cap_net_admin=pe",
        user="hugo",
    ),
)

# Add a file - setting flags on it equivalent to `%config(noreplace)`
builder.with_file(
    "./tests/assets/SOURCES/example_config.toml",
    FileOptions.new("/etc/awesome/config.toml", config=True, noreplace=True),
)

# add a file from in-memory content instead of reading from disk
builder.with_file_contents(
    b"hello world!",
    FileOptions.new("/usr/share/awesome/greeting.txt"),
)

# binary content works too
builder.with_file_contents(
    b"\x00\x01\x02\x03",
    FileOptions.new("/usr/share/awesome/data.bin", permissions=0o600),
)

# symlinks don't require a source file
builder.with_symlink(
    FileOptions.symlink("/usr/bin/awesome_link", "/usr/bin/awesome"),
)

# directories can be created with explicit ownership and permissions
# this does not add any directory contents, just declares a directory
builder.with_dir_entry(
    FileOptions.dir("/var/log/awesome", permissions=0o750),
)

# recursively add all files from a directory on disk, with keyword arguments to
# customize the file options for each entry (e.g. marking all files as documentation)
builder.with_dir("./build/share", "/usr/share/awesome", doc=True)

# ghost files / directories are not included in the package payload, but their metadata
# (ownership, permissions, etc.) is tracked by RPM. This is commonly used for files
# created at runtime (e.g. log files, PID files).
builder.with_ghost(
    FileOptions.ghost("/var/log/awesome/app.log"),
)

builder.pre_install_script("echo preinst")

import socket
builder.build_host(socket.gethostname())

builder.add_changelog_entry(
    "Max Mustermann <max@example.com> - 0.1-29",
    "- was awesome, eh?",
    1681945000,
)
builder.add_changelog_entry(
    "Charlie Yom <test2@example.com> - 0.1-28",
    "- yeah, it was",
    840_000_000,
)

builder.requires("wget")
builder.vendor("corporation or individual")
builder.url("www.github.com/repo")
builder.vcs("git:repo=example_repo:branch=example_branch:sha=example_sha")

pkg = builder.build_and_sign(signer)

# Write to a specific file
pkg.write_to("/tmp/awesome.rpm")

# Or write to a directory with auto-generated filename (`/tmp/awesome-0.1.0-1.x86_64.rpm`)
pkg.write_to("/tmp")
```
