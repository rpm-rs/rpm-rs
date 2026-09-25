"""Tests for Package (full package with payload)."""

import os
import tempfile
from pathlib import Path

from rpm_rs import FileEntry, FileType, Package, PackageMetadata, RpmFile

from conftest import RPM_BASIC, RPM_EMPTY, RPM_FILE_TYPES


class TestOpen:
    def test_open(self):
        pkg = Package.open(RPM_BASIC)
        assert pkg.metadata.name == "rpm-basic"

    def test_open_pathlike(self):
        pkg = Package.open(Path(RPM_BASIC))
        assert pkg.metadata.name == "rpm-basic"

    def test_from_bytes(self):
        with open(RPM_BASIC, "rb") as f:
            data = f.read()
        pkg = Package.from_bytes(data)
        assert pkg.metadata.name == "rpm-basic"


class TestMetadataProperty:
    def test_metadata_type(self):
        pkg = Package.open(RPM_BASIC)
        m = pkg.metadata
        assert isinstance(m, PackageMetadata)
        assert m.name == "rpm-basic"


class TestDigests:
    def test_verify_digests(self):
        pkg = Package.open(RPM_BASIC)
        pkg.verify_digests()

    def test_verify_digests_empty(self):
        pkg = Package.open(RPM_EMPTY)
        pkg.verify_digests()


class TestFiles:
    def test_files_basic(self):
        pkg = Package.open(RPM_BASIC)
        files = pkg.files()
        assert len(files) > 0
        assert all(isinstance(f, RpmFile) for f in files)

    def test_file_metadata_and_content(self):
        pkg = Package.open(RPM_BASIC)
        files = pkg.files()
        for f in files:
            assert isinstance(f.metadata, FileEntry)
            assert isinstance(f.content, (bytes, type(None)))
            assert isinstance(f.has_payload, bool)
            assert f.has_payload is (f.content is not None)

    def test_files_with_types(self):
        pkg = Package.open(RPM_FILE_TYPES)
        files = pkg.files()
        types = {f.metadata.mode.file_type for f in files}
        assert FileType.Regular in types

    def test_empty_package_no_files(self):
        pkg = Package.open(RPM_EMPTY)
        files = pkg.files()
        assert len(files) == 0


class TestExtract:
    def test_extract(self):
        pkg = Package.open(RPM_BASIC)
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = os.path.join(tmpdir, "extracted")
            pkg.extract(dest)
            assert os.path.isdir(dest)


class TestRoundtrip:
    def test_roundtrip_bytes(self):
        pkg = Package.open(RPM_BASIC)
        data = pkg.to_bytes()
        pkg2 = Package.from_bytes(data)
        assert pkg2.metadata.name == pkg.metadata.name
        assert pkg2.metadata.version == pkg.metadata.version

    def test_write_file(self):
        pkg = Package.open(RPM_BASIC)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "output.rpm"
            pkg.write_file(path)
            pkg2 = Package.open(path)
            assert pkg2.metadata.name == pkg.metadata.name

    def test_write_to_directory(self):
        pkg = Package.open(RPM_BASIC)
        with tempfile.TemporaryDirectory() as tmpdir:
            actual_path = pkg.write_to(Path(tmpdir))
            assert os.path.isfile(actual_path)
            assert actual_path.startswith(tmpdir)
            assert actual_path.endswith(".rpm")
            pkg2 = Package.open(actual_path)
            assert pkg2.metadata.name == pkg.metadata.name

    def test_write_to_file(self):
        pkg = Package.open(RPM_BASIC)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "custom-name.rpm")
            actual_path = pkg.write_to(path)
            assert actual_path == path
            assert os.path.isfile(actual_path)
            pkg2 = Package.open(actual_path)
            assert pkg2.metadata.name == pkg.metadata.name


class TestCanonicalFilename:
    def test_canonical_filename(self):
        pkg = Package.open(RPM_BASIC)
        assert pkg.canonical_filename() == "rpm-basic-2.3.4-5.el9.noarch.rpm"
