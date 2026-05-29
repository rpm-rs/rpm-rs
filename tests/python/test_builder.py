"""Smoke tests for PackageBuilder, FileOptions, and BuildConfig."""

import os
import tempfile

from rpm_rs import (
    BuildConfig,
    CompressionType,
    FileFlags,
    FileOptions,
    Package,
    PackageBuilder,
    RpmFormat,
    Signer,
    Verifier,
)

from conftest import ASSETS, PRIVATE_KEY, PUBLIC_KEY

SOURCES = os.path.join(ASSETS, "SOURCES")
EXAMPLE_CONFIG = os.path.join(SOURCES, "example_config.toml")
EXAMPLE_SCRIPT = os.path.join(SOURCES, "multiplication_tables.py")


class TestBasicBuild:
    def test_minimal_package(self):
        b = PackageBuilder("test-pkg", "1.0.0", "MIT", "noarch")
        pkg = b.build()
        m = pkg.metadata
        assert m.name == "test-pkg"
        assert m.version == "1.0.0"
        assert m.license == "MIT"
        assert m.arch == "noarch"

    def test_with_metadata(self):
        b = PackageBuilder("test-pkg", "2.0", "Apache-2.0", "x86_64", "A test package")
        b.description("A longer description of the test package")
        b.release("3.fc40")
        b.epoch(1)
        b.url("https://example.com")
        b.vcs("https://github.com/example/repo")
        b.vendor("Test Vendor")
        b.packager("Test Packager")
        b.build_host("localhost")

        pkg = b.build()
        m = pkg.metadata
        assert m.summary == "A test package"
        assert m.description == "A longer description of the test package"
        assert m.release == "3.fc40"
        assert m.epoch == 1
        assert m.url == "https://example.com"
        assert m.vcs == "https://github.com/example/repo"
        assert m.vendor == "Test Vendor"
        assert m.packager == "Test Packager"
        assert m.build_host == "localhost"


class TestBuildConfig:
    def test_default_config(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.using_config(BuildConfig())
        pkg = b.build()
        assert pkg.metadata.name == "test"

    def test_v4_config(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.using_config(BuildConfig(format=RpmFormat.V4))
        pkg = b.build()
        assert pkg.metadata.name == "test"

    def test_compression(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.using_config(BuildConfig(compression=CompressionType.Gzip))
        pkg = b.build()
        assert pkg.metadata.payload_compressor == "Gzip"

    def test_compression_with_level(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.using_config(
            BuildConfig(compression=CompressionType.Gzip, compression_level=1)
        )
        pkg = b.build()
        assert pkg.metadata.payload_compressor == "Gzip"

    def test_source_date(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.using_config(BuildConfig(source_date=1_600_000_000))
        pkg = b.build()
        assert pkg.metadata.build_time == 1_600_000_000

    def test_reserved_space_custom(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.using_config(BuildConfig(reserved_space=8192))
        pkg = b.build()
        assert pkg.metadata.name == "test"

    def test_reserved_space_disabled(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.using_config(BuildConfig(reserved_space=0))
        pkg = b.build()
        assert pkg.metadata.name == "test"


class TestFiles:
    def test_with_file(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file(EXAMPLE_CONFIG, FileOptions.new("/etc/test.toml"))
        pkg = b.build()
        paths = pkg.metadata.file_paths()
        assert "/etc/test.toml" in paths

    def test_with_file_contents(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(b"hello world", FileOptions.new("/usr/share/test.txt"))
        pkg = b.build()
        paths = pkg.metadata.file_paths()
        assert "/usr/share/test.txt" in paths

    def test_with_file_permissions(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(
            b"#!/bin/sh\necho hello",
            FileOptions.new("/usr/bin/test", permissions=0o755, user="testuser"),
        )
        pkg = b.build()
        entries = pkg.metadata.file_entries()
        entry = [e for e in entries if e.path == "/usr/bin/test"][0]
        assert entry.permissions == 0o755
        assert entry.user == "testuser"

    def test_with_config_file(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(
            b"key=value",
            FileOptions.new("/etc/test.conf", config=True, noreplace=True),
        )
        pkg = b.build()
        entries = pkg.metadata.file_entries()
        entry = [e for e in entries if e.path == "/etc/test.conf"][0]
        # CONFIG | NOREPLACE flags should be set
        assert int(entry.flags) != 0

    def test_with_doc_file(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(
            b"README content",
            FileOptions.new("/usr/share/doc/test/README", doc=True),
        )
        pkg = b.build()
        entries = pkg.metadata.file_entries()
        entry = [e for e in entries if e.path == "/usr/share/doc/test/README"][0]
        assert int(entry.flags) & FileFlags.DOC

    def test_with_license_file(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(
            b"MIT License...",
            FileOptions.new("/usr/share/licenses/test/LICENSE", license=True),
        )
        pkg = b.build()
        entries = pkg.metadata.file_entries()
        entry = [e for e in entries if e.path == "/usr/share/licenses/test/LICENSE"][0]
        assert int(entry.flags) & FileFlags.LICENSE

    def test_with_missingok(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(
            b"optional",
            FileOptions.new("/etc/test.conf", config=True, missingok=True),
        )
        pkg = b.build()
        entries = pkg.metadata.file_entries()
        entry = [e for e in entries if e.path == "/etc/test.conf"][0]
        assert int(entry.flags) & FileFlags.MISSINGOK

    def test_with_artifact(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(
            b"build log",
            FileOptions.new("/usr/share/test/build.log", artifact=True),
        )
        pkg = b.build()
        entries = pkg.metadata.file_entries()
        entry = [e for e in entries if e.path == "/usr/share/test/build.log"][0]
        assert int(entry.flags) & FileFlags.ARTIFACT

    def test_with_caps(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_file_contents(
            b"#!/bin/sh\necho hello",
            FileOptions.new("/usr/bin/test", caps="cap_net_admin=pe"),
        )
        pkg = b.build()
        entries = pkg.metadata.file_entries()
        entry = [e for e in entries if e.path == "/usr/bin/test"][0]
        assert entry.caps == "cap_net_admin=ep"

    def test_with_dir_entry(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_dir_entry(FileOptions.dir("/var/log/test"))
        pkg = b.build()
        paths = pkg.metadata.file_paths()
        assert "/var/log/test" in paths

    def test_with_symlink(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_symlink(FileOptions.symlink("/usr/bin/link", "/usr/bin/target"))
        pkg = b.build()
        paths = pkg.metadata.file_paths()
        assert "/usr/bin/link" in paths

    def test_with_ghost(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.with_ghost(FileOptions.ghost("/var/run/test.pid"))
        pkg = b.build()
        paths = pkg.metadata.file_paths()
        assert "/var/run/test.pid" in paths


class TestDependencies:
    def test_requires(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.requires("bash")
        b.requires("coreutils", "8.0")
        pkg = b.build()
        requires = pkg.metadata.requires()
        names = [r.name for r in requires]
        assert "bash" in names
        assert "coreutils" in names

    def test_provides(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.provides("test-capability", "1.0")
        pkg = b.build()
        provides = pkg.metadata.provides()
        names = [p.name for p in provides]
        assert "test-capability" in names

    def test_conflicts_obsoletes(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.conflicts("old-test")
        b.obsoletes("legacy-test", "0.9")
        pkg = b.build()
        assert any(c.name == "old-test" for c in pkg.metadata.conflicts())
        assert any(o.name == "legacy-test" for o in pkg.metadata.obsoletes())

    def test_weak_deps(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.recommends("optional-dep")
        b.suggests("nice-to-have")
        pkg = b.build()
        assert any(r.name == "optional-dep" for r in pkg.metadata.recommends())
        assert any(s.name == "nice-to-have" for s in pkg.metadata.suggests())


class TestScriptlets:
    def test_pre_install(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.pre_install_script("echo pre")
        pkg = b.build()
        script = pkg.metadata.pre_install_script()
        assert script.script == "echo pre"

    def test_post_install(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.post_install_script("echo post")
        pkg = b.build()
        script = pkg.metadata.post_install_script()
        assert script.script == "echo post"


class TestChangelog:
    def test_changelog(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.add_changelog_entry(
            "Test Author <test@example.com> - 1.0-1",
            "- Initial release",
            1_600_000_000,
        )
        pkg = b.build()
        entries = pkg.metadata.changelog_entries()
        assert len(entries) >= 1
        assert "Test Author" in entries[0].name
        assert "Initial release" in entries[0].description


class TestWriteAndReadBack:
    def test_roundtrip(self):
        b = PackageBuilder(
            "roundtrip-test", "1.0", "MIT", "noarch", "roundtrip test package"
        )
        b.with_file_contents(b"test content", FileOptions.new("/usr/share/test.txt"))
        pkg = b.build()

        with tempfile.NamedTemporaryFile(suffix=".rpm", delete=False) as f:
            path = f.name
        try:
            pkg.write_file(path)
            reopened = Package.open(path)
            assert reopened.metadata.name == "roundtrip-test"
            assert reopened.metadata.summary == "roundtrip test package"
            reopened.verify_digests()
        finally:
            os.unlink(path)


class TestSigning:
    def test_build_and_sign(self):
        with open(PRIVATE_KEY, "rb") as f:
            signer = Signer(f.read())
        with open(PUBLIC_KEY, "rb") as f:
            verifier = Verifier(f.read())

        b = PackageBuilder("signed-test", "1.0", "MIT", "noarch")
        pkg = b.build_and_sign(signer)
        pkg.verify_signature(verifier)


class TestTriggers:
    def test_trigger_in(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.trigger_in("bash", "echo triggered")
        pkg = b.build()
        triggers = pkg.metadata.triggers()
        assert len(triggers) == 1
        assert "echo triggered" in triggers[0].script

    def test_trigger_with_version_condition(self):
        from rpm_rs import DependencyFlags

        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.trigger_in(
            "bash",
            "echo versioned",
            flags=int(DependencyFlags.GREATER | DependencyFlags.EQUAL),
            version="5.0",
        )
        pkg = b.build()
        triggers = pkg.metadata.triggers()
        assert len(triggers) == 1
        c = triggers[0].conditions[0]
        assert c.name == "bash"
        assert c.version == "5.0"

    def test_file_trigger_in(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.file_trigger_in("/usr/lib", "echo file triggered")
        pkg = b.build()
        triggers = pkg.metadata.file_triggers()
        assert len(triggers) == 1

    def test_trans_file_trigger_in(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.trans_file_trigger_in("/usr/lib", "echo trans triggered")
        pkg = b.build()
        triggers = pkg.metadata.trans_file_triggers()
        assert len(triggers) == 1

    def test_verify_script_roundtrip(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.verify_script("echo verify")
        pkg = b.build()
        s = pkg.metadata.verify_script()
        assert "echo verify" in s.script


class TestBuilderReuse:
    def test_double_build_raises(self):
        b = PackageBuilder("test", "1.0", "MIT", "noarch")
        b.build()
        try:
            b.build()
            assert False, "Expected ValueError on double build"
        except ValueError as e:
            assert "already been consumed" in str(e)
