"""Tests for PackageMetadata."""

from pathlib import Path

import pytest

from rpm_rs import (
    ChangelogEntry,
    Dependency,
    DigestAlgorithm,
    Evr,
    FileEntry,
    FileType,
    Nevra,
    Package,
    PackageMetadata,
    Scriptlet,
    SignatureInfo,
    SignatureTag,
    Tag,
    Trigger,
    TriggerCondition,
)

from conftest import (
    RPM_BASIC,
    RPM_EMPTY,
    RPM_SCRIPTLETS,
    RPM_RICH_DEPS,
    RPM_SIGNED,
    SRPM_BASIC,
)


class TestOpen:
    def test_open(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.name == "rpm-basic"
        assert m.version == "2.3.4"
        assert m.release == "5.el9"
        assert m.arch == "noarch"

    def test_open_pathlike(self):
        m = PackageMetadata.open(Path(RPM_BASIC))
        assert m.name == "rpm-basic"

    def test_from_bytes(self):
        with open(RPM_BASIC, "rb") as f:
            data = f.read()
        m = PackageMetadata.from_bytes(data)
        assert m.name == "rpm-basic"

    def test_roundtrip_bytes(self):
        m = PackageMetadata.open(RPM_BASIC)
        data = m.to_bytes()
        m2 = PackageMetadata.from_bytes(data)
        assert m2.name == m.name
        assert m2.version == m.version
        assert m2.release == m.release


class TestIdentity:
    def test_epoch(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.epoch == 1

    def test_nevra(self):
        m = PackageMetadata.open(RPM_BASIC)
        n = m.nevra()
        assert isinstance(n, Nevra)
        assert n.name == "rpm-basic"
        assert n.epoch == "1"
        assert n.version == "2.3.4"
        assert n.release == "5.el9"
        assert n.arch == "noarch"

    def test_evr(self):
        m = PackageMetadata.open(RPM_BASIC)
        e = m.evr()
        assert isinstance(e, Evr)
        assert e.epoch == "1"
        assert e.version == "2.3.4"
        assert e.release == "5.el9"

    def test_is_source_package_false(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.is_source_package() is False

    def test_is_source_package_true(self):
        m = PackageMetadata.open(SRPM_BASIC)
        assert m.is_source_package() is True


class TestSorting:
    def test_sort_by_nevra(self):
        basic = PackageMetadata.open(RPM_BASIC)
        scriptlets = PackageMetadata.open(RPM_SCRIPTLETS)
        pkgs = [scriptlets, basic]
        pkgs.sort(key=lambda p: p.nevra())
        assert pkgs[0].name == "rpm-basic"
        assert pkgs[1].name == "rpm-scriptlets"

    def test_sort_by_evr(self):
        # rpm-basic has epoch 1; rpm-empty has epoch 0
        basic = PackageMetadata.open(RPM_BASIC)
        empty = PackageMetadata.open(RPM_EMPTY)
        pkgs = [basic, empty]
        pkgs.sort(key=lambda p: p.evr())
        assert pkgs[0].name == "rpm-empty"
        assert pkgs[1].name == "rpm-basic"


class TestDescription:
    def test_summary(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert isinstance(m.summary, str)
        assert len(m.summary) > 0

    def test_description(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert isinstance(m.description, str)

    def test_license(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert isinstance(m.license, str)
        assert len(m.license) > 0


class TestBuildInfo:
    def test_build_time(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.build_time > 0

    def test_build_host(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert isinstance(m.build_host, str)

    def test_source_rpm(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert isinstance(m.source_rpm, str)
        assert m.source_rpm.endswith(".src.rpm")


class TestContent:
    def test_installed_size(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.installed_size > 0

    def test_payload_compressor(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert isinstance(m.payload_compressor, str)

    def test_file_digest_algorithm(self):
        m = PackageMetadata.open(RPM_BASIC)
        algo = m.file_digest_algorithm
        assert str(algo) is not None
        assert algo == DigestAlgorithm.SHA2_256


class TestDependencies:
    def test_provides(self):
        m = PackageMetadata.open(RPM_BASIC)
        provides = m.provides()
        assert len(provides) > 0
        assert all(isinstance(d, Dependency) for d in provides)
        assert any(d.name == "rpm-basic" for d in provides)

    def test_requires(self):
        m = PackageMetadata.open(RPM_BASIC)
        requires = m.requires()
        assert len(requires) > 0

    def test_dependency_fields(self):
        m = PackageMetadata.open(RPM_BASIC)
        provides = m.provides()
        d = provides[0]
        assert isinstance(d.name, str)
        assert isinstance(d.version, str)
        assert d.flags is not None

    def test_rich_deps(self):
        m = PackageMetadata.open(RPM_RICH_DEPS)
        requires = m.requires()
        rich = [d for d in requires if d.name.startswith("(")]
        assert len(rich) > 0

    def test_all_dep_types(self):
        m = PackageMetadata.open(RPM_RICH_DEPS)
        assert len(m.provides()) > 0
        assert len(m.requires()) > 0
        assert len(m.recommends()) > 0
        assert len(m.suggests()) > 0
        assert len(m.supplements()) > 0
        assert len(m.enhances()) > 0
        assert len(m.conflicts()) > 0

    def test_empty_package_deps(self):
        m = PackageMetadata.open(RPM_EMPTY)
        # Empty packages still have self-provides and rpmlib requires
        assert len(m.provides()) > 0


class TestFiles:
    def test_file_paths(self):
        m = PackageMetadata.open(RPM_BASIC)
        paths = m.file_paths()
        assert len(paths) > 0
        assert all(isinstance(p, str) for p in paths)

    def test_file_entries(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.file_entries()
        assert len(entries) > 0
        assert all(isinstance(e, FileEntry) for e in entries)

    def test_file_entry_properties(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.file_entries()
        e = entries[0]
        assert isinstance(e.path, str)
        assert e.user is not None
        assert e.group is not None

    def test_file_type_enum(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.file_entries()

        dirs = [e for e in entries if e.mode.file_type == FileType.Dir]
        regulars = [e for e in entries if e.mode.file_type == FileType.Regular]
        assert len(dirs) > 0
        assert len(regulars) > 0

    def test_file_mode_permissions(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.file_entries()
        for e in entries:
            assert e.mode.raw_mode > 0
            assert e.mode.permissions <= 0o7777

    def test_file_digest(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.file_entries()
        regular_files = [e for e in entries if e.mode.file_type == FileType.Regular]
        assert len(regular_files) > 0
        with_digest = [f for f in regular_files if f.digest is not None]
        assert len(with_digest) > 0
        for f in with_digest:
            assert len(f.digest.digest) > 0
            assert f.digest.algorithm is not None

    def test_empty_package_no_files(self):
        m = PackageMetadata.open(RPM_EMPTY)
        assert len(m.file_paths()) == 0
        assert len(m.file_entries()) == 0


class TestScriptlets:
    def test_scriptlets_present(self):
        m = PackageMetadata.open(RPM_SCRIPTLETS)
        pre = m.pre_install_script()
        assert isinstance(pre, Scriptlet)
        assert len(pre.script) > 0

    def test_scriptlet_program(self):
        m = PackageMetadata.open(RPM_SCRIPTLETS)
        pre = m.pre_install_script()
        if pre.program is not None:
            assert isinstance(pre.program, list)

    def test_scriptlets_missing_raises(self):
        m = PackageMetadata.open(RPM_BASIC)
        with pytest.raises(RuntimeError):
            m.pre_install_script()


class TestSignatures:
    def test_unsigned_metadata(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.signatures() == []
        assert m.raw_signatures() == []

    def test_signed_metadata(self):
        m = PackageMetadata.open(RPM_SIGNED)
        sigs = m.signatures()
        assert len(sigs) > 0
        assert all(isinstance(s, SignatureInfo) for s in sigs)
        assert sigs[0].fingerprint is not None
        raw = m.raw_signatures()
        assert len(raw) > 0
        assert all(isinstance(s, bytes) for s in raw)


class TestChangelog:
    def test_changelog(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.changelog_entries()
        assert isinstance(entries, list)
        assert len(entries) == 3

        e = entries[0]
        assert isinstance(e, ChangelogEntry)
        assert e.name == "Walter White <ww@savewalterwhite.com> - 3.3.3-3"
        assert e.timestamp == 1623672000
        assert "empire business" in e.description

        e = entries[2]
        assert e.name == "Mike Ehrmantraut <mike@lospolloshermanos.com> - 1.1.1-1"
        assert e.timestamp == 1617192000


class TestRawTagAccess:
    def test_entry_is_present(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.header.entry_is_present(Tag.NAME)
        assert not m.header.entry_is_present(9999)

    def test_entry_with_raw_int(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.header.entry(1000) == "rpm-basic"

    def test_entry_string(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.header.entry(Tag.NAME) == "rpm-basic"

    def test_entry_int(self):
        m = PackageMetadata.open(RPM_BASIC)
        val = m.header.entry(Tag.BUILDTIME)
        assert isinstance(val, list)
        assert all(isinstance(v, int) for v in val)

    def test_entry_string_array(self):
        m = PackageMetadata.open(RPM_BASIC)
        val = m.header.entry(Tag.BASENAMES)
        assert isinstance(val, list)
        assert all(isinstance(v, str) for v in val)

    def test_entry_not_found(self):
        m = PackageMetadata.open(RPM_BASIC)
        with pytest.raises(RuntimeError, match="unable to find tag"):
            m.header.entry(9999)

    def test_get_all_entries(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.header.get_all_entries()
        assert isinstance(entries, dict)
        assert len(entries) > 0
        assert entries[int(Tag.NAME)] == "rpm-basic"
        assert entries[int(Tag.VERSION)] == "2.3.4"


class TestRawSignatureTagAccess:
    def test_signature_entry_is_present(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.signature.entry_is_present(SignatureTag.SHA256)
        assert not m.signature.entry_is_present(9999)

    def test_signature_entry_with_raw_int(self):
        m = PackageMetadata.open(RPM_BASIC)
        val = m.signature.entry(273)  # SHA256
        assert isinstance(val, str)

    def test_signature_entry_string(self):
        m = PackageMetadata.open(RPM_BASIC)
        val = m.signature.entry(SignatureTag.SHA256)
        assert isinstance(val, str)
        assert len(val) == 64

    def test_signature_entry_not_found(self):
        m = PackageMetadata.open(RPM_BASIC)
        with pytest.raises(RuntimeError, match="unable to find tag"):
            m.signature.entry(9999)

    def test_get_all_signature_entries(self):
        m = PackageMetadata.open(RPM_BASIC)
        entries = m.signature.get_all_entries()
        assert isinstance(entries, dict)
        assert len(entries) > 0
        assert int(SignatureTag.SHA256) in entries


class TestHeaderBytes:
    def test_header_bytes_returns_bytes(self):
        m = PackageMetadata.open(RPM_BASIC)
        header = m.header_bytes()
        assert isinstance(header, bytes)
        assert len(header) > 0

    def test_header_bytes_matches_package(self):
        pkg = Package.open(RPM_SIGNED)
        assert pkg.header_bytes() == pkg.metadata.header_bytes()


class TestDigests:
    def test_check_digests(self):
        m = PackageMetadata.open(RPM_BASIC)
        report = m.check_digests()
        assert report.is_ok()
        assert report.has_header_digest()

    def test_verify_digests(self):
        PackageMetadata.open(RPM_BASIC).verify_digests()

    def test_verify_digests_signed(self):
        PackageMetadata.open(RPM_SIGNED).verify_digests()


class TestVerifyScript:
    def test_verify_script_missing_raises(self):
        m = PackageMetadata.open(RPM_BASIC)
        with pytest.raises(RuntimeError):
            m.verify_script()


class TestTriggers:
    def test_package_triggers(self):
        m = PackageMetadata.open(RPM_SCRIPTLETS)
        triggers = m.triggers()
        assert len(triggers) > 0
        assert all(isinstance(t, Trigger) for t in triggers)

    def test_trigger_properties(self):
        m = PackageMetadata.open(RPM_SCRIPTLETS)
        t = m.triggers()[0]
        assert isinstance(t.script, str)
        assert len(t.script) > 0
        assert isinstance(t.program, list)
        assert len(t.conditions) > 0
        c = t.conditions[0]
        assert isinstance(c, TriggerCondition)
        assert isinstance(c.name, str)
        assert isinstance(c.version, str)

    def test_file_triggers(self):
        m = PackageMetadata.open(RPM_SCRIPTLETS)
        triggers = m.file_triggers()
        assert len(triggers) > 0

    def test_trans_file_triggers(self):
        m = PackageMetadata.open(RPM_SCRIPTLETS)
        triggers = m.trans_file_triggers()
        assert len(triggers) > 0

    def test_no_triggers(self):
        m = PackageMetadata.open(RPM_BASIC)
        assert m.triggers() == []
        assert m.file_triggers() == []
        assert m.trans_file_triggers() == []
