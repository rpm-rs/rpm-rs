#![allow(clippy::too_many_arguments)]

//! Python bindings for rpm-rs via PyO3.
//!
//! This module is only compiled when the `python` feature is enabled.
//! To build as a Python extension module, you also need:
//!   - `crate-type = ["cdylib"]` in `[lib]` (or use maturin which handles this automatically)
//!   - The `pyo3/extension-module` feature (already implied by the `python` feature)
//!
//! With maturin, create a `pyproject.toml` that specifies `features = ["python"]` and run
//! `maturin develop` or `maturin build`.

use std::cmp::Ordering;
use std::io::{BufReader, Cursor};
use std::path::PathBuf;

use pyo3::exceptions::{PyIOError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyType};

/// Convert an rpm::Error into a Python exception.
fn to_pyerr(e: crate::Error) -> PyErr {
    match e {
        crate::Error::Io(io_err) => PyIOError::new_err(io_err.to_string()),

        crate::Error::Hex(_)
        | crate::Error::InvalidDestinationPath { .. }
        | crate::Error::InvalidCapabilities { .. }
        | crate::Error::InvalidFileOptions { .. }
        | crate::Error::InvalidFileMode { .. }
        | crate::Error::InvalidDigestLength { .. }
        | crate::Error::InvalidControlChar { .. }
        | crate::Error::InvalidCharacters { .. }
        | crate::Error::InvalidFileCaps(_)
        | crate::Error::TimestampConv(_)
        | crate::Error::UnknownCompressorType(_)
        | crate::Error::UnsupportedCompressorType(_)
        | crate::Error::UnsupportedDigestAlgorithm(_)
        | crate::Error::BuilderReuse => PyValueError::new_err(e.to_string()),

        other => PyRuntimeError::new_err(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// DigestAlgorithm
// ---------------------------------------------------------------------------

/// The hash algorithm used for file checksums within an RPM package.
#[pyclass(name = "DigestAlgorithm", from_py_object)]
#[derive(Clone)]
pub struct PyDigestAlgorithm(pub(crate) crate::DigestAlgorithm);

#[allow(non_snake_case)]
#[pymethods]
impl PyDigestAlgorithm {
    #[classattr]
    fn MD5() -> Self {
        Self(crate::DigestAlgorithm::Md5)
    }
    #[classattr]
    fn SHA2_224() -> Self {
        Self(crate::DigestAlgorithm::Sha2_224)
    }
    #[classattr]
    fn SHA2_256() -> Self {
        Self(crate::DigestAlgorithm::Sha2_256)
    }
    #[classattr]
    fn SHA2_384() -> Self {
        Self(crate::DigestAlgorithm::Sha2_384)
    }
    #[classattr]
    fn SHA2_512() -> Self {
        Self(crate::DigestAlgorithm::Sha2_512)
    }
    #[classattr]
    fn SHA3_256() -> Self {
        Self(crate::DigestAlgorithm::Sha3_256)
    }
    #[classattr]
    fn SHA3_512() -> Self {
        Self(crate::DigestAlgorithm::Sha3_512)
    }

    fn __repr__(&self) -> String {
        format!("DigestAlgorithm.{:?}", self.0)
    }

    fn __str__(&self) -> String {
        format!("{:?}", self.0)
    }

    fn __eq__(&self, other: &PyDigestAlgorithm) -> bool {
        self.0 == other.0
    }

    /// The numeric value of this digest algorithm (as used in the RPM header).
    #[getter]
    fn value(&self) -> u32 {
        self.0 as u32
    }
}

// ---------------------------------------------------------------------------
// FileType
// ---------------------------------------------------------------------------

/// The type of a file entry: regular, directory, symlink, or other.
#[pyclass(name = "FileType", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, PartialEq, Hash)]
pub enum PyFileType {
    Regular,
    Dir,
    SymbolicLink,
    Other,
}

#[pymethods]
impl PyFileType {
    fn __repr__(&self) -> &str {
        match self {
            PyFileType::Regular => "FileType.Regular",
            PyFileType::Dir => "FileType.Dir",
            PyFileType::SymbolicLink => "FileType.SymbolicLink",
            PyFileType::Other => "FileType.Other",
        }
    }
}

impl From<crate::FileType> for PyFileType {
    fn from(ft: crate::FileType) -> Self {
        match ft {
            crate::FileType::Regular => PyFileType::Regular,
            crate::FileType::Dir => PyFileType::Dir,
            crate::FileType::SymbolicLink => PyFileType::SymbolicLink,
            crate::FileType::Other => PyFileType::Other,
        }
    }
}

// ---------------------------------------------------------------------------
// FileMode
// ---------------------------------------------------------------------------

/// The mode of a file entry: type (regular/dir/symlink) and permission bits.
#[pyclass(name = "FileMode", from_py_object)]
#[derive(Clone)]
pub struct PyFileMode(pub(crate) crate::FileMode);

#[pymethods]
impl PyFileMode {
    fn __repr__(&self) -> String {
        format!("{:?}", self.0)
    }

    /// The raw combined mode bits (file type | permissions), as a 16-bit value.
    #[getter]
    fn raw_mode(&self) -> u16 {
        self.0.raw_mode()
    }

    /// The permission bits only (e.g. 0o755), without the file type bits.
    #[getter]
    fn permissions(&self) -> u16 {
        self.0.permissions()
    }

    /// The file type.
    #[getter]
    fn file_type(&self) -> PyFileType {
        self.0.file_type().into()
    }
}

// ---------------------------------------------------------------------------
// FileDigest
// ---------------------------------------------------------------------------

/// A file checksum (digest) and the algorithm used to compute it.
#[pyclass(name = "FileDigest", from_py_object)]
#[derive(Clone)]
pub struct PyFileDigest(pub(crate) crate::FileDigest);

#[pymethods]
impl PyFileDigest {
    fn __repr__(&self) -> String {
        format!(
            "FileDigest(algo={:?}, digest={})",
            self.0.algo,
            self.0.as_hex()
        )
    }

    fn __str__(&self) -> String {
        self.0.as_hex().to_string()
    }

    /// The hex-encoded digest string.
    #[getter]
    fn digest(&self) -> &str {
        self.0.as_hex()
    }

    /// The algorithm used to compute this digest.
    #[getter]
    fn algorithm(&self) -> PyDigestAlgorithm {
        PyDigestAlgorithm(self.0.algo)
    }
}

// ---------------------------------------------------------------------------
// FileOwnership
// ---------------------------------------------------------------------------

/// The owning user and group of a file entry.
#[pyclass(name = "FileOwnership", from_py_object)]
#[derive(Clone)]
pub struct PyFileOwnership(pub(crate) crate::FileOwnership);

#[pymethods]
impl PyFileOwnership {
    fn __repr__(&self) -> String {
        format!(
            "FileOwnership(user={:?}, group={:?})",
            self.0.user, self.0.group
        )
    }

    /// The owning user name.
    #[getter]
    fn user(&self) -> &str {
        &self.0.user
    }

    /// The owning group name.
    #[getter]
    fn group(&self) -> &str {
        &self.0.group
    }
}

// ---------------------------------------------------------------------------
// FileEntry
// ---------------------------------------------------------------------------

/// A file entry from an RPM package, including path, mode, ownership, and digest.
#[pyclass(name = "FileEntry", from_py_object)]
#[derive(Clone)]
pub struct PyFileEntry(pub(crate) crate::FileEntry);

#[pymethods]
impl PyFileEntry {
    fn __repr__(&self) -> String {
        format!("FileEntry({:?})", self.0.path.display().to_string())
    }

    /// The full installation path of this file (e.g. "/usr/bin/foo").
    #[getter]
    fn path(&self) -> String {
        self.0.path.display().to_string()
    }

    /// The file mode (type and permissions).
    #[getter]
    fn mode(&self) -> PyFileMode {
        PyFileMode(self.0.mode)
    }

    /// The owning user and group.
    #[getter]
    fn ownership(&self) -> PyFileOwnership {
        PyFileOwnership(self.0.ownership.clone())
    }

    /// Last modified timestamp as seconds since the Unix epoch.
    #[getter]
    fn modified_at(&self) -> u32 {
        self.0.modified_at.0
    }

    /// The size of the file in bytes.
    /// Note: for directories this is the inode size, not the directory content size.
    #[getter]
    fn size(&self) -> usize {
        self.0.size
    }

    /// File flags as a `FileFlags` IntFlag value (DOC, CONFIG, GHOST, LICENSE, etc.).
    #[getter]
    fn flags(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let cls = py.import("rpm_rs")?.getattr("FileFlags")?;
        Ok(cls.call1((self.0.flags.bits(),))?.into())
    }

    /// The checksum of this file, or None if not present.
    #[getter]
    fn digest(&self) -> Option<PyFileDigest> {
        self.0.digest.clone().map(PyFileDigest)
    }

    /// POSIX capabilities string for this file, or None.
    #[getter]
    fn caps(&self) -> Option<String> {
        self.0.caps.clone()
    }

    /// Symlink target path, or None if this is not a symlink.
    #[getter]
    fn linkto(&self) -> Option<&str> {
        self.0.linkto.as_deref()
    }

    /// IMA (Integrity Measurement Architecture) signature, or None.
    #[getter]
    fn ima_signature(&self) -> Option<String> {
        self.0.ima_signature.clone()
    }
}

// ---------------------------------------------------------------------------
// ChangelogEntry
// ---------------------------------------------------------------------------

/// A single entry in an RPM package's changelog.
#[pyclass(name = "ChangelogEntry", from_py_object)]
#[derive(Clone)]
pub struct PyChangelogEntry(pub(crate) crate::ChangelogEntry);

#[pymethods]
impl PyChangelogEntry {
    fn __repr__(&self) -> String {
        format!("ChangelogEntry(name={:?})", self.0.name)
    }

    /// The author name and email of this changelog entry.
    #[getter]
    fn name(&self) -> &str {
        &self.0.name
    }

    /// The timestamp of this changelog entry as seconds since the Unix epoch.
    #[getter]
    fn timestamp(&self) -> u64 {
        self.0.timestamp
    }

    /// The description / body of this changelog entry.
    #[getter]
    fn description(&self) -> &str {
        &self.0.description
    }
}

// ---------------------------------------------------------------------------
// Dependency
// ---------------------------------------------------------------------------

/// A dependency relationship as stored in an RPM header
/// (used for Provides, Requires, Conflicts, Obsoletes, etc.).
#[pyclass(name = "Dependency")]
pub struct PyDependency(crate::Dependency);

impl From<crate::Dependency> for PyDependency {
    fn from(d: crate::Dependency) -> Self {
        PyDependency(d)
    }
}

#[pymethods]
impl PyDependency {
    fn __repr__(&self) -> String {
        format!(
            "Dependency(name={:?}, version={:?})",
            self.0.name, self.0.version
        )
    }

    fn __str__(&self) -> String {
        self.0.to_string()
    }

    /// The dependency name (package name, file path, or virtual provide).
    #[getter]
    fn name(&self) -> &str {
        &self.0.name
    }

    /// The version constraint string, or an empty string if unconstrained.
    #[getter]
    fn version(&self) -> &str {
        &self.0.version
    }

    /// Dependency flags as a `DependencyFlags` IntFlag value.
    #[getter]
    fn flags(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let cls = py.import("rpm_rs")?.getattr("DependencyFlags")?;
        Ok(cls.call1((self.0.flags.bits(),))?.into())
    }
}

// ---------------------------------------------------------------------------
// Scriptlet
// ---------------------------------------------------------------------------

/// An RPM scriptlet (pre/post install/uninstall script).
#[pyclass(name = "Scriptlet")]
pub struct PyScriptlet(crate::Scriptlet);

impl From<crate::Scriptlet> for PyScriptlet {
    fn from(s: crate::Scriptlet) -> Self {
        PyScriptlet(s)
    }
}

#[pymethods]
impl PyScriptlet {
    fn __repr__(&self) -> String {
        format!("Scriptlet(program={:?})", self.0.program)
    }

    /// The scriptlet body / content.
    #[getter]
    fn script(&self) -> &str {
        &self.0.script
    }

    /// Scriptlet flags as a `ScriptletFlags` IntFlag value, or None if not set.
    #[getter]
    fn flags(&self, py: Python<'_>) -> PyResult<Option<Py<PyAny>>> {
        match self.0.flags {
            Some(f) => {
                let cls = py.import("rpm_rs")?.getattr("ScriptletFlags")?;
                Ok(Some(cls.call1((f.bits(),))?.into()))
            }
            None => Ok(None),
        }
    }

    /// The interpreter and arguments, if specified (e.g. `["/bin/sh", "-e"]`).
    #[getter]
    fn program(&self) -> Option<Vec<String>> {
        self.0.program.clone()
    }
}

// ---------------------------------------------------------------------------
// Trigger
// ---------------------------------------------------------------------------

/// An RPM trigger entry (package, file, or transactional file trigger).
#[pyclass(name = "Trigger", frozen)]
pub struct PyTrigger(crate::Trigger);

#[pymethods]
impl PyTrigger {
    fn __repr__(&self) -> String {
        format!(
            "Trigger(conditions={}, script_len={})",
            self.0.conditions.len(),
            self.0.script.len()
        )
    }

    /// The script body.
    #[getter]
    fn script(&self) -> &str {
        &self.0.script
    }

    /// The interpreter and arguments (e.g. `["/bin/sh"]`).
    #[getter]
    fn program(&self) -> Vec<String> {
        self.0.program.clone()
    }

    /// The trigger conditions.
    #[getter]
    fn conditions(&self) -> Vec<PyTriggerCondition> {
        self.0
            .conditions
            .iter()
            .cloned()
            .map(PyTriggerCondition)
            .collect()
    }
}

/// A single condition within a trigger entry.
#[pyclass(name = "TriggerCondition", frozen)]
pub struct PyTriggerCondition(crate::TriggerCondition);

#[pymethods]
impl PyTriggerCondition {
    fn __repr__(&self) -> String {
        format!(
            "TriggerCondition(name={:?}, version={:?})",
            self.0.name, self.0.version
        )
    }

    /// Target package name or file path.
    #[getter]
    fn name(&self) -> &str {
        &self.0.name
    }

    /// Dependency flags as a `DependencyFlags` IntFlag value.
    #[getter]
    fn flags(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let cls = py.import("rpm_rs")?.getattr("DependencyFlags")?;
        Ok(cls.call1((self.0.flags.bits(),))?.into())
    }

    /// Version constraint (empty string if unconstrained).
    #[getter]
    fn version(&self) -> &str {
        &self.0.version
    }
}

// ---------------------------------------------------------------------------
// Header
// ---------------------------------------------------------------------------

enum HeaderInner {
    Main(crate::Header<crate::IndexTag>),
    Signature(crate::Header<crate::IndexSignatureTag>),
}

/// A raw RPM header, providing access to individual tag entries.
#[pyclass(name = "Header")]
pub struct PyHeader(HeaderInner);

#[pymethods]
impl PyHeader {
    /// Check whether this header contains an entry for the given tag number.
    fn entry_is_present(&self, tag: u32) -> bool {
        match &self.0 {
            HeaderInner::Main(h) => h.entry_is_present(tag),
            HeaderInner::Signature(h) => h.entry_is_present(tag),
        }
    }

    /// Look up a raw tag by number and return its data as a native Python type.
    ///
    /// Returns `None` for Null, `bytes` for binary data, `int` or `list[int]`
    /// for integer types, `str` for single strings, and `list[str]` for string
    /// arrays. Raises `RuntimeError` if the tag is not present.
    fn entry(&self, tag: u32, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let data = match &self.0 {
            HeaderInner::Main(h) => h.entry(tag),
            HeaderInner::Signature(h) => h.entry(tag),
        }
        .map_err(to_pyerr)?;
        index_data_to_py(py, data)
    }

    /// Return all entries as a dict mapping tag numbers to values.
    fn get_all_entries(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let entries = match &self.0 {
            HeaderInner::Main(h) => h.get_all_entries(),
            HeaderInner::Signature(h) => h.get_all_entries(),
        }
        .map_err(to_pyerr)?;
        let dict = PyDict::new(py);
        for (tag, data) in entries {
            dict.set_item(tag, index_data_to_py(py, data)?)?;
        }
        Ok(dict.into_any().unbind())
    }
}

// ---------------------------------------------------------------------------
// PackageMetadata
// ---------------------------------------------------------------------------

/// RPM package metadata: the lead, signature header, and main header.
/// Does not include the compressed payload.
#[pyclass(name = "PackageMetadata")]
pub struct PyPackageMetadata(pub(crate) crate::PackageMetadata);

#[pymethods]
impl PyPackageMetadata {
    /// Open and parse only the metadata (headers) from an RPM file on disk.
    #[staticmethod]
    fn open(path: PathBuf) -> PyResult<Self> {
        crate::PackageMetadata::open(path)
            .map(PyPackageMetadata)
            .map_err(to_pyerr)
    }

    /// Parse package metadata from raw bytes.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let mut cursor = BufReader::new(Cursor::new(data));
        crate::PackageMetadata::parse(&mut cursor)
            .map(PyPackageMetadata)
            .map_err(to_pyerr)
    }

    /// Serialize this metadata to bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.0.write(&mut buf).map_err(to_pyerr)?;
        Ok(buf)
    }

    // --- Raw header access ---

    /// The main header, for raw tag access.
    #[getter]
    fn header(&self) -> PyHeader {
        PyHeader(HeaderInner::Main(self.0.header.clone()))
    }

    /// The signature header, for raw tag access.
    #[getter]
    fn signature(&self) -> PyHeader {
        PyHeader(HeaderInner::Signature(self.0.signature.clone()))
    }

    // --- Identity ---

    /// The package name.
    #[getter]
    fn name(&self) -> PyResult<String> {
        self.0.get_name().map(str::to_owned).map_err(to_pyerr)
    }

    /// The package epoch (0 if not set).
    #[getter]
    fn epoch(&self) -> PyResult<u32> {
        self.0.get_epoch().map_err(to_pyerr)
    }

    /// The package version string.
    #[getter]
    fn version(&self) -> PyResult<String> {
        self.0.get_version().map(str::to_owned).map_err(to_pyerr)
    }

    /// The package release string.
    #[getter]
    fn release(&self) -> PyResult<String> {
        self.0.get_release().map(str::to_owned).map_err(to_pyerr)
    }

    /// The package architecture (e.g. "x86_64", "noarch").
    #[getter]
    fn arch(&self) -> PyResult<String> {
        self.0.get_arch().map(str::to_owned).map_err(to_pyerr)
    }

    /// The full NEVRA as a structured object.
    fn nevra(&self) -> PyResult<PyNevra> {
        self.0.get_nevra().map(PyNevra::from).map_err(to_pyerr)
    }

    // --- Description ---

    /// A short one-line summary of the package.
    #[getter]
    fn summary(&self) -> PyResult<String> {
        self.0.get_summary().map(str::to_owned).map_err(to_pyerr)
    }

    /// The long description of the package.
    #[getter]
    fn description(&self) -> PyResult<String> {
        self.0
            .get_description()
            .map(str::to_owned)
            .map_err(to_pyerr)
    }

    /// The license expression for this package.
    #[getter]
    fn license(&self) -> PyResult<String> {
        self.0.get_license().map(str::to_owned).map_err(to_pyerr)
    }

    /// The vendor / organization that produced this package.
    #[getter]
    fn vendor(&self) -> PyResult<String> {
        self.0.get_vendor().map(str::to_owned).map_err(to_pyerr)
    }

    /// The upstream URL associated with this package.
    #[getter]
    fn url(&self) -> PyResult<String> {
        self.0.get_url().map(str::to_owned).map_err(to_pyerr)
    }

    /// VCS information (e.g. a `git:repo=…:branch=…:sha=…` string).
    #[getter]
    fn vcs(&self) -> PyResult<String> {
        self.0.get_vcs().map(str::to_owned).map_err(to_pyerr)
    }

    /// The RPM group (e.g. "Development/Libraries").
    #[getter]
    fn group(&self) -> PyResult<String> {
        self.0.get_group().map(str::to_owned).map_err(to_pyerr)
    }

    /// The packager contact string.
    #[getter]
    fn packager(&self) -> PyResult<String> {
        self.0.get_packager().map(str::to_owned).map_err(to_pyerr)
    }

    // --- Build information ---

    /// Build timestamp as seconds since the Unix epoch.
    #[getter]
    fn build_time(&self) -> PyResult<u64> {
        self.0.get_build_time().map_err(to_pyerr)
    }

    /// Hostname of the machine that built this package.
    #[getter]
    fn build_host(&self) -> PyResult<String> {
        self.0.get_build_host().map(str::to_owned).map_err(to_pyerr)
    }

    /// The build cookie (opaque build identifier).
    #[getter]
    fn cookie(&self) -> PyResult<String> {
        self.0.get_cookie().map(str::to_owned).map_err(to_pyerr)
    }

    /// The name of the source RPM this package was built from.
    #[getter]
    fn source_rpm(&self) -> PyResult<String> {
        self.0.get_source_rpm().map(str::to_owned).map_err(to_pyerr)
    }

    /// True if this is a source RPM (SRPM), False if it is a binary RPM.
    fn is_source_package(&self) -> bool {
        self.0.is_source_package()
    }

    // --- Content information ---

    /// Total installed (uncompressed) size of the package in bytes.
    #[getter]
    fn installed_size(&self) -> PyResult<u64> {
        self.0.get_installed_size().map_err(to_pyerr)
    }

    /// Name of the compression algorithm used for the payload (e.g. "Zstd", "Gzip").
    #[getter]
    fn payload_compressor(&self) -> PyResult<String> {
        self.0
            .get_payload_compressor()
            .map(|c| format!("{:?}", c))
            .map_err(to_pyerr)
    }

    /// The digest algorithm used for file checksums within this package.
    #[getter]
    fn file_digest_algorithm(&self) -> PyResult<PyDigestAlgorithm> {
        self.0
            .get_file_digest_algorithm()
            .map(PyDigestAlgorithm)
            .map_err(to_pyerr)
    }

    // --- Scriptlets ---

    /// The pre-install scriptlet (%pre), or raises RuntimeError if not present.
    fn pre_install_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_pre_install_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    /// The post-install scriptlet (%post), or raises RuntimeError if not present.
    fn post_install_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_post_install_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    /// The pre-uninstall scriptlet (%preun), or raises RuntimeError if not present.
    fn pre_uninstall_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_pre_uninstall_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    /// The post-uninstall scriptlet (%postun), or raises RuntimeError if not present.
    fn post_uninstall_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_post_uninstall_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    /// The pre-transaction scriptlet (%pretrans), or raises RuntimeError if not present.
    fn pre_trans_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_pre_trans_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    /// The post-transaction scriptlet (%posttrans), or raises RuntimeError if not present.
    fn post_trans_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_post_trans_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    /// The pre-untrans scriptlet (%preuntrans), or raises RuntimeError if not present.
    fn pre_untrans_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_pre_untrans_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    /// The post-untrans scriptlet (%postuntrans), or raises RuntimeError if not present.
    fn post_untrans_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_post_untrans_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    // --- Dependencies ---

    /// List of capabilities this package provides.
    fn provides(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_provides()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    /// List of capabilities this package requires.
    fn requires(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_requires()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    /// List of capabilities this package conflicts with.
    fn conflicts(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_conflicts()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    /// List of capabilities this package obsoletes.
    fn obsoletes(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_obsoletes()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    /// List of capabilities this package recommends.
    fn recommends(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_recommends()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    /// List of capabilities this package suggests.
    fn suggests(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_suggests()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    /// List of capabilities this package enhances.
    fn enhances(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_enhances()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    /// List of capabilities this package supplements.
    fn supplements(&self) -> PyResult<Vec<PyDependency>> {
        self.0
            .get_supplements()
            .map(|v| v.into_iter().map(PyDependency::from).collect())
            .map_err(to_pyerr)
    }

    // --- Files ---

    /// List of all file paths contained in this package, as strings.
    fn file_paths(&self) -> PyResult<Vec<String>> {
        self.0
            .get_file_paths()
            .map(|v| v.into_iter().map(|p| p.display().to_string()).collect())
            .map_err(to_pyerr)
    }

    /// List of all file entries with full metadata (mode, ownership, digest, etc.).
    fn file_entries(&self) -> PyResult<Vec<PyFileEntry>> {
        self.0
            .get_file_entries()
            .map(|v| v.into_iter().map(PyFileEntry).collect())
            .map_err(to_pyerr)
    }

    // --- Changelog ---

    /// List of changelog entries, most recent first.
    fn changelog_entries(&self) -> PyResult<Vec<PyChangelogEntry>> {
        self.0
            .get_changelog_entries()
            .map(|v| v.into_iter().map(PyChangelogEntry).collect())
            .map_err(to_pyerr)
    }

    // --- Scriptlets (continued) ---

    /// The verify scriptlet (%verifyscript), or raises RuntimeError if not present.
    fn verify_script(&self) -> PyResult<PyScriptlet> {
        self.0
            .get_verify_script()
            .map(PyScriptlet::from)
            .map_err(to_pyerr)
    }

    // --- Triggers ---

    /// List of package trigger entries (%triggerin, %triggerun, etc.).
    fn triggers(&self) -> PyResult<Vec<PyTrigger>> {
        self.0
            .get_triggers()
            .map(|v| v.into_iter().map(PyTrigger).collect())
            .map_err(to_pyerr)
    }

    /// List of file trigger entries (%filetriggerin, %filetriggerun, etc.).
    fn file_triggers(&self) -> PyResult<Vec<PyTrigger>> {
        self.0
            .get_file_triggers()
            .map(|v| v.into_iter().map(PyTrigger).collect())
            .map_err(to_pyerr)
    }

    /// List of transactional file trigger entries (%transfiletriggerin, etc.).
    fn trans_file_triggers(&self) -> PyResult<Vec<PyTrigger>> {
        self.0
            .get_trans_file_triggers()
            .map(|v| v.into_iter().map(PyTrigger).collect())
            .map_err(to_pyerr)
    }

    // --- Digests ---

    /// Return the raw header bytes for signing workflows.
    fn header_bytes(&self) -> PyResult<Vec<u8>> {
        self.0.header_bytes().map_err(to_pyerr)
    }

    /// Verify that all header digests are correct.
    /// Raises RuntimeError if any digest does not match.
    fn verify_digests(&self) -> PyResult<()> {
        self.0.verify_digests().map_err(to_pyerr)
    }

    /// Check header digests and return a detailed report.
    ///
    /// Payload digest fields are set to `NotChecked`.
    fn check_digests(&self) -> PyResult<PyDigestReport> {
        self.0.check_digests().map(PyDigestReport).map_err(to_pyerr)
    }

    /// Return the byte offsets of each segment (lead, signature header, header, payload)
    /// as they would appear in the on-disk package file.
    fn package_segment_offsets(&self) -> PyPackageSegmentOffsets {
        PyPackageSegmentOffsets(self.0.get_package_segment_offsets())
    }

    /// Return parsed information about each OpenPGP signature embedded in the package.
    ///
    /// Returns a list of `SignatureInfo` objects, or an empty list if the package is unsigned.
    fn signatures(&self) -> PyResult<Vec<PySignatureInfo>> {
        self.0
            .signatures()
            .map(|sigs| sigs.into_iter().map(PySignatureInfo).collect())
            .map_err(to_pyerr)
    }

    /// Return the raw bytes of each signature in the package's signature header.
    ///
    /// Returns a list of `bytes` objects. Returns an empty list if unsigned.
    fn raw_signatures(&self) -> PyResult<Vec<Vec<u8>>> {
        self.0
            .raw_signatures()
            .map(|sigs| sigs.into_iter().map(|s| s.into_owned()).collect())
            .map_err(to_pyerr)
    }

    /// Verify the package's header PGP signature against a `Verifier`.
    ///
    /// Raises RuntimeError if verification fails or no signature is present.
    /// Payload signatures are not checked; use `Package.verify_signature()` for full verification.
    fn verify_signature(&self, verifier: &PyVerifier) -> PyResult<()> {
        self.0
            .verify_signature(verifier.0.clone())
            .map_err(to_pyerr)
    }

    /// Check header digests and verify header-only signatures, returning a detailed report.
    ///
    /// Returns a `SignatureReport` with per-digest and per-signature results.
    /// Unlike `verify_signature()`, this does not raise on failure — inspect
    /// the report to see which digests and signatures passed or failed.
    ///
    /// Payload digest fields are set to `NotChecked`.
    fn check_signatures(&self, verifier: &PyVerifier) -> PyResult<PySignatureReport> {
        let report = self
            .0
            .check_signatures(verifier.0.clone())
            .map_err(to_pyerr)?;
        let ok = report.is_ok();
        let digest_report = report.digests;
        let sig_results = report
            .signatures
            .into_iter()
            .map(|r| (r.info, r.error.map(|e| e.to_string())))
            .collect();
        Ok(PySignatureReport {
            digest_report,
            sig_results,
            ok,
        })
    }
}

// ---------------------------------------------------------------------------
// PackageSegmentOffsets
// ---------------------------------------------------------------------------

/// Byte offsets into an RPM package demarking the start of each segment.
#[pyclass(name = "PackageSegmentOffsets", frozen)]
pub struct PyPackageSegmentOffsets(crate::PackageSegmentOffsets);

#[pymethods]
impl PyPackageSegmentOffsets {
    /// Offset of the lead (always 0).
    #[getter]
    fn lead(&self) -> u64 {
        self.0.lead
    }

    /// Offset of the signature header.
    #[getter]
    fn signature_header(&self) -> u64 {
        self.0.signature_header
    }

    /// Offset of the main header.
    #[getter]
    fn header(&self) -> u64 {
        self.0.header
    }

    /// Offset of the payload.
    #[getter]
    fn payload(&self) -> u64 {
        self.0.payload
    }

    fn __repr__(&self) -> String {
        format!(
            "PackageSegmentOffsets(lead={}, signature_header={}, header={}, payload={})",
            self.0.lead, self.0.signature_header, self.0.header, self.0.payload,
        )
    }
}

// ---------------------------------------------------------------------------
// RpmFile
// ---------------------------------------------------------------------------

/// A file from an RPM package payload, including its metadata and content bytes.
#[pyclass(name = "RpmFile")]
pub struct PyRpmFile(pub(crate) crate::RpmFile);

#[pymethods]
impl PyRpmFile {
    fn __repr__(&self) -> String {
        format!(
            "RpmFile({:?}, {} bytes)",
            self.0.metadata.path.display(),
            self.0.content.len()
        )
    }

    /// The file entry metadata (path, mode, ownership, digest, etc.).
    #[getter]
    fn metadata(&self) -> PyFileEntry {
        PyFileEntry(self.0.metadata.clone())
    }

    /// The raw file content bytes.
    #[getter]
    fn content(&self) -> &[u8] {
        &self.0.content
    }
}

// ---------------------------------------------------------------------------
// Package
// ---------------------------------------------------------------------------

/// A complete RPM package: metadata (headers) plus the compressed payload.
#[pyclass(name = "Package")]
pub struct PyPackage(pub(crate) crate::Package);

#[pymethods]
impl PyPackage {
    /// Open and parse a complete RPM package from a file path.
    #[staticmethod]
    fn open(path: PathBuf) -> PyResult<Self> {
        crate::Package::open(path).map(PyPackage).map_err(to_pyerr)
    }

    /// Parse a complete RPM package from raw bytes.
    #[staticmethod]
    fn from_bytes(data: &[u8]) -> PyResult<Self> {
        let mut reader = BufReader::new(Cursor::new(data));
        crate::Package::parse(&mut reader)
            .map(PyPackage)
            .map_err(to_pyerr)
    }

    /// Serialize the full package (metadata + payload) to bytes.
    fn to_bytes(&self) -> PyResult<Vec<u8>> {
        let mut buf = Vec::new();
        self.0.write(&mut buf).map_err(to_pyerr)?;
        Ok(buf)
    }

    /// Write the full package to a file at the given path.
    fn write_file(&self, path: PathBuf) -> PyResult<()> {
        self.0.write_file(path).map_err(to_pyerr)
    }

    /// Write the full package to a file or directory.
    ///
    /// If `path` is an existing directory, the package is written with an auto-generated filename
    /// based on its NEVRA (e.g. `foo-1.0.0-1.x86_64.rpm`).  Otherwise `path` is treated as a file
    /// path (a `.rpm` extension is ensured).
    ///
    /// Returns the actual path where the package was written.
    fn write_to(&self, path: PathBuf) -> PyResult<String> {
        self.0
            .write_to(path)
            .map(|p| p.to_string_lossy().into_owned())
            .map_err(to_pyerr)
    }

    /// Serialize the main header to bytes suitable for signing.
    ///
    /// These are the bytes that a signing key should sign. Useful for remote
    /// signing workflows: extract header bytes, send them to a remote signer,
    /// then apply the resulting signature with `apply_signature`.
    fn header_bytes(&self) -> PyResult<Vec<u8>> {
        self.0.header_bytes().map_err(to_pyerr)
    }

    /// The package metadata (headers), without the payload.
    #[getter]
    fn metadata(&self) -> PyPackageMetadata {
        PyPackageMetadata(self.0.metadata.clone())
    }

    /// The canonical filename for this package (e.g. `name-version-release.arch.rpm`).
    fn canonical_filename(&self) -> PyResult<String> {
        self.0.canonical_filename().map_err(to_pyerr)
    }

    /// Extract all files from the package payload into the given destination directory.
    fn extract(&self, destination: PathBuf) -> PyResult<()> {
        self.0.extract(destination).map_err(to_pyerr)
    }

    /// List of all files from the package payload, including their content bytes.
    ///
    /// This eagerly decompresses and reads the entire payload. For large packages,
    /// prefer using `extract()` if you only need to write files to disk.
    fn files(&self) -> PyResult<Vec<PyRpmFile>> {
        self.0
            .files()
            .map_err(to_pyerr)?
            .map(|r| r.map(PyRpmFile).map_err(to_pyerr))
            .collect()
    }

    /// Verify that all file digests in the package are correct.
    /// Raises RuntimeError if any digest does not match.
    fn verify_digests(&self) -> PyResult<()> {
        self.0.verify_digests().map_err(to_pyerr)
    }

    /// Check all digests and return a detailed report.
    ///
    /// Returns a `DigestReport` with per-digest verification status.
    /// Unlike `verify_digests()`, this does not raise on mismatch — inspect
    /// the report to see which digests passed, failed, or are absent.
    ///
    /// Raises only on internal I/O errors (should not occur in practice).
    fn check_digests(&self) -> PyResult<PyDigestReport> {
        self.0.check_digests().map(PyDigestReport).map_err(to_pyerr)
    }

    /// Apply a pre-computed signature to this package.
    ///
    /// The raw OpenPGP signature bytes are added to the signature header.
    /// Header digests are recalculated automatically.
    fn apply_signature(&mut self, signature: Vec<u8>) -> PyResult<()> {
        self.0.apply_signature(signature).map_err(to_pyerr)
    }

    /// Clear all signatures from the package, regenerating header digests.
    ///
    /// After calling this, the package will have no PGP signatures but will
    /// retain valid SHA-256 and SHA3-256 header digests.
    fn clear_signatures(&mut self) -> PyResult<()> {
        self.0.clear_signatures().map_err(to_pyerr)
    }

    /// Sign the package with a `Signer`.
    ///
    /// Optionally provide a `timestamp` (seconds since Unix epoch) to embed within the signature
    /// instead of the current time. Useful for reproducible builds.
    #[pyo3(signature = (signer, timestamp=None))]
    fn sign(&mut self, signer: &PySigner, timestamp: Option<u32>) -> PyResult<()> {
        if let Some(timestamp) = timestamp {
            self.0.sign_with_timestamp(signer.0.clone(), timestamp)
        } else {
            self.0.sign(signer.0.clone())
        }
        .map_err(to_pyerr)
    }

    /// Verify the package's PGP signature against a `Verifier`.
    ///
    /// Raises RuntimeError if verification fails or no signature is present.
    fn verify_signature(&self, verifier: &PyVerifier) -> PyResult<()> {
        self.0
            .verify_signature(verifier.0.clone())
            .map_err(to_pyerr)
    }

    /// Check all digests and verify all signatures, returning a detailed report.
    ///
    /// Returns a `SignatureReport` with per-digest and per-signature results.
    /// Unlike `verify_signature()`, this does not raise on failure — inspect
    /// the report to see which digests and signatures passed or failed.
    ///
    /// Raises only on internal I/O errors (should not occur in practice).
    fn check_signatures(&self, verifier: &PyVerifier) -> PyResult<PySignatureReport> {
        let report = self
            .0
            .check_signatures(verifier.0.clone())
            .map_err(to_pyerr)?;
        let ok = report.is_ok();
        let digest_report = report.digests;
        let sig_results = report
            .signatures
            .into_iter()
            .map(|r| (r.info, r.error.map(|e| e.to_string())))
            .collect();
        Ok(PySignatureReport {
            digest_report,
            sig_results,
            ok,
        })
    }

    /// Return parsed information about each OpenPGP signature embedded in the package.
    ///
    /// Returns a list of `SignatureInfo` objects, or an empty list if the package is unsigned.
    fn signatures(&self) -> PyResult<Vec<PySignatureInfo>> {
        self.0
            .signatures()
            .map(|sigs| sigs.into_iter().map(PySignatureInfo).collect())
            .map_err(to_pyerr)
    }

    /// Return the raw bytes of each signature in the package's signature header.
    ///
    /// Returns a list of `bytes` objects. Returns an empty list if unsigned.
    fn raw_signatures(&self) -> PyResult<Vec<Vec<u8>>> {
        self.0
            .raw_signatures()
            .map(|sigs| sigs.into_iter().map(|s| s.into_owned()).collect())
            .map_err(to_pyerr)
    }

    /// Re-sign an on-disk RPM package in-place without rewriting the payload.
    ///
    /// The existing signature is replaced and the signature header is padded
    /// to the same size using reserved space, so the file size is unchanged.
    #[staticmethod]
    fn resign_in_place(path: PathBuf, signer: &PySigner) -> PyResult<()> {
        crate::Package::resign_in_place(path, signer.0.clone()).map_err(to_pyerr)
    }

    /// Apply a pre-computed signature to an on-disk RPM package in-place.
    ///
    /// The raw signature bytes are added to the signature header; reserved
    /// space is consumed to keep the file size unchanged.
    #[staticmethod]
    fn apply_signature_in_place(path: PathBuf, signature: Vec<u8>) -> PyResult<()> {
        crate::Package::apply_signature_in_place(path, signature).map_err(to_pyerr)
    }

    /// Remove all signatures from an on-disk RPM package in-place.
    ///
    /// The space previously occupied by signatures is converted to reserved
    /// space, so the file size is unchanged.
    #[staticmethod]
    fn clear_signatures_in_place(path: PathBuf) -> PyResult<()> {
        crate::Package::clear_signatures_in_place(path).map_err(to_pyerr)
    }
}

// ---------------------------------------------------------------------------
// Signer / Verifier
// ---------------------------------------------------------------------------

/// A PGP signer for signing RPM packages.
///
/// Constructed from an ASCII-armored secret key. Optionally configure a
/// passphrase or select a specific signing key by fingerprint.
#[pyclass(name = "Signer")]
struct PySigner(crate::signature::pgp::Signer);

#[pymethods]
impl PySigner {
    /// Create a signer from ASCII-armored secret key bytes.
    ///
    /// Automatically selects the first subkey with signing capability,
    /// or the primary key if no signing subkey is found.
    #[new]
    fn new(key_asc: &[u8]) -> PyResult<Self> {
        crate::signature::pgp::Signer::from_asc_bytes(key_asc)
            .map(PySigner)
            .map_err(to_pyerr)
    }

    /// Create a signer from an ASCII-armored secret key file.
    #[classmethod]
    fn from_file(_cls: &Bound<'_, PyType>, path: PathBuf) -> PyResult<Self> {
        crate::signature::pgp::Signer::from_asc_file(path)
            .map(PySigner)
            .map_err(to_pyerr)
    }

    /// Set the passphrase for a password-protected key.
    fn with_key_passphrase(&self, passphrase: &str) -> Self {
        PySigner(self.0.clone().with_key_passphrase(passphrase))
    }

    /// Select a specific signing key by fingerprint (hex string).
    fn with_signing_key(&self, fingerprint: &str) -> PyResult<Self> {
        let fp = hex::decode(fingerprint).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid hex fingerprint: {e}"))
        })?;
        self.0
            .clone()
            .with_signing_key(&fp)
            .map(PySigner)
            .map_err(to_pyerr)
    }

    /// Sign raw data bytes and return the OpenPGP signature.
    ///
    /// Useful for remote signing workflows where you extract header bytes
    /// with `Package.header_bytes()`, sign them, and apply the result
    /// with `Package.apply_signature()`.
    fn sign(&self, data: &[u8]) -> PyResult<Vec<u8>> {
        use crate::Timestamp;
        use crate::signature::Signing;
        self.0
            .sign(std::io::Cursor::new(data), Timestamp::now())
            .map_err(to_pyerr)
    }
}

/// A PGP verifier for verifying RPM package signatures.
///
/// Constructed from ASCII-armored public key bytes. Multiple keys can be
/// loaded by calling `load_key` to append additional keys.
#[pyclass(name = "Verifier")]
struct PyVerifier(crate::signature::pgp::Verifier);

#[pymethods]
impl PyVerifier {
    /// Create a verifier, optionally loading ASCII-armored public key bytes.
    #[new]
    #[pyo3(signature = (key_asc=None))]
    fn new(key_asc: Option<&[u8]>) -> PyResult<Self> {
        match key_asc {
            Some(key) => crate::signature::pgp::Verifier::from_asc_bytes(key)
                .map(PyVerifier)
                .map_err(to_pyerr),
            None => Ok(PyVerifier(crate::signature::pgp::Verifier::new())),
        }
    }

    /// Create a verifier from an ASCII-armored public key file.
    #[classmethod]
    fn from_file(_cls: &Bound<'_, PyType>, path: PathBuf) -> PyResult<Self> {
        crate::signature::pgp::Verifier::from_asc_file(path)
            .map(PyVerifier)
            .map_err(to_pyerr)
    }

    /// Append additional public key(s) from ASCII-armored bytes.
    fn load_from_asc_bytes(&mut self, key_asc: &[u8]) -> PyResult<()> {
        self.0.load_from_asc_bytes(key_asc).map_err(to_pyerr)
    }

    /// Append additional public key(s) from an ASCII-armored file.
    fn load_from_asc_file(&mut self, path: PathBuf) -> PyResult<()> {
        self.0.load_from_asc_file(path).map_err(to_pyerr)
    }

    /// Filter to a single certificate by primary key fingerprint (hex string).
    fn with_key(&self, fingerprint: &str) -> PyResult<Self> {
        let fp = hex::decode(fingerprint).map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid hex fingerprint: {e}"))
        })?;
        self.0
            .clone()
            .with_key(&fp)
            .map(PyVerifier)
            .map_err(to_pyerr)
    }
}

// ---------------------------------------------------------------------------
// Signature info
// ---------------------------------------------------------------------------

/// Parsed information about a single OpenPGP signature embedded in an RPM package.
#[pyclass(name = "SignatureVersion", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, PartialEq, Hash)]
pub enum PySignatureVersion {
    V4 = 4,
    V6 = 6,
}

#[pymethods]
impl PySignatureVersion {
    fn __repr__(&self) -> &str {
        match self {
            PySignatureVersion::V4 => "SignatureVersion.V4",
            PySignatureVersion::V6 => "SignatureVersion.V6",
        }
    }
}

#[pyclass(name = "SignatureInfo", frozen)]
struct PySignatureInfo(crate::signature::pgp::SignatureInfo);

#[pymethods]
impl PySignatureInfo {
    /// The issuer fingerprint as a lowercase hex string, or None.
    #[getter]
    fn fingerprint(&self) -> Option<&str> {
        self.0.fingerprint()
    }

    /// The issuer key ID as a lowercase hex string, or None.
    #[getter]
    fn key_id(&self) -> Option<&str> {
        self.0.key_id()
    }

    /// The signature creation time as seconds since the Unix epoch, or None.
    #[getter]
    fn created(&self) -> Option<u32> {
        self.0.created()
    }

    /// The public key algorithm name (e.g. "RSA", "EdDSA"), or None.
    #[getter]
    fn algorithm(&self) -> Option<&str> {
        self.0.algorithm().map(|a| match a {
            crate::signature::pgp::SignatureAlgorithm::RSA => "RSA",
            crate::signature::pgp::SignatureAlgorithm::DSA => "DSA",
            crate::signature::pgp::SignatureAlgorithm::ECDSA => "ECDSA",
            crate::signature::pgp::SignatureAlgorithm::EdDSALegacy => "EdDSALegacy",
            crate::signature::pgp::SignatureAlgorithm::Ed25519 => "Ed25519",
            crate::signature::pgp::SignatureAlgorithm::Ed448 => "Ed448",
            crate::signature::pgp::SignatureAlgorithm::MlDsa65Ed25519 => "ML-DSA-65+Ed25519",
            crate::signature::pgp::SignatureAlgorithm::MlDsa87Ed448 => "ML-DSA-87+Ed448",
            _ => "Unsupported",
        })
    }

    /// The OpenPGP signature version.
    ///
    /// Raises `ValueError` if the version is not recognized.
    #[getter]
    fn version(&self) -> PyResult<PySignatureVersion> {
        match self.0.version() {
            crate::signature::pgp::SignatureVersion::V4 => Ok(PySignatureVersion::V4),
            crate::signature::pgp::SignatureVersion::V6 => Ok(PySignatureVersion::V6),
            crate::signature::pgp::SignatureVersion::Unsupported(v) => {
                Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unsupported OpenPGP signature version: {v}"
                )))
            }
        }
    }

    /// The hash algorithm name (e.g. "SHA256", "SHA512"), or None.
    #[getter]
    fn hash_algorithm(&self) -> Option<&str> {
        self.0.hash_algorithm().map(|h| match h {
            crate::signature::pgp::SignatureHashAlgorithm::SHA1 => "SHA1",
            crate::signature::pgp::SignatureHashAlgorithm::SHA256 => "SHA256",
            crate::signature::pgp::SignatureHashAlgorithm::SHA384 => "SHA384",
            crate::signature::pgp::SignatureHashAlgorithm::SHA512 => "SHA512",
            crate::signature::pgp::SignatureHashAlgorithm::SHA224 => "SHA224",
            crate::signature::pgp::SignatureHashAlgorithm::SHA3_256 => "SHA3-256",
            crate::signature::pgp::SignatureHashAlgorithm::SHA3_512 => "SHA3-512",
            _ => "Unsupported",
        })
    }

    fn __repr__(&self) -> String {
        format!(
            "SignatureInfo(fingerprint={:?}, key_id={:?}, algorithm={:?})",
            self.fingerprint(),
            self.key_id(),
            self.algorithm(),
        )
    }
}

// ---------------------------------------------------------------------------
// DigestStatus
// ---------------------------------------------------------------------------

/// The verification status of a single digest in an RPM package.
#[pyclass(name = "DigestStatus", frozen)]
pub struct PyDigestStatus(crate::DigestStatus);

#[pymethods]
impl PyDigestStatus {
    /// True if the digest was present and matched the computed value.
    fn is_verified(&self) -> bool {
        self.0.is_verified()
    }

    /// True if the digest tag was not present in the package headers.
    fn is_not_present(&self) -> bool {
        self.0.is_not_present()
    }

    /// True if the digest was not checked.
    fn is_not_checked(&self) -> bool {
        self.0.is_not_checked()
    }

    /// True if the digest was present but did not match the computed value.
    fn is_mismatch(&self) -> bool {
        self.0.is_mismatch()
    }

    /// The digest value declared in the RPM header, or None if not a mismatch.
    #[getter]
    fn expected(&self) -> Option<&str> {
        match &self.0 {
            crate::DigestStatus::Mismatch { expected, .. } => Some(expected.as_str()),
            _ => None,
        }
    }

    /// The digest value computed from the actual content, or None if not a mismatch.
    #[getter]
    fn actual(&self) -> Option<&str> {
        match &self.0 {
            crate::DigestStatus::Mismatch { actual, .. } => Some(actual.as_str()),
            _ => None,
        }
    }

    fn __repr__(&self) -> String {
        match &self.0 {
            crate::DigestStatus::Verified => "DigestStatus.Verified".to_string(),
            crate::DigestStatus::NotPresent => "DigestStatus.NotPresent".to_string(),
            crate::DigestStatus::NotChecked => "DigestStatus.NotChecked".to_string(),
            crate::DigestStatus::Mismatch { expected, actual } => {
                format!("DigestStatus.Mismatch(expected={expected:?}, actual={actual:?})")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DigestReport
// ---------------------------------------------------------------------------

/// Results of verifying all digests in an RPM package.
///
/// Each attribute holds the verification status for a specific digest type.
/// Not all digests are present in all packages — v4 packages typically have
/// SHA-1 and SHA-256, while v6 packages add SHA3-256 and SHA-512 variants.
#[pyclass(name = "DigestReport", frozen)]
pub struct PyDigestReport(crate::DigestReport);

#[pymethods]
impl PyDigestReport {
    /// SHA-1 of the header (v4 packages).
    #[getter]
    fn header_sha1(&self) -> PyDigestStatus {
        PyDigestStatus(self.0.header_sha1.clone())
    }

    /// SHA-256 of the header.
    #[getter]
    fn header_sha256(&self) -> PyDigestStatus {
        PyDigestStatus(self.0.header_sha256.clone())
    }

    /// SHA3-256 of the header (v6 packages).
    #[getter]
    fn header_sha3_256(&self) -> PyDigestStatus {
        PyDigestStatus(self.0.header_sha3_256.clone())
    }

    /// SHA-256 of the compressed payload.
    #[getter]
    fn payload_sha256(&self) -> PyDigestStatus {
        PyDigestStatus(self.0.payload_sha256.clone())
    }

    /// SHA-512 of the compressed payload (v6 packages).
    #[getter]
    fn payload_sha512(&self) -> PyDigestStatus {
        PyDigestStatus(self.0.payload_sha512.clone())
    }

    /// SHA3-256 of the compressed payload (v6 packages).
    #[getter]
    fn payload_sha3_256(&self) -> PyDigestStatus {
        PyDigestStatus(self.0.payload_sha3_256.clone())
    }

    /// True if at least one header digest was present.
    fn has_header_digest(&self) -> bool {
        self.0.has_header_digest()
    }

    /// True if at least one payload digest was present.
    fn has_payload_digest(&self) -> bool {
        self.0.has_payload_digest()
    }

    /// True if every present digest verified and none mismatched.
    fn is_ok(&self) -> bool {
        self.0.is_ok()
    }

    /// Raise RuntimeError if any digest mismatched.
    fn verify(&self) -> PyResult<()> {
        self.0.result().map_err(to_pyerr)
    }

    fn __repr__(&self) -> String {
        format!("DigestReport(is_ok={})", self.0.is_ok())
    }
}

// ---------------------------------------------------------------------------
// SignatureCheckResult
// ---------------------------------------------------------------------------

/// The result of verifying a single OpenPGP signature against the provided keys.
///
/// Attributes:
///     info: Parsed metadata about the signature (fingerprint, algorithm, etc.).
///     error: Error message string if verification failed, or None if verified.
///     is_verified: True if this signature was successfully verified.
#[pyclass(name = "SignatureCheckResult", frozen)]
pub struct PySignatureCheckResult {
    info: crate::signature::pgp::SignatureInfo,
    error_msg: Option<String>,
}

#[pymethods]
impl PySignatureCheckResult {
    /// Parsed metadata about the signature.
    #[getter]
    fn info(&self) -> PySignatureInfo {
        PySignatureInfo(self.info.clone())
    }

    /// Error message if verification failed, or None if verified.
    #[getter]
    fn error(&self) -> Option<&str> {
        self.error_msg.as_deref()
    }

    /// True if this signature was successfully verified.
    fn is_verified(&self) -> bool {
        self.error_msg.is_none()
    }

    fn __repr__(&self) -> String {
        let fp = self.info.fingerprint().unwrap_or("unknown");
        if self.error_msg.is_some() {
            format!("SignatureCheckResult(fingerprint={:?}, verified=False)", fp)
        } else {
            format!("SignatureCheckResult(fingerprint={:?}, verified=True)", fp)
        }
    }
}

// ---------------------------------------------------------------------------
// SignatureReport
// ---------------------------------------------------------------------------

/// Results of verifying all digests and signatures in an RPM package.
///
/// Attributes:
///     digests: Digest verification results.
///     signatures: List of per-signature verification results.
///     is_ok: True if digests are ok and at least one signature verified.
#[pyclass(name = "SignatureReport", frozen)]
pub struct PySignatureReport {
    digest_report: crate::DigestReport,
    sig_results: Vec<(crate::signature::pgp::SignatureInfo, Option<String>)>,
    ok: bool,
}

#[pymethods]
impl PySignatureReport {
    /// Digest verification results.
    #[getter]
    fn digests(&self) -> PyDigestReport {
        PyDigestReport(self.digest_report.clone())
    }

    /// List of per-signature verification results.
    #[getter]
    fn signatures(&self) -> Vec<PySignatureCheckResult> {
        self.sig_results
            .iter()
            .map(|(info, err)| PySignatureCheckResult {
                info: info.clone(),
                error_msg: err.clone(),
            })
            .collect()
    }

    /// True if digests are ok and at least one signature verified.
    fn is_ok(&self) -> bool {
        self.ok
    }

    /// Raise RuntimeError if any digest mismatched or no signature was verified.
    fn verify(&self) -> PyResult<()> {
        self.digest_report.result().map_err(to_pyerr)?;
        if self.sig_results.iter().any(|(_, err)| err.is_none()) {
            Ok(())
        } else {
            let last_err = self
                .sig_results
                .last()
                .and_then(|(_, err)| err.as_deref())
                .unwrap_or("no signature found");
            Err(PyRuntimeError::new_err(last_err.to_string()))
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "SignatureReport(is_ok={}, signatures={})",
            self.ok,
            self.sig_results.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// CompressionType
// ---------------------------------------------------------------------------

/// Compression algorithm for the package payload.
#[pyclass(name = "CompressionType", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, PartialEq, Hash)]
pub enum PyCompressionType {
    #[pyo3(name = "NONE")]
    None,
    Gzip,
    Zstd,
    Xz,
    Bzip2,
}

impl From<PyCompressionType> for crate::CompressionType {
    fn from(ct: PyCompressionType) -> Self {
        match ct {
            PyCompressionType::None => crate::CompressionType::None,
            PyCompressionType::Gzip => crate::CompressionType::Gzip,
            PyCompressionType::Zstd => crate::CompressionType::Zstd,
            PyCompressionType::Xz => crate::CompressionType::Xz,
            PyCompressionType::Bzip2 => crate::CompressionType::Bzip2,
        }
    }
}

// ---------------------------------------------------------------------------
// BuildConfig
// ---------------------------------------------------------------------------

/// RPM format version (v4 or v6).
#[pyclass(name = "RpmFormat", eq, eq_int, hash, frozen, from_py_object)]
#[derive(Clone, PartialEq, Hash)]
pub enum PyRpmFormat {
    V4 = 4,
    V6 = 6,
}

/// Configuration for building RPM packages.
///
/// All parameters are optional and have sensible defaults (v6 format, zstd compression).
///
/// Args:
///     format: RPM format version (RpmFormat.V4 or RpmFormat.V6). Default: V6.
///     compression: Compression algorithm (CompressionType). Default: Zstd.
///     compression_level: Compression level (integer). Default depends on algorithm.
///     source_date: Fixed timestamp (seconds since Unix epoch) for reproducible builds.
///     reserved_space: Size in bytes of reserved space for in-place re-signing.
///         If omitted, the library default (4128 bytes) is used. Pass `0` to
///         disable reserved space entirely (no tag is written).
#[pyclass(name = "BuildConfig")]
pub struct PyBuildConfig(crate::BuildConfig);

#[pymethods]
impl PyBuildConfig {
    #[new]
    #[pyo3(signature = (*, format=None, compression=None, compression_level=None, source_date=None, reserved_space=None))]
    fn new(
        format: Option<PyRpmFormat>,
        compression: Option<PyCompressionType>,
        compression_level: Option<i32>,
        source_date: Option<u32>,
        reserved_space: Option<u32>,
    ) -> Self {
        let mut config = match format {
            Some(PyRpmFormat::V4) => crate::BuildConfig::v4(),
            Some(PyRpmFormat::V6) | None => crate::BuildConfig::v6(),
        };

        if let Some(ct) = compression {
            let cwl = match (ct, compression_level) {
                (PyCompressionType::None, _) => crate::CompressionWithLevel::None,
                (PyCompressionType::Gzip, Some(l)) => crate::CompressionWithLevel::Gzip(l as u32),
                (PyCompressionType::Gzip, None) => crate::CompressionType::Gzip.into(),
                (PyCompressionType::Zstd, Some(l)) => crate::CompressionWithLevel::Zstd(l),
                (PyCompressionType::Zstd, None) => crate::CompressionType::Zstd.into(),
                (PyCompressionType::Xz, Some(l)) => crate::CompressionWithLevel::Xz(l as u32),
                (PyCompressionType::Xz, None) => crate::CompressionType::Xz.into(),
                (PyCompressionType::Bzip2, Some(l)) => crate::CompressionWithLevel::Bzip2(l as u32),
                (PyCompressionType::Bzip2, None) => crate::CompressionType::Bzip2.into(),
            };
            config = config.compression(cwl);
        }

        if let Some(ts) = source_date {
            config = config.source_date(ts);
        }

        if let Some(rs) = reserved_space {
            config = config.reserved_space(if rs == 0 { None } else { Some(rs) });
        }

        PyBuildConfig(config)
    }
}

// ---------------------------------------------------------------------------
// FileOptions
// ---------------------------------------------------------------------------

/// Options for a file entry in an RPM package (destination path, permissions, flags, etc.).
///
/// Use the static constructors to create the appropriate kind of file options:
/// - `FileOptions.new(path, ...)` for regular files
/// - `FileOptions.dir(path, ...)` for directories
/// - `FileOptions.symlink(path, target, ...)` for symbolic links
/// - `FileOptions.ghost(path, ...)` for ghost files
/// - `FileOptions.ghost_dir(path, ...)` for ghost directories
///
/// Common keyword arguments (all optional):
///     user: Owning user name.
///     group: Owning group name.
///     permissions: Permission bits (e.g. 0o755).
///     config: If True, mark as a configuration file.
///     noreplace: If True, mark as noreplace (only meaningful with config=True).
///     doc: If True, mark as documentation.
#[pyclass(name = "FileOptions")]
pub struct PyFileOptions(Option<crate::FileOptionsBuilder>);

impl PyFileOptions {
    fn take(&mut self) -> crate::FileOptionsBuilder {
        self.0
            .take()
            .expect("FileOptions has already been consumed")
    }
}

/// Apply common keyword arguments to a FileOptionsBuilder.
fn apply_file_options(
    mut builder: crate::FileOptionsBuilder,
    user: Option<&str>,
    group: Option<&str>,
    permissions: Option<u16>,
    caps: Option<&str>,
    config: bool,
    noreplace: bool,
    missingok: bool,
    doc: bool,
    license: bool,
    artifact: bool,
) -> Result<crate::FileOptionsBuilder, crate::Error> {
    if let Some(u) = user {
        builder = builder.user(u);
    }
    if let Some(g) = group {
        builder = builder.group(g);
    }
    if let Some(p) = permissions {
        builder = builder.permissions(p);
    }
    if let Some(c) = caps {
        builder = builder.caps(c)?;
    }
    if config {
        builder = builder.config();
    }
    if noreplace {
        builder = builder.noreplace();
    }
    if missingok {
        builder = builder.missingok();
    }
    if doc {
        builder = builder.doc();
    }
    if license {
        builder = builder.license();
    }
    if artifact {
        builder = builder.artifact();
    }
    Ok(builder)
}

#[pymethods]
impl PyFileOptions {
    /// Create options for a regular file at the given destination path.
    #[staticmethod]
    #[pyo3(name = "new", signature = (dest, *, user=None, group=None, permissions=None, caps=None, config=false, noreplace=false, missingok=false, doc=false, license=false, artifact=false))]
    fn new_file(
        dest: &str,
        user: Option<&str>,
        group: Option<&str>,
        permissions: Option<u16>,
        caps: Option<&str>,
        config: bool,
        noreplace: bool,
        missingok: bool,
        doc: bool,
        license: bool,
        artifact: bool,
    ) -> PyResult<Self> {
        apply_file_options(
            crate::FileOptions::new(dest),
            user,
            group,
            permissions,
            caps,
            config,
            noreplace,
            missingok,
            doc,
            license,
            artifact,
        )
        .map(|b| PyFileOptions(Some(b)))
        .map_err(to_pyerr)
    }

    /// Create options for a directory at the given destination path.
    #[staticmethod]
    #[pyo3(signature = (dest, *, user=None, group=None, permissions=None))]
    fn dir(
        dest: &str,
        user: Option<&str>,
        group: Option<&str>,
        permissions: Option<u16>,
    ) -> PyResult<Self> {
        apply_file_options(
            crate::FileOptions::dir(dest),
            user,
            group,
            permissions,
            None,
            false,
            false,
            false,
            false,
            false,
            false,
        )
        .map(|b| PyFileOptions(Some(b)))
        .map_err(to_pyerr)
    }

    /// Create options for a symbolic link.
    #[staticmethod]
    #[pyo3(signature = (dest, target, *, user=None, group=None))]
    fn symlink(
        dest: &str,
        target: &str,
        user: Option<&str>,
        group: Option<&str>,
    ) -> PyResult<Self> {
        apply_file_options(
            crate::FileOptions::symlink(dest, target),
            user,
            group,
            None,
            None,
            false,
            false,
            false,
            false,
            false,
            false,
        )
        .map(|b| PyFileOptions(Some(b)))
        .map_err(to_pyerr)
    }

    /// Create options for a ghost file (not in payload, but metadata is tracked).
    #[staticmethod]
    #[pyo3(signature = (dest, *, user=None, group=None, permissions=None))]
    fn ghost(
        dest: &str,
        user: Option<&str>,
        group: Option<&str>,
        permissions: Option<u16>,
    ) -> PyResult<Self> {
        apply_file_options(
            crate::FileOptions::ghost(dest),
            user,
            group,
            permissions,
            None,
            false,
            false,
            false,
            false,
            false,
            false,
        )
        .map(|b| PyFileOptions(Some(b)))
        .map_err(to_pyerr)
    }

    /// Create options for a ghost directory.
    #[staticmethod]
    #[pyo3(signature = (dest, *, user=None, group=None, permissions=None))]
    fn ghost_dir(
        dest: &str,
        user: Option<&str>,
        group: Option<&str>,
        permissions: Option<u16>,
    ) -> PyResult<Self> {
        apply_file_options(
            crate::FileOptions::ghost_dir(dest),
            user,
            group,
            permissions,
            None,
            false,
            false,
            false,
            false,
            false,
            false,
        )
        .map(|b| PyFileOptions(Some(b)))
        .map_err(to_pyerr)
    }
}

// ---------------------------------------------------------------------------
// PackageBuilder
// ---------------------------------------------------------------------------

/// A builder for constructing RPM packages programmatically.
///
/// Use `PackageBuilder(name, version, license, arch)` to create a new builder,
/// then chain builder methods to add metadata, files, dependencies, and scripts.
/// Finally, call `.build()` or `.build_and_sign(signer)` to produce a `Package`.
#[pyclass(name = "PackageBuilder")]
pub struct PyPackageBuilder(crate::PackageBuilder);

#[pymethods]
impl PyPackageBuilder {
    /// Create a new package builder with the required metadata.
    #[new]
    #[pyo3(signature = (name, version, license, arch, summary=""))]
    fn new(name: &str, version: &str, license: &str, arch: &str, summary: &str) -> Self {
        PyPackageBuilder(crate::PackageBuilder::new(
            name, version, license, arch, summary,
        ))
    }

    /// Set the package description.
    fn description(&mut self, desc: &str) {
        self.0.description(desc);
    }

    /// Set the package release string.
    fn release(&mut self, release: &str) {
        self.0.release(release);
    }

    /// Set the package epoch.
    fn epoch(&mut self, epoch: u32) {
        self.0.epoch(epoch);
    }

    /// Set the package URL.
    fn url(&mut self, url: &str) {
        self.0.url(url);
    }

    /// Set the VCS URL.
    fn vcs(&mut self, vcs: &str) {
        self.0.vcs(vcs);
    }

    /// Set the package vendor.
    fn vendor(&mut self, vendor: &str) {
        self.0.vendor(vendor);
    }

    /// Set the packager name.
    fn packager(&mut self, packager: &str) {
        self.0.packager(packager);
    }

    /// Set the package group (deprecated in most packaging guidelines).
    fn group(&mut self, group: &str) {
        self.0.group(group);
    }

    /// Set the build host name.
    fn build_host(&mut self, host: &str) {
        self.0.build_host(host);
    }

    /// Set the build cookie.
    fn cookie(&mut self, cookie: &str) {
        self.0.cookie(cookie);
    }

    /// Set default ownership and permissions for regular file entries.
    ///
    /// These defaults are applied to files where user/group/permissions have
    /// not been explicitly set on the FileOptions. Pass None for any field
    /// to leave its current default unchanged.
    #[pyo3(signature = (*, permissions=None, user=None, group=None))]
    fn default_file_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) {
        self.0.default_file_attrs(permissions, user, group);
    }

    /// Set default ownership and permissions for directory entries.
    ///
    /// These defaults are applied to directories where user/group/permissions
    /// have not been explicitly set on the FileOptions. Pass None for any field
    /// to leave its current default unchanged.
    #[pyo3(signature = (*, permissions=None, user=None, group=None))]
    fn default_dir_attrs(
        &mut self,
        permissions: Option<u16>,
        user: Option<String>,
        group: Option<String>,
    ) {
        self.0.default_dir_attrs(permissions, user, group);
    }

    /// Set the build configuration.
    fn using_config(&mut self, config: &PyBuildConfig) {
        self.0.using_config(config.0);
    }

    /// Add a file from disk to the package.
    fn with_file(&mut self, source: &str, options: &mut PyFileOptions) -> PyResult<()> {
        self.0.with_file(source, options.take()).map_err(to_pyerr)?;
        Ok(())
    }

    /// Add a file from in-memory content.
    fn with_file_contents(&mut self, content: &[u8], options: &mut PyFileOptions) -> PyResult<()> {
        self.0
            .with_file_contents(content.to_vec(), options.take())
            .map_err(to_pyerr)?;
        Ok(())
    }

    /// Add a directory entry (no content, just metadata).
    fn with_dir_entry(&mut self, options: &mut PyFileOptions) -> PyResult<()> {
        self.0.with_dir_entry(options.take()).map_err(to_pyerr)?;
        Ok(())
    }

    /// Add a symbolic link entry.
    fn with_symlink(&mut self, options: &mut PyFileOptions) -> PyResult<()> {
        self.0.with_symlink(options.take()).map_err(to_pyerr)?;
        Ok(())
    }

    /// Add a ghost file entry (tracked by RPM but not in the payload).
    fn with_ghost(&mut self, options: &mut PyFileOptions) -> PyResult<()> {
        self.0.with_ghost(options.take()).map_err(to_pyerr)?;
        Ok(())
    }

    /// Add an entire directory tree from disk to the package.
    ///
    /// All files and subdirectories under source_dir are added recursively,
    /// with destination paths rooted at dest_prefix.
    #[pyo3(signature = (source_dir, dest_prefix, *, user=None, group=None, permissions=None, caps=None, config=false, noreplace=false, missingok=false, doc=false, license=false, artifact=false))]
    fn with_dir(
        &mut self,
        source_dir: &str,
        dest_prefix: &str,
        user: Option<String>,
        group: Option<String>,
        permissions: Option<u16>,
        caps: Option<String>,
        config: bool,
        noreplace: bool,
        missingok: bool,
        doc: bool,
        license: bool,
        artifact: bool,
    ) -> PyResult<()> {
        // Validate caps upfront since the closure can't return Result
        if let Some(ref c) = caps {
            crate::FileOptions::new("/validate")
                .caps(c)
                .map_err(to_pyerr)?;
        }
        self.0
            .with_dir(source_dir, dest_prefix, |opts| {
                // caps was already validated above, so unwrap is safe
                apply_file_options(
                    opts,
                    user.as_deref(),
                    group.as_deref(),
                    permissions,
                    caps.as_deref(),
                    config,
                    noreplace,
                    missingok,
                    doc,
                    license,
                    artifact,
                )
                .unwrap()
            })
            .map_err(to_pyerr)?;
        Ok(())
    }

    /// Add a Requires dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn requires(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.requires(make_dependency(name, version, flags));
    }

    /// Add a Provides dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn provides(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.provides(make_dependency(name, version, flags));
    }

    /// Add a Conflicts dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn conflicts(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.conflicts(make_dependency(name, version, flags));
    }

    /// Add an Obsoletes dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn obsoletes(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.obsoletes(make_dependency(name, version, flags));
    }

    /// Add a Recommends dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn recommends(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.recommends(make_dependency(name, version, flags));
    }

    /// Add a Suggests dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn suggests(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.suggests(make_dependency(name, version, flags));
    }

    /// Add an Enhances dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn enhances(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.enhances(make_dependency(name, version, flags));
    }

    /// Add a Supplements dependency.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn supplements(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0.supplements(make_dependency(name, version, flags));
    }

    /// Add an ordering hint for package installation/upgrade.
    #[pyo3(signature = (name, version=None, flags=None))]
    fn order_with_requires(&mut self, name: &str, version: Option<&str>, flags: Option<u32>) {
        self.0
            .order_with_requires(make_dependency(name, version, flags));
    }

    /// Add a changelog entry.
    fn add_changelog_entry(&mut self, name: &str, description: &str, timestamp: u32) {
        self.0.add_changelog_entry(name, description, timestamp);
    }

    /// Set the pre-install scriptlet.
    fn pre_install_script(&mut self, script: &str) {
        self.0.pre_install_script(script);
    }

    /// Set the post-install scriptlet.
    fn post_install_script(&mut self, script: &str) {
        self.0.post_install_script(script);
    }

    /// Set the pre-uninstall scriptlet.
    fn pre_uninstall_script(&mut self, script: &str) {
        self.0.pre_uninstall_script(script);
    }

    /// Set the post-uninstall scriptlet.
    fn post_uninstall_script(&mut self, script: &str) {
        self.0.post_uninstall_script(script);
    }

    /// Set the pre-transaction scriptlet.
    fn pre_trans_script(&mut self, script: &str) {
        self.0.pre_trans_script(script);
    }

    /// Set the post-transaction scriptlet.
    fn post_trans_script(&mut self, script: &str) {
        self.0.post_trans_script(script);
    }

    /// Set the pre-untransaction scriptlet.
    fn pre_untrans_script(&mut self, script: &str) {
        self.0.pre_untrans_script(script);
    }

    /// Set the post-untransaction scriptlet.
    fn post_untrans_script(&mut self, script: &str) {
        self.0.post_untrans_script(script);
    }

    /// Set the verification scriptlet.
    fn verify_script(&mut self, script: &str) {
        self.0.verify_script(script);
    }

    // --- Triggers ---

    /// Add a `%triggerin` script that fires when the target package is installed.
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn trigger_in(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.trigger_in(target, condition, script);
    }

    /// Add a `%triggerun` script that fires just before the target package is removed.
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn trigger_un(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.trigger_un(target, condition, script);
    }

    /// Add a `%triggerpostun` script that fires after the target package is removed.
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn trigger_postun(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.trigger_postun(target, condition, script);
    }

    /// Add a `%triggerprein` script that fires just before the target package is installed.
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn trigger_prein(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.trigger_prein(target, condition, script);
    }

    /// Add a `%filetriggerin` script that fires when a file matching the target path is installed.
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn file_trigger_in(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.file_trigger_in(target, condition, script);
    }

    /// Add a `%filetriggerun` script that fires when a file matching the target path is removed.
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn file_trigger_un(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.file_trigger_un(target, condition, script);
    }

    /// Add a `%filetriggerpostun` script that fires after a file matching the target path is removed.
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn file_trigger_postun(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.file_trigger_postun(target, condition, script);
    }

    /// Add a `%transfiletriggerin` script (transactional file trigger on install).
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn trans_file_trigger_in(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.trans_file_trigger_in(target, condition, script);
    }

    /// Add a `%transfiletriggerun` script (transactional file trigger on uninstall).
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn trans_file_trigger_un(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.trans_file_trigger_un(target, condition, script);
    }

    /// Add a `%transfiletriggerpostun` script (transactional file trigger after uninstall).
    #[pyo3(signature = (target, script, flags=None, version=None))]
    fn trans_file_trigger_postun(
        &mut self,
        target: &str,
        script: &str,
        flags: Option<u32>,
        version: Option<&str>,
    ) {
        let condition = make_trigger_condition(flags, version);
        self.0.trans_file_trigger_postun(target, condition, script);
    }

    /// Build the package and return a `Package` object.
    fn build(&mut self) -> PyResult<PyPackage> {
        self.0.build().map(PyPackage).map_err(to_pyerr)
    }

    /// Build the package, signing it with the provided `Signer`.
    fn build_and_sign(&mut self, signer: &PySigner) -> PyResult<PyPackage> {
        self.0
            .build_and_sign(signer.0.clone())
            .map(PyPackage)
            .map_err(to_pyerr)
    }
}

/// Helper to construct a trigger condition from optional Python arguments.
fn make_trigger_condition(
    flags: Option<u32>,
    version: Option<&str>,
) -> Option<(crate::DependencyFlags, &str)> {
    match (flags, version) {
        (Some(f), Some(v)) => Some((crate::DependencyFlags::from_bits_retain(f), v)),
        _ => None,
    }
}

/// Helper to construct a Dependency from Python arguments.
fn make_dependency(name: &str, version: Option<&str>, flags: Option<u32>) -> crate::Dependency {
    match (version, flags) {
        (Some(v), Some(f)) => crate::Dependency {
            name: name.to_string(),
            version: v.to_string(),
            flags: crate::DependencyFlags::from_bits_retain(f),
        },
        (Some(v), None) => crate::Dependency::eq(name, v),
        _ => crate::Dependency::any(name),
    }
}

/// Convert an IndexData value to a native Python object.
fn index_data_to_py(py: Python<'_>, data: crate::IndexData) -> PyResult<Py<PyAny>> {
    use crate::IndexData;
    Ok(match data {
        IndexData::Null => py.None(),
        IndexData::Char(v) | IndexData::Int8(v) | IndexData::Bin(v) => v.into_pyobject(py)?.into(),
        IndexData::Int16(v) => v.into_pyobject(py)?.into(),
        IndexData::Int32(v) => v.into_pyobject(py)?.into(),
        IndexData::Int64(v) => v.into_pyobject(py)?.into(),
        IndexData::StringTag(s) => s.into_pyobject(py)?.into(),
        IndexData::StringArray(v) | IndexData::I18NString(v) => v.into_pyobject(py)?.into(),
    })
}

/// Create a Python `IntFlag` subclass with the given name and members.
///
/// `members` is a slice of `(name, value)` pairs. Returns the new class object.
fn make_int_flag<'py>(
    py: Python<'py>,
    name: &str,
    members: &[(&str, u32)],
) -> PyResult<Bound<'py, PyAny>> {
    let enum_mod = py.import("enum")?;
    let int_flag = enum_mod.getattr("IntFlag")?;
    let kwargs = PyDict::new(py);
    for &(member_name, value) in members {
        kwargs.set_item(member_name, value)?;
    }
    int_flag.call((name, kwargs), None)
}

/// Create a Python `IntEnum` subclass with the given name and members.
fn make_int_enum<'py>(
    py: Python<'py>,
    name: &str,
    members: &[(&str, u32)],
) -> PyResult<Bound<'py, PyAny>> {
    let enum_mod = py.import("enum")?;
    let int_enum = enum_mod.getattr("IntEnum")?;
    let kwargs = PyDict::new(py);
    for &(member_name, value) in members {
        kwargs.set_item(member_name, value)?;
    }
    int_enum.call((name, kwargs), None)
}

// ---------------------------------------------------------------------------
// Module registration
// ---------------------------------------------------------------------------

/// Python module exporting rpm-rs package reading functionality.
///
/// Register all public types with the Python interpreter.
#[pymodule]
pub fn rpm_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyPackage>()?;
    m.add_class::<PyPackageMetadata>()?;
    m.add_class::<PyHeader>()?;
    m.add_class::<PyPackageSegmentOffsets>()?;
    m.add_class::<PyRpmFile>()?;
    m.add_class::<PyEvr>()?;
    m.add_class::<PyNevra>()?;
    m.add_class::<PyDependency>()?;
    m.add_class::<PyFileEntry>()?;
    m.add_class::<PyFileType>()?;
    m.add_class::<PyFileMode>()?;
    m.add_class::<PyFileDigest>()?;
    m.add_class::<PyFileOwnership>()?;
    m.add_class::<PyChangelogEntry>()?;
    m.add_class::<PyScriptlet>()?;
    m.add_class::<PyTrigger>()?;
    m.add_class::<PyTriggerCondition>()?;
    m.add_class::<PyDigestAlgorithm>()?;
    m.add_class::<PyCompressionType>()?;
    m.add_class::<PyRpmFormat>()?;
    m.add_class::<PyBuildConfig>()?;
    m.add_class::<PyFileOptions>()?;
    m.add_class::<PyPackageBuilder>()?;
    m.add_class::<PySigner>()?;
    m.add_class::<PyVerifier>()?;
    m.add_class::<PySignatureVersion>()?;
    m.add_class::<PySignatureInfo>()?;
    m.add_class::<PyDigestStatus>()?;
    m.add_class::<PyDigestReport>()?;
    m.add_class::<PySignatureCheckResult>()?;
    m.add_class::<PySignatureReport>()?;
    m.add_function(wrap_pyfunction!(evr_compare, m)?)?;

    // Tag enums for raw header access
    m.add(
        "Tag",
        make_int_enum(
            m.py(),
            "Tag",
            &[
                ("HEADERIMAGE", crate::IndexTag::RPMTAG_HEADERIMAGE as u32),
                (
                    "HEADERSIGNATURES",
                    crate::IndexTag::RPMTAG_HEADERSIGNATURES as u32,
                ),
                (
                    "HEADERIMMUTABLE",
                    crate::IndexTag::RPMTAG_HEADERIMMUTABLE as u32,
                ),
                (
                    "HEADERREGIONS",
                    crate::IndexTag::RPMTAG_HEADERREGIONS as u32,
                ),
                (
                    "HEADERI18NTABLE",
                    crate::IndexTag::RPMTAG_HEADERI18NTABLE as u32,
                ),
                ("SIGSIZE", crate::IndexTag::RPMTAG_SIGSIZE as u32),
                ("SIGLEMD5_1", crate::IndexTag::RPMTAG_SIGLEMD5_1 as u32),
                ("SIGPGP", crate::IndexTag::RPMTAG_SIGPGP as u32),
                ("SIGLEMD5_2", crate::IndexTag::RPMTAG_SIGLEMD5_2 as u32),
                ("SIGMD5", crate::IndexTag::RPMTAG_SIGMD5 as u32),
                ("SIGGPG", crate::IndexTag::RPMTAG_SIGGPG as u32),
                ("SIGPGP5", crate::IndexTag::RPMTAG_SIGPGP5 as u32),
                ("BADSHA1_1", crate::IndexTag::RPMTAG_BADSHA1_1 as u32),
                ("BADSHA1_2", crate::IndexTag::RPMTAG_BADSHA1_2 as u32),
                ("PUBKEYS", crate::IndexTag::RPMTAG_PUBKEYS as u32),
                ("DSAHEADER", crate::IndexTag::RPMTAG_DSAHEADER as u32),
                ("RSAHEADER", crate::IndexTag::RPMTAG_RSAHEADER as u32),
                ("SHA1HEADER", crate::IndexTag::RPMTAG_SHA1HEADER as u32),
                ("LONGSIGSIZE", crate::IndexTag::RPMTAG_LONGSIGSIZE as u32),
                (
                    "LONGARCHIVESIZE",
                    crate::IndexTag::RPMTAG_LONGARCHIVESIZE as u32,
                ),
                ("SHA256HEADER", crate::IndexTag::RPMTAG_SHA256HEADER as u32),
                (
                    "VERITYSIGNATURES",
                    crate::IndexTag::RPMTAG_VERITYSIGNATURES as u32,
                ),
                (
                    "VERITYSIGNATUREALGO",
                    crate::IndexTag::RPMTAG_VERITYSIGNATUREALGO as u32,
                ),
                ("OPENPGP", crate::IndexTag::RPMTAG_OPENPGP as u32),
                (
                    "SHA3_256_HEADER",
                    crate::IndexTag::RPMTAG_SHA3_256_HEADER as u32,
                ),
                ("NAME", crate::IndexTag::RPMTAG_NAME as u32),
                ("VERSION", crate::IndexTag::RPMTAG_VERSION as u32),
                ("RELEASE", crate::IndexTag::RPMTAG_RELEASE as u32),
                ("EPOCH", crate::IndexTag::RPMTAG_EPOCH as u32),
                ("SUMMARY", crate::IndexTag::RPMTAG_SUMMARY as u32),
                ("DESCRIPTION", crate::IndexTag::RPMTAG_DESCRIPTION as u32),
                ("BUILDTIME", crate::IndexTag::RPMTAG_BUILDTIME as u32),
                ("BUILDHOST", crate::IndexTag::RPMTAG_BUILDHOST as u32),
                ("INSTALLTIME", crate::IndexTag::RPMTAG_INSTALLTIME as u32),
                ("SIZE", crate::IndexTag::RPMTAG_SIZE as u32),
                ("DISTRIBUTION", crate::IndexTag::RPMTAG_DISTRIBUTION as u32),
                ("VENDOR", crate::IndexTag::RPMTAG_VENDOR as u32),
                ("GIF", crate::IndexTag::RPMTAG_GIF as u32),
                ("XPM", crate::IndexTag::RPMTAG_XPM as u32),
                ("LICENSE", crate::IndexTag::RPMTAG_LICENSE as u32),
                ("PACKAGER", crate::IndexTag::RPMTAG_PACKAGER as u32),
                ("GROUP", crate::IndexTag::RPMTAG_GROUP as u32),
                ("CHANGELOG", crate::IndexTag::RPMTAG_CHANGELOG as u32),
                ("SOURCE", crate::IndexTag::RPMTAG_SOURCE as u32),
                ("PATCH", crate::IndexTag::RPMTAG_PATCH as u32),
                ("URL", crate::IndexTag::RPMTAG_URL as u32),
                ("OS", crate::IndexTag::RPMTAG_OS as u32),
                ("ARCH", crate::IndexTag::RPMTAG_ARCH as u32),
                ("PREIN", crate::IndexTag::RPMTAG_PREIN as u32),
                ("POSTIN", crate::IndexTag::RPMTAG_POSTIN as u32),
                ("PREUN", crate::IndexTag::RPMTAG_PREUN as u32),
                ("POSTUN", crate::IndexTag::RPMTAG_POSTUN as u32),
                ("OLDFILENAMES", crate::IndexTag::RPMTAG_OLDFILENAMES as u32),
                ("FILESIZES", crate::IndexTag::RPMTAG_FILESIZES as u32),
                ("FILESTATES", crate::IndexTag::RPMTAG_FILESTATES as u32),
                ("FILEMODES", crate::IndexTag::RPMTAG_FILEMODES as u32),
                ("FILEUIDS", crate::IndexTag::RPMTAG_FILEUIDS as u32),
                ("FILEGIDS", crate::IndexTag::RPMTAG_FILEGIDS as u32),
                ("FILERDEVS", crate::IndexTag::RPMTAG_FILERDEVS as u32),
                ("FILEMTIMES", crate::IndexTag::RPMTAG_FILEMTIMES as u32),
                ("FILEDIGESTS", crate::IndexTag::RPMTAG_FILEDIGESTS as u32),
                ("FILELINKTOS", crate::IndexTag::RPMTAG_FILELINKTOS as u32),
                ("FILEFLAGS", crate::IndexTag::RPMTAG_FILEFLAGS as u32),
                ("ROOT", crate::IndexTag::RPMTAG_ROOT as u32),
                ("FILEUSERNAME", crate::IndexTag::RPMTAG_FILEUSERNAME as u32),
                (
                    "FILEGROUPNAME",
                    crate::IndexTag::RPMTAG_FILEGROUPNAME as u32,
                ),
                ("EXCLUDE", crate::IndexTag::RPMTAG_EXCLUDE as u32),
                ("EXCLUSIVE", crate::IndexTag::RPMTAG_EXCLUSIVE as u32),
                ("ICON", crate::IndexTag::RPMTAG_ICON as u32),
                ("SOURCERPM", crate::IndexTag::RPMTAG_SOURCERPM as u32),
                (
                    "FILEVERIFYFLAGS",
                    crate::IndexTag::RPMTAG_FILEVERIFYFLAGS as u32,
                ),
                ("ARCHIVESIZE", crate::IndexTag::RPMTAG_ARCHIVESIZE as u32),
                ("PROVIDENAME", crate::IndexTag::RPMTAG_PROVIDENAME as u32),
                ("REQUIREFLAGS", crate::IndexTag::RPMTAG_REQUIREFLAGS as u32),
                ("REQUIRENAME", crate::IndexTag::RPMTAG_REQUIRENAME as u32),
                (
                    "REQUIREVERSION",
                    crate::IndexTag::RPMTAG_REQUIREVERSION as u32,
                ),
                ("NOSOURCE", crate::IndexTag::RPMTAG_NOSOURCE as u32),
                ("NOPATCH", crate::IndexTag::RPMTAG_NOPATCH as u32),
                (
                    "CONFLICTFLAGS",
                    crate::IndexTag::RPMTAG_CONFLICTFLAGS as u32,
                ),
                ("CONFLICTNAME", crate::IndexTag::RPMTAG_CONFLICTNAME as u32),
                (
                    "CONFLICTVERSION",
                    crate::IndexTag::RPMTAG_CONFLICTVERSION as u32,
                ),
                (
                    "DEFAULTPREFIX",
                    crate::IndexTag::RPMTAG_DEFAULTPREFIX as u32,
                ),
                ("BUILDROOT", crate::IndexTag::RPMTAG_BUILDROOT as u32),
                (
                    "INSTALLPREFIX",
                    crate::IndexTag::RPMTAG_INSTALLPREFIX as u32,
                ),
                ("EXCLUDEARCH", crate::IndexTag::RPMTAG_EXCLUDEARCH as u32),
                ("EXCLUDEOS", crate::IndexTag::RPMTAG_EXCLUDEOS as u32),
                (
                    "EXCLUSIVEARCH",
                    crate::IndexTag::RPMTAG_EXCLUSIVEARCH as u32,
                ),
                ("EXCLUSIVEOS", crate::IndexTag::RPMTAG_EXCLUSIVEOS as u32),
                ("AUTOREQPROV", crate::IndexTag::RPMTAG_AUTOREQPROV as u32),
                ("RPMVERSION", crate::IndexTag::RPMTAG_RPMVERSION as u32),
                (
                    "TRIGGERSCRIPTS",
                    crate::IndexTag::RPMTAG_TRIGGERSCRIPTS as u32,
                ),
                ("TRIGGERNAME", crate::IndexTag::RPMTAG_TRIGGERNAME as u32),
                (
                    "TRIGGERVERSION",
                    crate::IndexTag::RPMTAG_TRIGGERVERSION as u32,
                ),
                ("TRIGGERFLAGS", crate::IndexTag::RPMTAG_TRIGGERFLAGS as u32),
                ("TRIGGERINDEX", crate::IndexTag::RPMTAG_TRIGGERINDEX as u32),
                ("VERIFYSCRIPT", crate::IndexTag::RPMTAG_VERIFYSCRIPT as u32),
                (
                    "CHANGELOGTIME",
                    crate::IndexTag::RPMTAG_CHANGELOGTIME as u32,
                ),
                (
                    "CHANGELOGNAME",
                    crate::IndexTag::RPMTAG_CHANGELOGNAME as u32,
                ),
                (
                    "CHANGELOGTEXT",
                    crate::IndexTag::RPMTAG_CHANGELOGTEXT as u32,
                ),
                ("BROKENMD5", crate::IndexTag::RPMTAG_BROKENMD5 as u32),
                ("PREREQ", crate::IndexTag::RPMTAG_PREREQ as u32),
                ("PREINPROG", crate::IndexTag::RPMTAG_PREINPROG as u32),
                ("POSTINPROG", crate::IndexTag::RPMTAG_POSTINPROG as u32),
                ("PREUNPROG", crate::IndexTag::RPMTAG_PREUNPROG as u32),
                ("POSTUNPROG", crate::IndexTag::RPMTAG_POSTUNPROG as u32),
                ("BUILDARCHS", crate::IndexTag::RPMTAG_BUILDARCHS as u32),
                ("OBSOLETENAME", crate::IndexTag::RPMTAG_OBSOLETENAME as u32),
                (
                    "VERIFYSCRIPTPROG",
                    crate::IndexTag::RPMTAG_VERIFYSCRIPTPROG as u32,
                ),
                (
                    "TRIGGERSCRIPTPROG",
                    crate::IndexTag::RPMTAG_TRIGGERSCRIPTPROG as u32,
                ),
                ("DOCDIR", crate::IndexTag::RPMTAG_DOCDIR as u32),
                ("COOKIE", crate::IndexTag::RPMTAG_COOKIE as u32),
                ("FILEDEVICES", crate::IndexTag::RPMTAG_FILEDEVICES as u32),
                ("FILEINODES", crate::IndexTag::RPMTAG_FILEINODES as u32),
                ("FILELANGS", crate::IndexTag::RPMTAG_FILELANGS as u32),
                ("PREFIXES", crate::IndexTag::RPMTAG_PREFIXES as u32),
                ("INSTPREFIXES", crate::IndexTag::RPMTAG_INSTPREFIXES as u32),
                ("TRIGGERIN", crate::IndexTag::RPMTAG_TRIGGERIN as u32),
                ("TRIGGERUN", crate::IndexTag::RPMTAG_TRIGGERUN as u32),
                (
                    "TRIGGERPOSTUN",
                    crate::IndexTag::RPMTAG_TRIGGERPOSTUN as u32,
                ),
                ("AUTOREQ", crate::IndexTag::RPMTAG_AUTOREQ as u32),
                ("AUTOPROV", crate::IndexTag::RPMTAG_AUTOPROV as u32),
                ("CAPABILITY", crate::IndexTag::RPMTAG_CAPABILITY as u32),
                (
                    "SOURCEPACKAGE",
                    crate::IndexTag::RPMTAG_SOURCEPACKAGE as u32,
                ),
                (
                    "OLDORIGFILENAMES",
                    crate::IndexTag::RPMTAG_OLDORIGFILENAMES as u32,
                ),
                ("BUILDPREREQ", crate::IndexTag::RPMTAG_BUILDPREREQ as u32),
                (
                    "BUILDREQUIRES",
                    crate::IndexTag::RPMTAG_BUILDREQUIRES as u32,
                ),
                (
                    "BUILDCONFLICTS",
                    crate::IndexTag::RPMTAG_BUILDCONFLICTS as u32,
                ),
                ("BUILDMACROS", crate::IndexTag::RPMTAG_BUILDMACROS as u32),
                ("PROVIDEFLAGS", crate::IndexTag::RPMTAG_PROVIDEFLAGS as u32),
                (
                    "PROVIDEVERSION",
                    crate::IndexTag::RPMTAG_PROVIDEVERSION as u32,
                ),
                (
                    "OBSOLETEFLAGS",
                    crate::IndexTag::RPMTAG_OBSOLETEFLAGS as u32,
                ),
                (
                    "OBSOLETEVERSION",
                    crate::IndexTag::RPMTAG_OBSOLETEVERSION as u32,
                ),
                ("DIRINDEXES", crate::IndexTag::RPMTAG_DIRINDEXES as u32),
                ("BASENAMES", crate::IndexTag::RPMTAG_BASENAMES as u32),
                ("DIRNAMES", crate::IndexTag::RPMTAG_DIRNAMES as u32),
                (
                    "ORIGDIRINDEXES",
                    crate::IndexTag::RPMTAG_ORIGDIRINDEXES as u32,
                ),
                (
                    "ORIGBASENAMES",
                    crate::IndexTag::RPMTAG_ORIGBASENAMES as u32,
                ),
                ("ORIGDIRNAMES", crate::IndexTag::RPMTAG_ORIGDIRNAMES as u32),
                ("OPTFLAGS", crate::IndexTag::RPMTAG_OPTFLAGS as u32),
                ("DISTURL", crate::IndexTag::RPMTAG_DISTURL as u32),
                (
                    "PAYLOADFORMAT",
                    crate::IndexTag::RPMTAG_PAYLOADFORMAT as u32,
                ),
                (
                    "PAYLOADCOMPRESSOR",
                    crate::IndexTag::RPMTAG_PAYLOADCOMPRESSOR as u32,
                ),
                ("PAYLOADFLAGS", crate::IndexTag::RPMTAG_PAYLOADFLAGS as u32),
                ("INSTALLCOLOR", crate::IndexTag::RPMTAG_INSTALLCOLOR as u32),
                ("INSTALLTID", crate::IndexTag::RPMTAG_INSTALLTID as u32),
                ("REMOVETID", crate::IndexTag::RPMTAG_REMOVETID as u32),
                ("SHA1RHN", crate::IndexTag::RPMTAG_SHA1RHN as u32),
                ("RHNPLATFORM", crate::IndexTag::RPMTAG_RHNPLATFORM as u32),
                ("PLATFORM", crate::IndexTag::RPMTAG_PLATFORM as u32),
                ("PATCHESNAME", crate::IndexTag::RPMTAG_PATCHESNAME as u32),
                ("PATCHESFLAGS", crate::IndexTag::RPMTAG_PATCHESFLAGS as u32),
                (
                    "PATCHESVERSION",
                    crate::IndexTag::RPMTAG_PATCHESVERSION as u32,
                ),
                ("CACHECTIME", crate::IndexTag::RPMTAG_CACHECTIME as u32),
                ("CACHEPKGPATH", crate::IndexTag::RPMTAG_CACHEPKGPATH as u32),
                ("CACHEPKGSIZE", crate::IndexTag::RPMTAG_CACHEPKGSIZE as u32),
                (
                    "CACHEPKGMTIME",
                    crate::IndexTag::RPMTAG_CACHEPKGMTIME as u32,
                ),
                ("FILECOLORS", crate::IndexTag::RPMTAG_FILECOLORS as u32),
                ("FILECLASS", crate::IndexTag::RPMTAG_FILECLASS as u32),
                ("CLASSDICT", crate::IndexTag::RPMTAG_CLASSDICT as u32),
                ("FILEDEPENDSX", crate::IndexTag::RPMTAG_FILEDEPENDSX as u32),
                ("FILEDEPENDSN", crate::IndexTag::RPMTAG_FILEDEPENDSN as u32),
                ("DEPENDSDICT", crate::IndexTag::RPMTAG_DEPENDSDICT as u32),
                ("SOURCESIGMD5", crate::IndexTag::RPMTAG_SOURCESIGMD5 as u32),
                ("FILECONTEXTS", crate::IndexTag::RPMTAG_FILECONTEXTS as u32),
                ("FSCONTEXTS", crate::IndexTag::RPMTAG_FSCONTEXTS as u32),
                ("RECONTEXTS", crate::IndexTag::RPMTAG_RECONTEXTS as u32),
                ("POLICIES", crate::IndexTag::RPMTAG_POLICIES as u32),
                ("PRETRANS", crate::IndexTag::RPMTAG_PRETRANS as u32),
                ("POSTTRANS", crate::IndexTag::RPMTAG_POSTTRANS as u32),
                ("PRETRANSPROG", crate::IndexTag::RPMTAG_PRETRANSPROG as u32),
                (
                    "POSTTRANSPROG",
                    crate::IndexTag::RPMTAG_POSTTRANSPROG as u32,
                ),
                ("DISTTAG", crate::IndexTag::RPMTAG_DISTTAG as u32),
                (
                    "OLDSUGGESTSNAME",
                    crate::IndexTag::RPMTAG_OLDSUGGESTSNAME as u32,
                ),
                (
                    "OLDSUGGESTSVERSION",
                    crate::IndexTag::RPMTAG_OLDSUGGESTSVERSION as u32,
                ),
                (
                    "OLDSUGGESTSFLAGS",
                    crate::IndexTag::RPMTAG_OLDSUGGESTSFLAGS as u32,
                ),
                (
                    "OLDENHANCESNAME",
                    crate::IndexTag::RPMTAG_OLDENHANCESNAME as u32,
                ),
                (
                    "OLDENHANCESVERSION",
                    crate::IndexTag::RPMTAG_OLDENHANCESVERSION as u32,
                ),
                (
                    "OLDENHANCESFLAGS",
                    crate::IndexTag::RPMTAG_OLDENHANCESFLAGS as u32,
                ),
                ("PRIORITY", crate::IndexTag::RPMTAG_PRIORITY as u32),
                ("CVSID", crate::IndexTag::RPMTAG_CVSID as u32),
                ("BLINKPKGID", crate::IndexTag::RPMTAG_BLINKPKGID as u32),
                ("BLINKHDRID", crate::IndexTag::RPMTAG_BLINKHDRID as u32),
                ("BLINKNEVRA", crate::IndexTag::RPMTAG_BLINKNEVRA as u32),
                ("FLINKPKGID", crate::IndexTag::RPMTAG_FLINKPKGID as u32),
                ("FLINKHDRID", crate::IndexTag::RPMTAG_FLINKHDRID as u32),
                ("FLINKNEVRA", crate::IndexTag::RPMTAG_FLINKNEVRA as u32),
                (
                    "PACKAGEORIGIN",
                    crate::IndexTag::RPMTAG_PACKAGEORIGIN as u32,
                ),
                ("TRIGGERPREIN", crate::IndexTag::RPMTAG_TRIGGERPREIN as u32),
                (
                    "BUILDSUGGESTS",
                    crate::IndexTag::RPMTAG_BUILDSUGGESTS as u32,
                ),
                (
                    "BUILDENHANCES",
                    crate::IndexTag::RPMTAG_BUILDENHANCES as u32,
                ),
                ("SCRIPTSTATES", crate::IndexTag::RPMTAG_SCRIPTSTATES as u32),
                (
                    "SCRIPTMETRICS",
                    crate::IndexTag::RPMTAG_SCRIPTMETRICS as u32,
                ),
                (
                    "BUILDCPUCLOCK",
                    crate::IndexTag::RPMTAG_BUILDCPUCLOCK as u32,
                ),
                (
                    "FILEDIGESTALGOS",
                    crate::IndexTag::RPMTAG_FILEDIGESTALGOS as u32,
                ),
                ("VARIANTS", crate::IndexTag::RPMTAG_VARIANTS as u32),
                ("XMAJOR", crate::IndexTag::RPMTAG_XMAJOR as u32),
                ("XMINOR", crate::IndexTag::RPMTAG_XMINOR as u32),
                ("REPOTAG", crate::IndexTag::RPMTAG_REPOTAG as u32),
                ("KEYWORDS", crate::IndexTag::RPMTAG_KEYWORDS as u32),
                (
                    "BUILDPLATFORMS",
                    crate::IndexTag::RPMTAG_BUILDPLATFORMS as u32,
                ),
                ("PACKAGECOLOR", crate::IndexTag::RPMTAG_PACKAGECOLOR as u32),
                (
                    "PACKAGEPREFCOLOR",
                    crate::IndexTag::RPMTAG_PACKAGEPREFCOLOR as u32,
                ),
                ("XATTRSDICT", crate::IndexTag::RPMTAG_XATTRSDICT as u32),
                ("FILEXATTRSX", crate::IndexTag::RPMTAG_FILEXATTRSX as u32),
                ("DEPATTRSDICT", crate::IndexTag::RPMTAG_DEPATTRSDICT as u32),
                (
                    "CONFLICTATTRSX",
                    crate::IndexTag::RPMTAG_CONFLICTATTRSX as u32,
                ),
                (
                    "OBSOLETEATTRSX",
                    crate::IndexTag::RPMTAG_OBSOLETEATTRSX as u32,
                ),
                (
                    "PROVIDEATTRSX",
                    crate::IndexTag::RPMTAG_PROVIDEATTRSX as u32,
                ),
                (
                    "REQUIREATTRSX",
                    crate::IndexTag::RPMTAG_REQUIREATTRSX as u32,
                ),
                (
                    "BUILDPROVIDES",
                    crate::IndexTag::RPMTAG_BUILDPROVIDES as u32,
                ),
                (
                    "BUILDOBSOLETES",
                    crate::IndexTag::RPMTAG_BUILDOBSOLETES as u32,
                ),
                ("DBINSTANCE", crate::IndexTag::RPMTAG_DBINSTANCE as u32),
                ("NVRA", crate::IndexTag::RPMTAG_NVRA as u32),
                ("FILENAMES", crate::IndexTag::RPMTAG_FILENAMES as u32),
                ("FILEPROVIDE", crate::IndexTag::RPMTAG_FILEPROVIDE as u32),
                ("FILEREQUIRE", crate::IndexTag::RPMTAG_FILEREQUIRE as u32),
                ("FSNAMES", crate::IndexTag::RPMTAG_FSNAMES as u32),
                ("FSSIZES", crate::IndexTag::RPMTAG_FSSIZES as u32),
                ("TRIGGERCONDS", crate::IndexTag::RPMTAG_TRIGGERCONDS as u32),
                ("TRIGGERTYPE", crate::IndexTag::RPMTAG_TRIGGERTYPE as u32),
                (
                    "ORIGFILENAMES",
                    crate::IndexTag::RPMTAG_ORIGFILENAMES as u32,
                ),
                (
                    "LONGFILESIZES",
                    crate::IndexTag::RPMTAG_LONGFILESIZES as u32,
                ),
                ("LONGSIZE", crate::IndexTag::RPMTAG_LONGSIZE as u32),
                ("FILECAPS", crate::IndexTag::RPMTAG_FILECAPS as u32),
                (
                    "FILEDIGESTALGO",
                    crate::IndexTag::RPMTAG_FILEDIGESTALGO as u32,
                ),
                ("BUGURL", crate::IndexTag::RPMTAG_BUGURL as u32),
                ("EVR", crate::IndexTag::RPMTAG_EVR as u32),
                ("NVR", crate::IndexTag::RPMTAG_NVR as u32),
                ("NEVR", crate::IndexTag::RPMTAG_NEVR as u32),
                ("NEVRA", crate::IndexTag::RPMTAG_NEVRA as u32),
                ("HEADERCOLOR", crate::IndexTag::RPMTAG_HEADERCOLOR as u32),
                ("VERBOSE", crate::IndexTag::RPMTAG_VERBOSE as u32),
                ("EPOCHNUM", crate::IndexTag::RPMTAG_EPOCHNUM as u32),
                ("PREINFLAGS", crate::IndexTag::RPMTAG_PREINFLAGS as u32),
                ("POSTINFLAGS", crate::IndexTag::RPMTAG_POSTINFLAGS as u32),
                ("PREUNFLAGS", crate::IndexTag::RPMTAG_PREUNFLAGS as u32),
                ("POSTUNFLAGS", crate::IndexTag::RPMTAG_POSTUNFLAGS as u32),
                (
                    "PRETRANSFLAGS",
                    crate::IndexTag::RPMTAG_PRETRANSFLAGS as u32,
                ),
                (
                    "POSTTRANSFLAGS",
                    crate::IndexTag::RPMTAG_POSTTRANSFLAGS as u32,
                ),
                (
                    "VERIFYSCRIPTFLAGS",
                    crate::IndexTag::RPMTAG_VERIFYSCRIPTFLAGS as u32,
                ),
                (
                    "TRIGGERSCRIPTFLAGS",
                    crate::IndexTag::RPMTAG_TRIGGERSCRIPTFLAGS as u32,
                ),
                ("COLLECTIONS", crate::IndexTag::RPMTAG_COLLECTIONS as u32),
                ("POLICYNAMES", crate::IndexTag::RPMTAG_POLICYNAMES as u32),
                ("POLICYTYPES", crate::IndexTag::RPMTAG_POLICYTYPES as u32),
                (
                    "POLICYTYPESINDEXES",
                    crate::IndexTag::RPMTAG_POLICYTYPESINDEXES as u32,
                ),
                ("POLICYFLAGS", crate::IndexTag::RPMTAG_POLICYFLAGS as u32),
                ("VCS", crate::IndexTag::RPMTAG_VCS as u32),
                ("ORDERNAME", crate::IndexTag::RPMTAG_ORDERNAME as u32),
                ("ORDERVERSION", crate::IndexTag::RPMTAG_ORDERVERSION as u32),
                ("ORDERFLAGS", crate::IndexTag::RPMTAG_ORDERFLAGS as u32),
                ("MSSFMANIFEST", crate::IndexTag::RPMTAG_MSSFMANIFEST as u32),
                ("MSSFDOMAIN", crate::IndexTag::RPMTAG_MSSFDOMAIN as u32),
                (
                    "INSTFILENAMES",
                    crate::IndexTag::RPMTAG_INSTFILENAMES as u32,
                ),
                ("REQUIRENEVRS", crate::IndexTag::RPMTAG_REQUIRENEVRS as u32),
                ("PROVIDENEVRS", crate::IndexTag::RPMTAG_PROVIDENEVRS as u32),
                (
                    "OBSOLETENEVRS",
                    crate::IndexTag::RPMTAG_OBSOLETENEVRS as u32,
                ),
                (
                    "CONFLICTNEVRS",
                    crate::IndexTag::RPMTAG_CONFLICTNEVRS as u32,
                ),
                ("FILENLINKS", crate::IndexTag::RPMTAG_FILENLINKS as u32),
                (
                    "RECOMMENDNAME",
                    crate::IndexTag::RPMTAG_RECOMMENDNAME as u32,
                ),
                (
                    "RECOMMENDVERSION",
                    crate::IndexTag::RPMTAG_RECOMMENDVERSION as u32,
                ),
                (
                    "RECOMMENDFLAGS",
                    crate::IndexTag::RPMTAG_RECOMMENDFLAGS as u32,
                ),
                ("SUGGESTNAME", crate::IndexTag::RPMTAG_SUGGESTNAME as u32),
                (
                    "SUGGESTVERSION",
                    crate::IndexTag::RPMTAG_SUGGESTVERSION as u32,
                ),
                ("SUGGESTFLAGS", crate::IndexTag::RPMTAG_SUGGESTFLAGS as u32),
                (
                    "SUPPLEMENTNAME",
                    crate::IndexTag::RPMTAG_SUPPLEMENTNAME as u32,
                ),
                (
                    "SUPPLEMENTVERSION",
                    crate::IndexTag::RPMTAG_SUPPLEMENTVERSION as u32,
                ),
                (
                    "SUPPLEMENTFLAGS",
                    crate::IndexTag::RPMTAG_SUPPLEMENTFLAGS as u32,
                ),
                ("ENHANCENAME", crate::IndexTag::RPMTAG_ENHANCENAME as u32),
                (
                    "ENHANCEVERSION",
                    crate::IndexTag::RPMTAG_ENHANCEVERSION as u32,
                ),
                ("ENHANCEFLAGS", crate::IndexTag::RPMTAG_ENHANCEFLAGS as u32),
                (
                    "RECOMMENDNEVRS",
                    crate::IndexTag::RPMTAG_RECOMMENDNEVRS as u32,
                ),
                ("SUGGESTNEVRS", crate::IndexTag::RPMTAG_SUGGESTNEVRS as u32),
                (
                    "SUPPLEMENTNEVRS",
                    crate::IndexTag::RPMTAG_SUPPLEMENTNEVRS as u32,
                ),
                ("ENHANCENEVRS", crate::IndexTag::RPMTAG_ENHANCENEVRS as u32),
                ("ENCODING", crate::IndexTag::RPMTAG_ENCODING as u32),
                (
                    "FILETRIGGERIN",
                    crate::IndexTag::RPMTAG_FILETRIGGERIN as u32,
                ),
                (
                    "FILETRIGGERUN",
                    crate::IndexTag::RPMTAG_FILETRIGGERUN as u32,
                ),
                (
                    "FILETRIGGERPOSTUN",
                    crate::IndexTag::RPMTAG_FILETRIGGERPOSTUN as u32,
                ),
                (
                    "FILETRIGGERSCRIPTS",
                    crate::IndexTag::RPMTAG_FILETRIGGERSCRIPTS as u32,
                ),
                (
                    "FILETRIGGERSCRIPTPROG",
                    crate::IndexTag::RPMTAG_FILETRIGGERSCRIPTPROG as u32,
                ),
                (
                    "FILETRIGGERSCRIPTFLAGS",
                    crate::IndexTag::RPMTAG_FILETRIGGERSCRIPTFLAGS as u32,
                ),
                (
                    "FILETRIGGERNAME",
                    crate::IndexTag::RPMTAG_FILETRIGGERNAME as u32,
                ),
                (
                    "FILETRIGGERINDEX",
                    crate::IndexTag::RPMTAG_FILETRIGGERINDEX as u32,
                ),
                (
                    "FILETRIGGERVERSION",
                    crate::IndexTag::RPMTAG_FILETRIGGERVERSION as u32,
                ),
                (
                    "FILETRIGGERFLAGS",
                    crate::IndexTag::RPMTAG_FILETRIGGERFLAGS as u32,
                ),
                (
                    "TRANSFILETRIGGERIN",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERIN as u32,
                ),
                (
                    "TRANSFILETRIGGERUN",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERUN as u32,
                ),
                (
                    "TRANSFILETRIGGERPOSTUN",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERPOSTUN as u32,
                ),
                (
                    "TRANSFILETRIGGERSCRIPTS",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERSCRIPTS as u32,
                ),
                (
                    "TRANSFILETRIGGERSCRIPTPROG",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERSCRIPTPROG as u32,
                ),
                (
                    "TRANSFILETRIGGERSCRIPTFLAGS",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERSCRIPTFLAGS as u32,
                ),
                (
                    "TRANSFILETRIGGERNAME",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERNAME as u32,
                ),
                (
                    "TRANSFILETRIGGERINDEX",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERINDEX as u32,
                ),
                (
                    "TRANSFILETRIGGERVERSION",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERVERSION as u32,
                ),
                (
                    "TRANSFILETRIGGERFLAGS",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERFLAGS as u32,
                ),
                (
                    "REMOVEPATHPOSTFIXES",
                    crate::IndexTag::RPMTAG_REMOVEPATHPOSTFIXES as u32,
                ),
                (
                    "FILETRIGGERPRIORITIES",
                    crate::IndexTag::RPMTAG_FILETRIGGERPRIORITIES as u32,
                ),
                (
                    "TRANSFILETRIGGERPRIORITIES",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERPRIORITIES as u32,
                ),
                (
                    "FILETRIGGERCONDS",
                    crate::IndexTag::RPMTAG_FILETRIGGERCONDS as u32,
                ),
                (
                    "FILETRIGGERTYPE",
                    crate::IndexTag::RPMTAG_FILETRIGGERTYPE as u32,
                ),
                (
                    "TRANSFILETRIGGERCONDS",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERCONDS as u32,
                ),
                (
                    "TRANSFILETRIGGERTYPE",
                    crate::IndexTag::RPMTAG_TRANSFILETRIGGERTYPE as u32,
                ),
                (
                    "FILESIGNATURES",
                    crate::IndexTag::RPMTAG_FILESIGNATURES as u32,
                ),
                (
                    "FILESIGNATURELENGTH",
                    crate::IndexTag::RPMTAG_FILESIGNATURELENGTH as u32,
                ),
                (
                    "PAYLOADSHA256",
                    crate::IndexTag::RPMTAG_PAYLOADSHA256 as u32,
                ),
                (
                    "PAYLOADSHA256ALGO",
                    crate::IndexTag::RPMTAG_PAYLOADSHA256ALGO as u32,
                ),
                (
                    "AUTOINSTALLED",
                    crate::IndexTag::RPMTAG_AUTOINSTALLED as u32,
                ),
                ("IDENTITY", crate::IndexTag::RPMTAG_IDENTITY as u32),
                (
                    "MODULARITYLABEL",
                    crate::IndexTag::RPMTAG_MODULARITYLABEL as u32,
                ),
                (
                    "PAYLOADSHA256ALT",
                    crate::IndexTag::RPMTAG_PAYLOADSHA256ALT as u32,
                ),
                ("ARCHSUFFIX", crate::IndexTag::RPMTAG_ARCHSUFFIX as u32),
                ("SPEC", crate::IndexTag::RPMTAG_SPEC as u32),
                (
                    "TRANSLATIONURL",
                    crate::IndexTag::RPMTAG_TRANSLATIONURL as u32,
                ),
                (
                    "UPSTREAMRELEASES",
                    crate::IndexTag::RPMTAG_UPSTREAMRELEASES as u32,
                ),
                (
                    "SOURCELICENSE",
                    crate::IndexTag::RPMTAG_SOURCELICENSE as u32,
                ),
                ("PREUNTRANS", crate::IndexTag::RPMTAG_PREUNTRANS as u32),
                ("POSTUNTRANS", crate::IndexTag::RPMTAG_POSTUNTRANS as u32),
                (
                    "PREUNTRANSPROG",
                    crate::IndexTag::RPMTAG_PREUNTRANSPROG as u32,
                ),
                (
                    "POSTUNTRANSPROG",
                    crate::IndexTag::RPMTAG_POSTUNTRANSPROG as u32,
                ),
                (
                    "PREUNTRANSFLAGS",
                    crate::IndexTag::RPMTAG_PREUNTRANSFLAGS as u32,
                ),
                (
                    "POSTUNTRANSFLAGS",
                    crate::IndexTag::RPMTAG_POSTUNTRANSFLAGS as u32,
                ),
                ("SYSUSERS", crate::IndexTag::RPMTAG_SYSUSERS as u32),
                ("BUILDSYSTEM", crate::IndexTag::RPMTAG_BUILDSYSTEM as u32),
                ("BUILDOPTION", crate::IndexTag::RPMTAG_BUILDOPTION as u32),
                ("PAYLOADSIZE", crate::IndexTag::RPMTAG_PAYLOADSIZE as u32),
                (
                    "PAYLOADSIZEALT",
                    crate::IndexTag::RPMTAG_PAYLOADSIZEALT as u32,
                ),
                ("RPMFORMAT", crate::IndexTag::RPMTAG_RPMFORMAT as u32),
                (
                    "FILEMIMEINDEX",
                    crate::IndexTag::RPMTAG_FILEMIMEINDEX as u32,
                ),
                ("MIMEDICT", crate::IndexTag::RPMTAG_MIMEDICT as u32),
                ("FILEMIMES", crate::IndexTag::RPMTAG_FILEMIMES as u32),
                (
                    "PACKAGEDIGESTS",
                    crate::IndexTag::RPMTAG_PACKAGEDIGESTS as u32,
                ),
                (
                    "PACKAGEDIGESTALGOS",
                    crate::IndexTag::RPMTAG_PACKAGEDIGESTALGOS as u32,
                ),
                ("SOURCENEVR", crate::IndexTag::RPMTAG_SOURCENEVR as u32),
                (
                    "PAYLOAD_SHA512",
                    crate::IndexTag::RPMTAG_PAYLOAD_SHA512 as u32,
                ),
                (
                    "PAYLOAD_SHA512_ALT",
                    crate::IndexTag::RPMTAG_PAYLOAD_SHA512_ALT as u32,
                ),
                (
                    "PAYLOAD_SHA3_256",
                    crate::IndexTag::RPMTAG_PAYLOAD_SHA3_256 as u32,
                ),
                (
                    "PAYLOAD_SHA3_256_ALT",
                    crate::IndexTag::RPMTAG_PAYLOAD_SHA3_256_ALT as u32,
                ),
            ],
        )?,
    )?;

    m.add(
        "SignatureTag",
        make_int_enum(
            m.py(),
            "SignatureTag",
            &[
                (
                    "HEADER_SIGNATURES",
                    crate::IndexSignatureTag::HEADER_SIGNATURES as u32,
                ),
                (
                    "FILESIGNATURES",
                    crate::IndexSignatureTag::RPMSIGTAG_FILESIGNATURES as u32,
                ),
                (
                    "FILESIGNATURE_LENGTH",
                    crate::IndexSignatureTag::RPMSIGTAG_FILESIGNATURE_LENGTH as u32,
                ),
                (
                    "VERITYSIGNATURES",
                    crate::IndexSignatureTag::RPMSIGTAG_VERITYSIGNATURES as u32,
                ),
                (
                    "VERITYSIGNATUREALGO",
                    crate::IndexSignatureTag::RPMSIGTAG_VERITYSIGNATUREALGO as u32,
                ),
                (
                    "OPENPGP",
                    crate::IndexSignatureTag::RPMSIGTAG_OPENPGP as u32,
                ),
                ("DSA", crate::IndexSignatureTag::RPMSIGTAG_DSA as u32),
                ("RSA", crate::IndexSignatureTag::RPMSIGTAG_RSA as u32),
                ("SHA1", crate::IndexSignatureTag::RPMSIGTAG_SHA1 as u32),
                (
                    "SHA3_256",
                    crate::IndexSignatureTag::RPMSIGTAG_SHA3_256 as u32,
                ),
                ("SHA256", crate::IndexSignatureTag::RPMSIGTAG_SHA256 as u32),
                (
                    "RESERVED",
                    crate::IndexSignatureTag::RPMSIGTAG_RESERVED as u32,
                ),
                (
                    "RESERVEDSPACE",
                    crate::IndexSignatureTag::RPMSIGTAG_RESERVEDSPACE as u32,
                ),
                ("MD5", crate::IndexSignatureTag::RPMSIGTAG_MD5 as u32),
                ("PGP", crate::IndexSignatureTag::RPMSIGTAG_PGP as u32),
                ("GPG", crate::IndexSignatureTag::RPMSIGTAG_GPG as u32),
                ("SIZE", crate::IndexSignatureTag::RPMSIGTAG_SIZE as u32),
                (
                    "PAYLOADSIZE",
                    crate::IndexSignatureTag::RPMSIGTAG_PAYLOADSIZE as u32,
                ),
                (
                    "LONGSIZE",
                    crate::IndexSignatureTag::RPMSIGTAG_LONGSIZE as u32,
                ),
                (
                    "LONGARCHIVESIZE",
                    crate::IndexSignatureTag::RPMSIGTAG_LONGARCHIVESIZE as u32,
                ),
            ],
        )?,
    )?;

    // IntFlag types for bitmask fields
    m.add(
        "FileFlags",
        make_int_flag(
            m.py(),
            "FileFlags",
            &[
                ("CONFIG", crate::FileFlags::CONFIG.bits()),
                ("DOC", crate::FileFlags::DOC.bits()),
                ("DONOTUSE", crate::FileFlags::DONOTUSE.bits()),
                ("MISSINGOK", crate::FileFlags::MISSINGOK.bits()),
                ("NOREPLACE", crate::FileFlags::NOREPLACE.bits()),
                ("SPECFILE", crate::FileFlags::SPECFILE.bits()),
                ("GHOST", crate::FileFlags::GHOST.bits()),
                ("LICENSE", crate::FileFlags::LICENSE.bits()),
                ("README", crate::FileFlags::README.bits()),
                ("PUBKEY", crate::FileFlags::PUBKEY.bits()),
                ("ARTIFACT", crate::FileFlags::ARTIFACT.bits()),
            ],
        )?,
    )?;

    m.add(
        "DependencyFlags",
        make_int_flag(
            m.py(),
            "DependencyFlags",
            &[
                ("ANY", crate::DependencyFlags::ANY.bits()),
                ("LESS", crate::DependencyFlags::LESS.bits()),
                ("GREATER", crate::DependencyFlags::GREATER.bits()),
                ("EQUAL", crate::DependencyFlags::EQUAL.bits()),
                ("LE", crate::DependencyFlags::LE.bits()),
                ("GE", crate::DependencyFlags::GE.bits()),
                ("POSTTRANS", crate::DependencyFlags::POSTTRANS.bits()),
                ("PREREQ", crate::DependencyFlags::PREREQ.bits()),
                ("PRETRANS", crate::DependencyFlags::PRETRANS.bits()),
                ("INTERP", crate::DependencyFlags::INTERP.bits()),
                ("SCRIPT_PRE", crate::DependencyFlags::SCRIPT_PRE.bits()),
                ("SCRIPT_POST", crate::DependencyFlags::SCRIPT_POST.bits()),
                ("SCRIPT_PREUN", crate::DependencyFlags::SCRIPT_PREUN.bits()),
                (
                    "SCRIPT_POSTUN",
                    crate::DependencyFlags::SCRIPT_POSTUN.bits(),
                ),
                (
                    "SCRIPT_VERIFY",
                    crate::DependencyFlags::SCRIPT_VERIFY.bits(),
                ),
                (
                    "FIND_REQUIRES",
                    crate::DependencyFlags::FIND_REQUIRES.bits(),
                ),
                (
                    "FIND_PROVIDES",
                    crate::DependencyFlags::FIND_PROVIDES.bits(),
                ),
                ("TRIGGERIN", crate::DependencyFlags::TRIGGERIN.bits()),
                ("TRIGGERUN", crate::DependencyFlags::TRIGGERUN.bits()),
                (
                    "TRIGGERPOSTUN",
                    crate::DependencyFlags::TRIGGERPOSTUN.bits(),
                ),
                ("MISSINGOK", crate::DependencyFlags::MISSINGOK.bits()),
                ("PREUNTRANS", crate::DependencyFlags::PREUNTRANS.bits()),
                ("POSTUNTRANS", crate::DependencyFlags::POSTUNTRANS.bits()),
                ("RPMLIB", crate::DependencyFlags::RPMLIB.bits()),
                ("TRIGGERPREIN", crate::DependencyFlags::TRIGGERPREIN.bits()),
                ("KEYRING", crate::DependencyFlags::KEYRING.bits()),
                ("CONFIG", crate::DependencyFlags::CONFIG.bits()),
                ("META", crate::DependencyFlags::META.bits()),
            ],
        )?,
    )?;

    m.add(
        "ScriptletFlags",
        make_int_flag(
            m.py(),
            "ScriptletFlags",
            &[
                ("EXPAND", crate::ScriptletFlags::EXPAND.bits()),
                ("QFORMAT", crate::ScriptletFlags::QFORMAT.bits()),
                ("CRITICAL", crate::ScriptletFlags::CRITICAL.bits()),
            ],
        )?,
    )?;

    Ok(())
}
