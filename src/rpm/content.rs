//! Access and extract RPM package payload contents (files, directories, symlinks).

use std::{fs, io, io::Read, path::Path};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{constants::*, decompress_stream, errors::*};

use super::headers::*;
use super::package::Package;
use super::payload;

#[cfg(unix)]
fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<(), Error> {
    std::os::unix::fs::symlink(original, link)?;
    Ok(())
}

#[cfg(windows)]
fn symlink(original: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<(), Error> {
    let original = original.as_ref();

    let Ok(metadata) = original.metadata() else {
        // Windows symlink creation requires the target to exist and be accessible.
        // Relative symlinks (e.g., "../dir") or targets outside the extraction directory
        // will fail, so we silently skip them to allow extraction to continue.
        // This matches RPM's behavior where symlinks are informational metadata.
        return Ok(());
    };

    if metadata.is_dir() {
        std::os::windows::fs::symlink_dir(original, link)?;
    } else {
        std::os::windows::fs::symlink_file(original, link)?;
    }

    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn symlink(_original: &Path, _link: &Path) -> Result<(), Error> {
    Err(Error::UnsupportedSymlink)
}

impl Package {
    /// Iterate over the file contents of the package payload
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// for entry in package.files()? {
    ///     let file = entry?;
    ///     // do something with file.content
    ///     println!("{} is {} bytes", file.metadata.path().display(), file.content.len());
    /// }
    /// # Ok(()) }
    /// ```
    pub fn files(&self) -> Result<FileIterator<'_>, Error> {
        let file_entries = self.metadata.get_file_entries()?;
        let archive = decompress_stream(
            self.metadata.get_payload_compressor()?,
            io::Cursor::new(&self.payload),
        )?;

        Ok(FileIterator {
            file_entries,
            archive,
            count: 0,
        })
    }

    /// Extract all contents of the package payload to a given directory.
    ///
    /// # Implementation
    ///
    /// The if the directory is nested, its parent directories must already exist. If the
    /// directory itself already exists, the operation will fail. All extracted files will be
    /// dropped relative to the provided directory (it will not install any files).
    ///
    /// ## Platform-specific behavior
    ///
    /// **Windows**: Symbolic links are only created if their target exists at extraction time.
    /// Symlinks with relative targets (e.g., `../dir`) or targets outside the extraction
    /// directory will be silently skipped. This is because Windows symlink creation requires
    /// the target to exist and be accessible.
    ///
    /// **Unix**: All symbolic links are created regardless of whether their target exists.
    ///
    /// # Examples
    ///
    /// ```text
    /// let package = rpm::Package::open("tests/assets/RPMS/v4/rpm-basic-2.3.4-5.el9.noarch.rpm")?;
    /// package.extract(&package.metadata.get_name()?)?;
    /// ```
    pub fn extract(&self, dest: impl AsRef<Path>) -> Result<(), Error> {
        fs::create_dir(&dest)?;

        let dirs = self
            .metadata
            .header
            .get_entry_data_as_string_array(IndexTag::RPMTAG_DIRNAMES)?;

        // pull every base directory name in the package and create the directory in advance
        for dir in &dirs {
            let dir_path = dest
                .as_ref()
                .join(Path::new(dir).strip_prefix("/").unwrap_or(dest.as_ref()));
            fs::create_dir_all(&dir_path)?;
        }

        let mut archive = decompress_stream(
            self.metadata.get_payload_compressor()?,
            io::Cursor::new(&self.payload),
        )?;
        let file_entries = self.metadata.get_file_entries()?;

        for file_entry in file_entries.iter() {
            // Ghost files are not present in the payload archive and should not be created
            if file_entry.flags.contains(FileFlags::GHOST) {
                continue;
            }

            let mut entry_reader = payload::Reader::new(&mut archive, &file_entries)?;
            if entry_reader.is_trailer() {
                return Ok(());
            }
            let entry_path = file_entry.path();
            let file_path = dest
                .as_ref()
                .join(entry_path.strip_prefix("/").unwrap_or(dest.as_ref()));
            match file_entry.file_type() {
                FileType::Dir => {
                    fs::create_dir_all(&file_path)?;
                    #[cfg(unix)]
                    {
                        let perms = fs::Permissions::from_mode(file_entry.permissions().into());
                        fs::set_permissions(&file_path, perms)?;
                    }
                }
                FileType::Regular => {
                    let mut f = fs::File::create(&file_path)?;
                    io::copy(&mut entry_reader, &mut f)?;
                    #[cfg(unix)]
                    {
                        let perms = fs::Permissions::from_mode(file_entry.permissions().into());
                        f.set_permissions(perms)?;
                    }
                }
                FileType::SymbolicLink => {
                    // broken symlinks (common for debuginfo handling) are perceived as not existing by "exists()"
                    if file_path.exists() || file_path.symlink_metadata().is_ok() {
                        fs::remove_file(&file_path)?;
                    }
                    symlink(file_entry.linkto().unwrap_or(""), &file_path)?;
                }
                // Skip file types we don't handle (e.g. device nodes, FIFOs, sockets)
                _ => {}
            }
            entry_reader.finish()?;
        }

        Ok(())
    }
}

pub struct FileIterator<'a> {
    file_entries: Vec<FileEntry<'a>>,
    archive: Box<dyn io::Read + 'a>,
    count: usize,
}

#[derive(Debug)]
pub struct RpmFile<'a> {
    pub metadata: FileEntry<'a>,
    pub content: Vec<u8>,
}

impl<'a> RpmFile<'a> {
    pub fn into_owned(self) -> RpmFile<'static> {
        RpmFile {
            metadata: self.metadata.into_owned(),
            content: self.content,
        }
    }
}

impl<'a> Iterator for FileIterator<'a> {
    type Item = Result<RpmFile<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count >= self.file_entries.len() {
            return None;
        }

        // @todo: probably safe to hand out a reference instead of cloning, just a bit more painful
        let file_entry = self.file_entries[self.count].clone();
        self.count += 1;

        // Ghost files are not in the payload archive, so return them immediately with empty content
        if file_entry.flags.contains(FileFlags::GHOST) {
            return Some(Ok(RpmFile {
                metadata: file_entry,
                content: Vec::new(),
            }));
        }

        let reader = payload::Reader::new(&mut self.archive, &self.file_entries);

        match reader {
            Ok(mut entry_reader) => {
                if entry_reader.is_trailer() {
                    return None;
                }

                let mut content = Vec::new();

                if let Err(e) = entry_reader.read_to_end(&mut content) {
                    return Some(Err(Error::Io(e)));
                }
                if let Err(e) = entry_reader.finish() {
                    return Some(Err(Error::Io(e)));
                }

                Some(Ok(RpmFile {
                    metadata: file_entry,
                    content,
                }))
            }
            Err(e) => Some(Err(Error::Io(e))),
        }
    }
}

impl ExactSizeIterator for FileIterator<'_> {
    fn len(&self) -> usize {
        self.file_entries.len() - self.count
    }
}
