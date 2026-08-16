//! Exact hardlink-set planning for RPM package construction.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use sha2::{Digest, Sha256};

use super::PackageFileEntry;
use crate::Error;

#[derive(Clone, Copy, Debug)]
pub(super) struct Member {
    pub(super) inode: u32,
    pub(super) link_count: u32,
    pub(super) has_content: bool,
}

#[derive(Default)]
pub(super) struct Plan {
    members: HashMap<String, Member>,
}

impl Plan {
    pub(super) fn from_files(files: &BTreeMap<String, PackageFileEntry>) -> Result<Self, Error> {
        let mut groups = BTreeMap::<&str, Vec<(&str, &PackageFileEntry)>>::new();
        for (path, entry) in files {
            if let Some(identity) = entry.hardlink_identity.as_deref() {
                groups.entry(identity).or_default().push((path, entry));
            }
        }

        let mut members = HashMap::new();
        for entries in groups.values() {
            validate_group(entries)?;
            let inode = files
                .keys()
                .position(|candidate| candidate == entries[0].0)
                .expect("hardlink member came from package file map")
                .checked_add(1)
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(Error::InvalidFileOptions {
                    method: "PackageBuilder::build",
                    reason: "hardlink inode exceeds RPM's 32-bit authority",
                })?;
            let link_count =
                u32::try_from(entries.len()).map_err(|_| Error::InvalidFileOptions {
                    method: "PackageBuilder::build",
                    reason: "hardlink set exceeds RPM's 32-bit link-count authority",
                })?;
            for (index, (path, _)) in entries.iter().enumerate() {
                members.insert(
                    (*path).to_string(),
                    Member {
                        inode,
                        link_count,
                        has_content: index + 1 == entries.len(),
                    },
                );
            }
        }
        Ok(Self { members })
    }

    pub(super) fn member(&self, path: &str) -> Option<Member> {
        self.members.get(path).copied()
    }

    pub(super) fn payload_order(&self, files: &BTreeMap<String, PackageFileEntry>) -> Vec<String> {
        files
            .iter()
            .filter(|(_, entry)| !entry.flags.contains(crate::FileFlags::GHOST))
            .filter(|(path, _)| !self.members.contains_key(path.as_str()))
            .chain(
                files
                    .iter()
                    .filter(|(_, entry)| !entry.flags.contains(crate::FileFlags::GHOST))
                    .filter(|(path, _)| self.members.contains_key(path.as_str())),
            )
            .map(|(path, _)| path.clone())
            .collect()
    }

    pub(super) fn installed_size(
        &self,
        files: &BTreeMap<String, PackageFileEntry>,
    ) -> Result<u64, Error> {
        files.iter().try_fold(0_u64, |total, (path, entry)| {
            let contributes = self.member(path).is_none_or(|member| member.has_content);
            let size = if contributes { entry.source.size()? } else { 0 };
            total.checked_add(size).ok_or(Error::InvalidFileOptions {
                method: "PackageBuilder::build",
                reason: "combined installed size exceeds RPM's 64-bit authority",
            })
        })
    }
}

fn validate_group(entries: &[(&str, &PackageFileEntry)]) -> Result<(), Error> {
    if entries.len() < 2 {
        return Err(Error::InvalidFileOptions {
            method: "PackageBuilder::build",
            reason: "hardlink identity must name at least two package files",
        });
    }
    let anchor = entries[0].1;
    let anchor_size = anchor.source.size()?;
    let anchor_digest = content_digest(anchor)?;
    for (_, member) in &entries[1..] {
        if member.mode != anchor.mode
            || member.modified_at != anchor.modified_at
            || member.user != anchor.user
            || member.group != anchor.group
            || member.flags != anchor.flags
            || member.verify_flags != anchor.verify_flags
            || member.link != anchor.link
            || member.caps.as_ref().map(ToString::to_string)
                != anchor.caps.as_ref().map(ToString::to_string)
        {
            return Err(Error::InvalidFileOptions {
                method: "PackageBuilder::build",
                reason: "hardlink members must have identical effective metadata",
            });
        }
        if member.source.size()? != anchor_size || content_digest(member)? != anchor_digest {
            return Err(Error::InvalidFileOptions {
                method: "PackageBuilder::build",
                reason: "hardlink members must have identical content",
            });
        }
    }
    Ok(())
}

fn content_digest(entry: &PackageFileEntry) -> Result<[u8; 32], Error> {
    let mut reader = entry.source.try_into_bufread()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}
