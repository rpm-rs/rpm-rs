//! Exact hardlink-set planning for RPM package construction.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;

use sha2::{Digest, Sha256};

use super::PackageFileEntry;
use crate::Error;

/// The RPM header and payload properties assigned to one declared hardlink member.
#[derive(Clone, Copy, Debug)]
pub(super) struct Member {
    /// Synthetic inode shared by every member of the set.
    pub(super) inode: u32,
    /// Number of paths in the complete package-local set.
    pub(super) link_count: u32,
    /// Whether this member carries the set's bytes in the CPIO payload.
    pub(super) has_content: bool,
}

/// Validated hardlink properties indexed by normalized package path.
#[derive(Default)]
pub(super) struct Plan {
    members: HashMap<String, Member>,
}

impl Plan {
    pub(super) fn from_files(files: &BTreeMap<String, PackageFileEntry>) -> Result<Self, Error> {
        // Group declarations by their caller-owned identity. BTreeMap ordering makes both
        // group traversal and member order deterministic across builder invocations.
        let mut groups = BTreeMap::<&str, Vec<(&str, &PackageFileEntry)>>::new();
        for (path, entry) in files {
            if let Some(identity) = entry.hardlink_identity.as_deref() {
                groups.entry(identity).or_default().push((path, entry));
            }
        }

        let mut members = HashMap::new();
        for entries in groups.values() {
            validate_group(entries)?;

            // RPM identifies files by their one-based position in the sorted header arrays.
            // Every member receives the position of the set's first package path.
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

            // In an RPM CPIO payload, earlier hardlink entries have zero size and the final
            // entry carries the shared bytes. `entries` is already in package-path order.
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
        // Match rpmbuild: ordinary payload entries come first, followed by all hardlink
        // members. Each partition retains the package's sorted header order.
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
        // Hardlink paths report the shared file size individually in RPMTAG_FILESIZES, but
        // RPMTAG_SIZE counts their installed bytes only once.
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
        // One filesystem inode cannot give its paths different ownership, mode, flags,
        // timestamps, link targets, capabilities, or verification policy.
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
        // Compare both size and a streaming digest so declarations work for raw buffers and
        // file-backed content without retaining every member's bytes in memory.
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

#[cfg(test)]
mod tests {
    use super::super::ContentSource;
    use super::*;
    use crate::{FileFlags, FileMode, FileVerifyFlags, Timestamp};

    fn entry(content: &str, identity: Option<&str>) -> PackageFileEntry {
        PackageFileEntry {
            mode: FileMode::regular(0o644),
            modified_at: Timestamp(7),
            link: String::new(),
            flags: FileFlags::empty(),
            user: "root".to_string(),
            group: "root".to_string(),
            base_name: String::new(),
            dir: "/".to_string(),
            caps: None,
            verify_flags: FileVerifyFlags::ALL_FLAGS,
            source: ContentSource::Raw(content.as_bytes().to_vec()),
            hardlink_identity: identity.map(str::to_string),
            bulk_added: false,
        }
    }

    #[test]
    fn plans_shared_identity_and_rpm_payload_order() {
        let files = BTreeMap::from([
            ("./alpha-1".to_string(), entry("alpha", Some("alpha"))),
            ("./alpha-2".to_string(), entry("alpha", Some("alpha"))),
            ("./beta-1".to_string(), entry("beta", Some("beta"))),
            ("./beta-2".to_string(), entry("beta", Some("beta"))),
            ("./standalone".to_string(), entry("alone", None)),
        ]);

        let plan = Plan::from_files(&files).unwrap();
        let alpha_1 = plan.member("./alpha-1").unwrap();
        let alpha_2 = plan.member("./alpha-2").unwrap();
        let beta_1 = plan.member("./beta-1").unwrap();
        let beta_2 = plan.member("./beta-2").unwrap();

        assert_eq!(alpha_1.inode, 1);
        assert_eq!(alpha_2.inode, alpha_1.inode);
        assert_eq!(alpha_1.link_count, 2);
        assert!(!alpha_1.has_content);
        assert!(alpha_2.has_content);
        assert_eq!(beta_1.inode, 3);
        assert_eq!(beta_2.inode, beta_1.inode);
        assert!(plan.member("./standalone").is_none());
        assert_eq!(
            plan.payload_order(&files),
            [
                "./standalone",
                "./alpha-1",
                "./alpha-2",
                "./beta-1",
                "./beta-2",
            ]
        );
        assert_eq!(plan.installed_size(&files).unwrap(), 14);
    }

    #[test]
    fn rejects_incomplete_or_conflicting_sets() {
        let incomplete =
            BTreeMap::from([("./only".to_string(), entry("same", Some("incomplete")))]);
        assert!(
            Plan::from_files(&incomplete)
                .err()
                .unwrap()
                .to_string()
                .contains("at least two package files")
        );

        let conflicting = BTreeMap::from([
            ("./first".to_string(), entry("first", Some("conflict"))),
            ("./second".to_string(), entry("second", Some("conflict"))),
        ]);
        assert!(
            Plan::from_files(&conflicting)
                .err()
                .unwrap()
                .to_string()
                .contains("identical content")
        );
    }
}
