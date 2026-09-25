use nom::bytes::complete;
use nom::number::complete::{be_u8, be_u16};
use std::convert::TryInto;

use crate::constants::*;
use crate::errors::*;

/// Lead of an rpm header.
///
/// Used to contain valid data, now only a very limited subset is used
/// and the remaining data is set to fixed values such that compatibility is kept.
/// Only the "magic number" is still relevant as it is used to detect rpm files.
#[derive(Clone, Eq)]
pub struct Lead {
    magic: [u8; 4],
    major: u8,
    minor: u8,
    package_type: u16,
    arch: u16,
    name: [u8; 66],
    os: u16,
    signature_type: u16,
    reserved: [u8; 16],
}

impl std::fmt::Debug for Lead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = String::from_utf8_lossy(&self.name);
        f.debug_struct("Lead")
            .field("magic", &self.magic)
            .field("major", &self.major)
            .field("minor", &self.minor)
            .field("package_type", &self.package_type)
            .field("arch", &self.arch)
            .field("name", &name)
            .field("os", &self.os)
            .field("signature_type", &self.signature_type)
            .field("reserved", &self.reserved)
            .finish()
    }
}

impl Lead {
    /// Construct a conventional binary RPM lead for a package name.
    #[cfg(feature = "payload")]
    pub fn new(name: &str) -> Self {
        let mut name_arr = [0; 66];
        let name_size = std::cmp::min(name_arr.len() - 1, name.len());
        name_arr[..name_size].clone_from_slice(&name.as_bytes()[..name_size]);
        Lead {
            magic: RPM_MAGIC,
            major: 3,
            minor: 0,
            package_type: 0,
            arch: 0,
            name: name_arr,
            os: 1,
            signature_type: 5,
            reserved: [0; 16],
        }
    }

    /// Return the RPM lead magic bytes.
    pub fn magic(&self) -> [u8; 4] {
        self.magic
    }

    /// Return the lead major version.
    ///
    /// NOTE: Not actually used or valid in practice. RPMv6 still encodes a "4" here.
    pub fn major(&self) -> u8 {
        self.major
    }

    /// Return the lead minor version.
    ///
    /// NOTE: Not actually used or valid in practice. RPMv6 still encodes a "0" here (as in 4.0).
    pub fn minor(&self) -> u8 {
        self.minor
    }

    /// Return the lead package type.
    ///
    /// NOTE: Typically "1" if a source package and "0" otherwise, but the header is the authoritative
    /// source of this information.
    pub fn package_type(&self) -> u16 {
        self.package_type
    }

    /// Return the lead architecture identifier.
    ///
    /// NOTE: Not actually used or valid in practice. Typically hardcoded to "0".
    pub fn arch(&self) -> u16 {
        self.arch
    }

    /// Return the lead operating-system identifier.
    ///
    /// NOTE: Not actually used or valid in practice. Typically hardcoded to "0".
    pub fn os(&self) -> u16 {
        self.os
    }

    /// Return the lead signature type identifier.
    ///
    /// NOTE: Typically hardcoded to "5".
    pub fn signature_type(&self) -> u16 {
        self.signature_type
    }

    /// Return the reserved bytes stored in the lead.
    pub fn reserved(&self) -> [u8; 16] {
        self.reserved
    }

    /// Return the NUL-terminated package name stored in the lead.
    ///
    /// NOTE: Truncated at 65 characters. The header is the authoritative source of this
    /// information.
    pub fn name(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }

    pub(crate) fn parse(input: &[u8]) -> Result<Self, Error> {
        let (rest, magic) = complete::take(4usize)(input)?;
        for i in 0..magic.len() {
            if magic[i] != RPM_MAGIC[i] {
                return Err(Error::InvalidMagic {
                    expected: RPM_MAGIC[i],
                    actual: magic[i],
                    complete_input: input.to_vec(),
                });
            }
        }
        let (rest, major) = be_u8(rest)?;
        let (rest, minor) = be_u8(rest)?;
        let (rest, pkg_type) = be_u16(rest)?;
        let (rest, arch) = be_u16(rest)?;
        let (rest, name) = complete::take(66usize)(rest)?;
        let (rest, os) = be_u16(rest)?;
        let (rest, sigtype) = be_u16(rest)?;

        let mut name_arr: [u8; 66] = [0; 66];
        name_arr.copy_from_slice(name);

        Ok(Lead {
            magic: RPM_MAGIC,
            major,
            minor,
            package_type: pkg_type,
            arch,
            name: name_arr,
            os,
            signature_type: sigtype,
            reserved: rest.try_into().unwrap(), // safe unwrap here since we've checked length of slices.
        })
    }

    pub(crate) fn write(&self, out: &mut impl std::io::Write) -> Result<(), Error> {
        out.write_all(&self.magic)?;
        out.write_all(&self.major.to_be_bytes())?;
        out.write_all(&self.minor.to_be_bytes())?;
        out.write_all(&self.package_type.to_be_bytes())?;
        out.write_all(&self.arch.to_be_bytes())?;
        out.write_all(&self.name)?;
        out.write_all(&self.os.to_be_bytes())?;
        out.write_all(&self.signature_type.to_be_bytes())?;
        out.write_all(&self.reserved)?;
        Ok(())
    }
}

impl PartialEq for Lead {
    fn eq(&self, other: &Lead) -> bool {
        for i in 0..self.name.len() {
            if other.name[i] != self.name[i] {
                return false;
            }
        }
        self.magic == other.magic
            && self.major == other.major
            && self.minor == other.minor
            && self.package_type == other.package_type
            && self.arch == other.arch
            && self.os == other.os
            && self.signature_type == other.signature_type
            && self.reserved == other.reserved
    }
}
